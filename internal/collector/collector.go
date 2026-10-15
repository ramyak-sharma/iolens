package collector

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ramyak-sharma/iolens/internal/cgroupmap"
	"github.com/ramyak-sharma/iolens/internal/diskstats"
	"github.com/ramyak-sharma/iolens/internal/hist"
	"github.com/ramyak-sharma/iolens/internal/k8s"
	"github.com/ramyak-sharma/iolens/internal/probe"
	"github.com/ramyak-sharma/iolens/internal/psi"
)

type Config struct {
	Interval time.Duration
	Source   probe.Source // nil means --no-bpf
	Resolver *cgroupmap.Resolver
	Pods     *k8s.Pods // nil outside k8s
	Devices  []string  // empty = all non virtual

	ProcRoot string // normally /proc
	SysRoot  string // normally /sys

	// rules engine plugs in here, called once per tick
	Findings func() (findings []Finding, warming bool)
	Log      *slog.Logger
}

type Collector struct {
	cfg    Config
	latest atomic.Pointer[Snapshot]

	subMu sync.Mutex
	subs  []chan *Snapshot

	// state carried between ticks, only touched by the collector goroutine
	seq       uint64
	lastTime  time.Time
	prevDisk  map[string]diskstats.Stat
	prevNode  psi.Pressure
	prevHist  map[probe.Key]*hist.Hist
	prevCgPSI map[uint64]psi.Pressure
	recent    map[probe.Key]*recentRing
	devNames  map[uint32]string
	labels    map[uint64]Labels
	lastClean time.Time
}

func New(cfg Config) *Collector {
	if cfg.Interval == 0 {
		cfg.Interval = time.Second
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.SysRoot == "" {
		cfg.SysRoot = "/sys"
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Collector{
		cfg:       cfg,
		prevDisk:  map[string]diskstats.Stat{},
		prevHist:  map[probe.Key]*hist.Hist{},
		prevCgPSI: map[uint64]psi.Pressure{},
		recent:    map[probe.Key]*recentRing{},
		devNames:  map[uint32]string{},
		labels:    map[uint64]Labels{},
	}
}

// Latest is the most recent snapshot, nil before the first tick
func (c *Collector) Latest() *Snapshot { return c.latest.Load() }

// Subscribe gets every new snapshot. channel holds one, a slow reader
// just misses ticks instead of blocking the collector
func (c *Collector) Subscribe() <-chan *Snapshot {
	ch := make(chan *Snapshot, 1)
	c.subMu.Lock()
	c.subs = append(c.subs, ch)
	c.subMu.Unlock()
	return ch
}

func (c *Collector) Run(ctx context.Context) error {
	// prime the previous values so first real snapshot has proper deltas
	if _, err := c.Collect(); err != nil {
		return err
	}
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.subMu.Lock()
			for _, ch := range c.subs {
				close(ch)
			}
			c.subs = nil
			c.subMu.Unlock()
			return nil
		case <-t.C:
			s, err := c.Collect()
			if err != nil {
				c.cfg.Log.Warn("collect failed", "err", err)
				continue
			}
			c.publish(s)
		}
	}
}

func (c *Collector) publish(s *Snapshot) {
	c.latest.Store(s)
	c.subMu.Lock()
	defer c.subMu.Unlock()
	for _, ch := range c.subs {
		select {
		case ch <- s:
		default:
			// drop the stale one, put the new one in
			select {
			case <-ch:
			default:
			}
			ch <- s
		}
	}
}

// Collect builds one snapshot. exported for `iolens once` and tests
func (c *Collector) Collect() (*Snapshot, error) {
	start := time.Now()
	s := &Snapshot{Time: start, BPF: c.cfg.Source != nil}
	if !c.lastTime.IsZero() {
		s.Interval = start.Sub(c.lastTime)
	}
	c.lastTime = start
	c.seq++
	s.Seq = c.seq

	if err := c.collectDisks(s); err != nil {
		return nil, fmt.Errorf("diskstats: %w", err)
	}
	if p, err := psi.ReadFile(filepath.Join(c.cfg.ProcRoot, "pressure/io")); err == nil {
		if s.Interval > 0 {
			s.NodePSI = psi.Between(c.prevNode, p, s.Interval)
		}
		s.NodePSICum = p
		c.prevNode = p
	}

	cgids := map[uint64]bool{}
	if c.cfg.Source != nil {
		if err := c.collectHists(s, cgids); err != nil {
			return nil, fmt.Errorf("bpf: %w", err)
		}
		s.Agent.BPF = c.cfg.Source.Stats()
		if n, err := c.cfg.Source.InflightEntries(); err == nil {
			s.Agent.Inflight = n
		}
	} else if c.cfg.Resolver != nil {
		// no bpf so no list of active cgroups, look at all of them
		for id := range c.cfg.Resolver.All() {
			cgids[id] = true
		}
	}
	c.collectCgroups(s, cgids)

	if c.cfg.Findings != nil {
		s.Findings, s.Warming = c.cfg.Findings()
	}
	s.Agent.CollectSeconds = time.Since(start).Seconds()
	return s, nil
}

func (c *Collector) collectDisks(s *Snapshot) error {
	all, err := diskstats.ReadFile(filepath.Join(c.cfg.ProcRoot, "diskstats"))
	if err != nil {
		return err
	}
	isPart := func(name string) bool {
		_, err := os.Stat(filepath.Join(c.cfg.SysRoot, "class/block", name, "partition"))
		return err == nil
	}
	for _, d := range diskstats.Filter(all, isPart) {
		if !c.wantDevice(d.Name) {
			continue
		}
		if prev, ok := c.prevDisk[d.Name]; ok && s.Interval > 0 {
			s.Devices = append(s.Devices, diskstats.Rate(prev, d, s.Interval))
		}
		c.prevDisk[d.Name] = d
	}
	return nil
}

func (c *Collector) wantDevice(name string) bool {
	if len(c.cfg.Devices) == 0 {
		return true
	}
	for _, d := range c.cfg.Devices {
		if d == name {
			return true
		}
	}
	return false
}

func (c *Collector) collectHists(s *Snapshot, cgids map[uint64]bool) error {
	cur, err := c.cfg.Source.Read()
	if err != nil {
		return err
	}
	now := s.Time
	for k, h := range cur {
		dev := c.devName(k.Dev)
		if !c.wantDevice(dev) {
			continue
		}
		ser := &Series{Key: k, Device: dev, Labels: c.label(k.Cgroup), Cum: *h}
		ser.Win = h.Sub(c.prevHist[k])
		r := c.recent[k]
		if r == nil {
			r = &recentRing{}
			c.recent[k] = r
		}
		ser.Recent = r.observe(now, h.Count)
		s.Series = append(s.Series, ser)
		cgids[k.Cgroup] = true
	}
	for k := range c.prevHist {
		if _, ok := cur[k]; !ok {
			delete(c.recent, k)
		}
	}
	c.prevHist = cur

	// every 30s, drop keys for cgroups gone at least 5 minutes so the
	// map doesnt fill up with dead pods
	if c.cfg.Resolver != nil && now.Sub(c.lastClean) > 30*time.Second {
		c.lastClean = now
		ids := make([]uint64, 0, len(cgids))
		for id := range cgids {
			ids = append(ids, id)
		}
		gone := c.cfg.Resolver.Gone(ids, 5*time.Minute)
		if len(gone) > 0 {
			dead := map[uint64]bool{}
			for _, id := range gone {
				dead[id] = true
				delete(c.labels, id)
				delete(c.prevCgPSI, id)
			}
			var keys []probe.Key
			for k := range cur {
				if dead[k.Cgroup] {
					keys = append(keys, k)
				}
			}
			if err := c.cfg.Source.Delete(keys); err != nil {
				c.cfg.Log.Warn("delete stale keys", "err", err)
			}
			c.cfg.Log.Info("cleaned up dead cgroups", "cgroups", len(gone), "keys", len(keys))
		}
	}
	return nil
}

func (c *Collector) collectCgroups(s *Snapshot, ids map[uint64]bool) {
	if c.cfg.Resolver == nil {
		return
	}
	for id := range ids {
		if id == 0 {
			continue
		}
		path, ok := c.cfg.Resolver.Lookup(id)
		if !ok {
			continue
		}
		dir := c.cfg.Resolver.Path(path)
		st, err := cgroupmap.ReadIOStat(filepath.Join(dir, "io.stat"))
		if err != nil || len(st) == 0 {
			// root has no io.stat, and idle cgroups have an empty one
			if c.cfg.Source == nil {
				continue
			}
		}
		cg := &CgroupIO{ID: id, Labels: c.label(id), IOStat: st}
		if p, err := psi.ReadFile(filepath.Join(dir, "io.pressure")); err == nil {
			cg.Pressure, cg.HasPSI = p, true
			if prev, ok := c.prevCgPSI[id]; ok && s.Interval > 0 {
				cg.Share = psi.Between(prev, p, s.Interval)
			}
			c.prevCgPSI[id] = p
		}
		s.Cgroups = append(s.Cgroups, cg)
	}
}

// devName maps a dev_t to its name through /sys/dev/block/MAJ:MIN/uevent
func (c *Collector) devName(dev uint32) string {
	if n, ok := c.devNames[dev]; ok {
		return n
	}
	maj, min := dev>>20, dev&(1<<20-1)
	name := fmt.Sprintf("%d:%d", maj, min)
	b, err := os.ReadFile(filepath.Join(c.cfg.SysRoot, fmt.Sprintf("dev/block/%d:%d/uevent", maj, min)))
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "DEVNAME="); ok {
				name = v
				break
			}
		}
	}
	c.devNames[dev] = name
	return name
}

// label resolves a cgroup id to pod labels. cached, but entries without a
// pod name get retried since the informer may just not have it yet
func (c *Collector) label(id uint64) Labels {
	if id == 0 {
		return Labels{}
	}
	if l, ok := c.labels[id]; ok && (l.Pod != "" || c.cfg.Pods == nil) {
		return l
	}
	var l Labels
	if c.cfg.Resolver != nil {
		path, ok := c.cfg.Resolver.Lookup(id)
		if !ok {
			return Labels{Cgroup: fmt.Sprintf("cgroup-%d", id)}
		}
		l.Cgroup = path
		if ref, ok := cgroupmap.ParsePath(path); ok {
			if pod, ok := c.cfg.Pods.Lookup(ref.PodUID); ok {
				l.Namespace, l.Pod = pod.Namespace, pod.Name
				l.Container = pod.Containers[ref.ContainerID]
				if l.Container == "" && ref.ContainerID != "" {
					l.Container = ref.ContainerID[:12]
				}
			}
		}
	}
	c.labels[id] = l
	return l
}

// recentRing keeps the cumulative count every 30s for the last ~5 min,
// so we can tell which cgroups were busy lately
type recentRing struct {
	at    [10]time.Time
	count [10]uint64
	pos   int
	n     int
}

func (r *recentRing) observe(now time.Time, cum uint64) uint64 {
	last := (r.pos + len(r.at) - 1) % len(r.at)
	if r.n == 0 || now.Sub(r.at[last]) >= 30*time.Second {
		r.at[r.pos], r.count[r.pos] = now, cum
		r.pos = (r.pos + 1) % len(r.at)
		if r.n < len(r.at) {
			r.n++
		}
	}
	oldest := (r.pos + len(r.at) - r.n) % len(r.at)
	if cum < r.count[oldest] {
		return cum
	}
	return cum - r.count[oldest]
}
