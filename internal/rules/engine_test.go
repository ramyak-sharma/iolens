package rules

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ramyak-sharma/iolens/internal/collector"
	"github.com/ramyak-sharma/iolens/internal/diskstats"
	"github.com/ramyak-sharma/iolens/internal/hist"
	"github.com/ramyak-sharma/iolens/internal/probe"
	"github.com/ramyak-sharma/iolens/internal/psi"
)

// scenario builds snapshots one second apart
type scenario struct {
	t   *testing.T
	e   *Engine
	now time.Time
}

func newScenario(t *testing.T) *scenario {
	cfg := Defaults()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &scenario{t: t, e: New(cfg, log), now: time.Unix(1_700_000_000, 0)}
}

type load struct {
	pod     string
	op      probe.Op
	n       uint64 // requests this second
	latUs   uint64 // total latency of each
	devUs   uint64 // device part, 0 = same as latUs
	bytesEa uint64 // bytes per request
}

func (sc *scenario) tick(depth, psiSome float64, loads ...load) {
	s := &collector.Snapshot{Time: sc.now, Interval: time.Second, NodePSI: psi.Share{Some: psiSome}}
	var iops float64
	for i, l := range loads {
		h := hist.Hist{Count: l.n, Bytes: l.n * l.bytesEa}
		dev := l.devUs
		if dev == 0 {
			dev = l.latUs
		}
		h.Total[hist.Index(l.latUs)] = l.n
		h.Device[hist.Index(dev)] = l.n
		h.TotalNs = l.n * l.latUs * 1000
		h.DeviceNs = l.n * dev * 1000
		h.QueueNs = h.TotalNs - h.DeviceNs
		s.Series = append(s.Series, &collector.Series{
			Key:    probe.Key{Cgroup: uint64(i + 1), Op: l.op},
			Device: "vdb",
			Labels: collector.Labels{Namespace: "default", Pod: l.pod},
			Win:    h,
		})
		iops += float64(l.n)
	}
	s.Devices = []diskstats.Rates{{Name: "vdb", RPS: iops, AquSz: depth}}
	sc.e.Observe(s)
	sc.now = sc.now.Add(time.Second)
}

func (sc *scenario) findings() []collector.Finding {
	f, _ := sc.e.Findings()
	return f
}

func (sc *scenario) has(rule string) *collector.Finding {
	for _, f := range sc.findings() {
		if f.Rule == rule {
			return &f
		}
	}
	return nil
}

var (
	dbQuiet  = load{pod: "db", op: probe.OpRead, n: 200, latUs: 300, bytesEa: 4096}
	dbHurt   = load{pod: "db", op: probe.OpRead, n: 200, latUs: 6000, devUs: 1500, bytesEa: 4096}
	writer   = load{pod: "noisy-writer", op: probe.OpWrite, n: 400, latUs: 8000, bytesEa: 1 << 20}
	writerLo = load{pod: "noisy-writer", op: probe.OpWrite, n: 2, latUs: 500, bytesEa: 4096}
)

func TestQuietDuringWarmUp(t *testing.T) {
	sc := newScenario(t)
	for i := 0; i < 100; i++ {
		sc.tick(20, 0.5, dbHurt, writer)
	}
	if f := sc.findings(); len(f) != 0 {
		t.Errorf("fired during warm up: %v", f)
	}
	if _, warming := sc.e.Findings(); !warming {
		t.Error("should report warming")
	}
}

func TestNoisyNeighbourFiresAndClears(t *testing.T) {
	sc := newScenario(t)
	for i := 0; i < 150; i++ {
		sc.tick(0.5, 0, dbQuiet)
	}
	if len(sc.findings()) != 0 {
		t.Fatalf("findings while quiet: %v", sc.findings())
	}

	fired := -1
	for i := 0; i < 20; i++ {
		sc.tick(2, 0.02, dbHurt, writer)
		if fired < 0 && sc.has("noisy-neighbour") != nil {
			fired = i
		}
	}
	if fired < 0 {
		t.Fatal("noisy-neighbour never fired")
	}
	// needs fireAfter (3) true evals, condition is true from the first tick
	if fired != 2 {
		t.Errorf("fired after %d ticks, want 2 (third eval)", fired)
	}
	f := sc.has("noisy-neighbour")
	if f.Victim != "default/db" || f.Culprit != "default/noisy-writer" {
		t.Errorf("victim/culprit = %q/%q", f.Victim, f.Culprit)
	}
	if !strings.Contains(f.Sentence, "noisy-writer went to") {
		t.Errorf("sentence = %q", f.Sentence)
	}

	// noise stops. the window still holds bad samples for 10 ticks, then 6
	// clean evals are needed to clear
	cleared := -1
	for i := 0; i < 30; i++ {
		sc.tick(0.5, 0, dbQuiet, writerLo)
		if cleared < 0 && sc.has("noisy-neighbour") == nil {
			cleared = i
		}
	}
	if cleared < 0 {
		t.Fatal("never cleared")
	}
	if cleared > 20 {
		t.Errorf("took %d ticks to clear", cleared)
	}
}

func TestDoesNotLearnIncident(t *testing.T) {
	sc := newScenario(t)
	for i := 0; i < 150; i++ {
		sc.tick(0.5, 0, dbQuiet)
	}
	// 15 minutes of incident, many half lives. baseline must not drift up
	for i := 0; i < 900; i++ {
		sc.tick(2, 0.02, dbHurt, writer)
	}
	if sc.has("noisy-neighbour") == nil {
		t.Fatal("finding should still be active after a long incident")
	}
	b := sc.e.base.get(keyP99("vdb", "default/db", "read"))
	if b.value > 1000 {
		t.Errorf("victim baseline drifted to %vus", b.value)
	}
}

func TestHysteresisNoFlap(t *testing.T) {
	sc := newScenario(t)
	for i := 0; i < 150; i++ {
		sc.tick(0.5, 0, dbQuiet)
	}
	// saturated only on every other tick, window mean stays above threshold
	// for a bit but individual evals flip. finding should not flap off/on
	changes := 0
	prev := false
	for i := 0; i < 40; i++ {
		depth := 0.0
		if i%2 == 0 {
			depth = 30
		}
		sc.tick(depth, 0.3, dbQuiet)
		now := sc.has("saturated") != nil
		if now != prev {
			changes++
		}
		prev = now
	}
	if changes > 1 {
		t.Errorf("saturated changed state %d times", changes)
	}
}

func TestDeviceSlow(t *testing.T) {
	sc := newScenario(t)
	for i := 0; i < 150; i++ {
		sc.tick(0.3, 0, dbQuiet)
	}
	slow := dbQuiet
	slow.latUs, slow.devUs = 5000, 5000
	for i := 0; i < 5; i++ {
		sc.tick(0.3, 0, slow)
	}
	f := sc.has("device-slow")
	if f == nil {
		t.Fatalf("device-slow did not fire, have %v", sc.findings())
	}
	if f.Device != "vdb" {
		t.Errorf("device %q", f.Device)
	}
	if sc.has("noisy-neighbour") != nil {
		t.Error("no other pod, noisy-neighbour should not fire")
	}
}

func TestQueueingDominantAndErrors(t *testing.T) {
	sc := newScenario(t)
	for i := 0; i < 150; i++ {
		sc.tick(0.3, 0, dbQuiet)
	}
	q := dbQuiet
	q.latUs, q.devUs = 3000, 500
	for i := 0; i < 4; i++ {
		s := &collector.Snapshot{Time: sc.now, Interval: time.Second}
		h := hist.Hist{Count: 200, Errors: 1, TotalNs: 200 * 3000_000, DeviceNs: 200 * 500_000, QueueNs: 200 * 2500_000}
		h.Total[hist.Index(3000)] = 200
		h.Device[hist.Index(500)] = 200
		s.Series = []*collector.Series{{Device: "vdb", Labels: collector.Labels{Namespace: "default", Pod: "db"}, Win: h}}
		sc.e.Observe(s)
		sc.now = sc.now.Add(time.Second)
	}
	if sc.has("queueing-dominant") == nil {
		t.Error("queueing-dominant should fire")
	}
	if f := sc.has("io-errors"); f == nil || !strings.Contains(f.Sentence, "I/O errors") {
		t.Errorf("io-errors = %+v", f)
	}
}

func TestIOStall(t *testing.T) {
	sc := newScenario(t)
	for i := 0; i < 125; i++ {
		s := &collector.Snapshot{Time: sc.now, Interval: time.Second, NodePSI: psi.Share{Some: 0.3, Full: 0.2}}
		sc.e.Observe(s)
		sc.now = sc.now.Add(time.Second)
	}
	if f := sc.has("io-stall"); f == nil || f.Victim != "node" {
		t.Errorf("io-stall = %+v", f)
	}
}
