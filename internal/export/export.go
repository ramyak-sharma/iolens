// package export serves the latest snapshot as prometheus metrics. kernel
// counters are cumulative already, which is what prometheus wants, so
// nothing here resets anything.
package export

import (
	"sort"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ramyak-sharma/iolens/internal/collector"
	"github.com/ramyak-sharma/iolens/internal/hist"
)

const Other = "_other"

var podLabels = []string{"namespace", "pod", "container", "cgroup"}

func withPod(extra ...string) []string {
	return append(append([]string{}, extra...), podLabels...)
}

var (
	descDevTime = prometheus.NewDesc("iolens_request_device_seconds",
		"Device time per block request (issue to complete).", withPod("device", "op"), nil)
	descTotTime = prometheus.NewDesc("iolens_request_total_seconds",
		"Queue plus device time per block request (insert to complete).", withPod("device", "op"), nil)
	descBytes = prometheus.NewDesc("iolens_request_bytes_total",
		"Bytes completed.", withPod("device", "op"), nil)
	descErrors = prometheus.NewDesc("iolens_request_errors_total",
		"Completions with non zero status.", withPod("device", "op"), nil)

	descCgBytes = prometheus.NewDesc("iolens_cgroup_io_bytes_total",
		"Bytes from the cgroup io.stat file, independent of bpf.", withPod("device", "dir"), nil)
	descCgPSI = prometheus.NewDesc("iolens_cgroup_io_pressure_seconds_total",
		"Per cgroup io stall time from io.pressure.", withPod("kind"), nil)

	descIOPS   = prometheus.NewDesc("iolens_device_iops", "Completed IOs per second, from diskstats.", []string{"device", "op"}, nil)
	descTput   = prometheus.NewDesc("iolens_device_throughput_bytes", "Bytes per second, from diskstats.", []string{"device", "op"}, nil)
	descAwait  = prometheus.NewDesc("iolens_device_await_seconds", "Average await, from diskstats. An average, use the histograms for tails.", []string{"device", "op"}, nil)
	descUtil   = prometheus.NewDesc("iolens_device_utilization_ratio", "Share of time with at least one request in flight. Not saturation on NVMe.", []string{"device"}, nil)
	descQDepth = prometheus.NewDesc("iolens_device_queue_depth", "Average requests in flight (aqu-sz).", []string{"device"}, nil)
	descNodePS = prometheus.NewDesc("iolens_node_io_pressure_ratio", "Node wide io PSI share for the last interval.", []string{"kind"}, nil)

	descFinding = prometheus.NewDesc("iolens_finding_active", "1 while a finding is firing.", []string{"rule", "device", "victim", "culprit", "severity"}, nil)
	descWarming = prometheus.NewDesc("iolens_rules_warming", "1 while rule baselines are still warming up.", nil, nil)

	descBPFns    = prometheus.NewDesc("iolens_agent_bpf_run_ns_per_event", "Per event cost from kernel bpf stats.", []string{"program"}, nil)
	descInflight = prometheus.NewDesc("iolens_agent_inflight_entries", "Entries in the in flight map.", nil, nil)
)

// Source is anything with a latest snapshot, the collector in practice
type Source interface {
	Latest() *collector.Snapshot
}

type Exporter struct {
	c          Source
	topCgroups int
	collectDur prometheus.Histogram
}

func New(c Source, topCgroups int) *Exporter {
	return &Exporter{
		c:          c,
		topCgroups: topCgroups,
		collectDur: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "iolens_agent_collect_seconds",
			Help:    "Time to build one snapshot.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 12),
		}),
	}
}

// Observe records per snapshot agent metrics. called from a subscriber
// so we see every snapshot, not just the ones that line up with scrapes
func (e *Exporter) Observe(s *collector.Snapshot) {
	e.collectDur.Observe(s.Agent.CollectSeconds)
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descDevTime, descTotTime, descBytes, descErrors,
		descCgBytes, descCgPSI, descIOPS, descTput, descAwait, descUtil, descQDepth, descNodePS,
		descFinding, descWarming, descBPFns, descInflight} {
		ch <- d
	}
	e.collectDur.Describe(ch)
}

type labelSet struct {
	namespace, pod, container, cgroup string
}

func (l labelSet) values() []string { return []string{l.namespace, l.pod, l.container, l.cgroup} }

func toLabelSet(l collector.Labels) labelSet {
	if l.Pod != "" {
		return labelSet{namespace: l.Namespace, pod: l.Pod, container: l.Container}
	}
	if l.Cgroup == "" {
		return labelSet{cgroup: collector.Unattributed}
	}
	return labelSet{cgroup: l.Cgroup}
}

var otherSet = labelSet{pod: Other}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.collectDur.Collect(ch)
	s := e.c.Latest()
	if s == nil {
		return
	}
	keep := e.topPerDevice(s)
	e.collectSeries(ch, s, keep)
	e.collectCgroups(ch, s, keep)

	g := func(d *prometheus.Desc, v float64, lv ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, lv...)
	}
	for _, d := range s.Devices {
		g(descIOPS, d.RPS, d.Name, "read")
		g(descIOPS, d.WPS, d.Name, "write")
		g(descIOPS, d.DPS, d.Name, "discard")
		g(descIOPS, d.FPS, d.Name, "flush")
		g(descTput, d.RKBps*1024, d.Name, "read")
		g(descTput, d.WKBps*1024, d.Name, "write")
		g(descAwait, d.RAwaitMs/1000, d.Name, "read")
		g(descAwait, d.WAwaitMs/1000, d.Name, "write")
		g(descUtil, d.Util, d.Name)
		g(descQDepth, d.AquSz, d.Name)
	}
	g(descNodePS, s.NodePSI.Some, "some")
	g(descNodePS, s.NodePSI.Full, "full")
	for _, f := range s.Findings {
		g(descFinding, 1, f.Rule, f.Device, f.Victim, f.Culprit, f.Severity)
	}
	warm := 0.0
	if s.Warming {
		warm = 1
	}
	g(descWarming, warm)
	if s.BPF {
		for name, st := range s.Agent.BPF {
			g(descBPFns, st.NsPerEvent(), name)
		}
		g(descInflight, float64(s.Agent.Inflight))
	}
}

// topPerDevice is the cardinality guard: per device only the busiest N
// label sets over the last ~5 min get their own series
func (e *Exporter) topPerDevice(s *collector.Snapshot) map[string]map[labelSet]bool {
	recent := map[string]map[labelSet]uint64{}
	for _, ser := range s.Series {
		m := recent[ser.Device]
		if m == nil {
			m = map[labelSet]uint64{}
			recent[ser.Device] = m
		}
		m[toLabelSet(ser.Labels)] += ser.Recent
	}
	out := map[string]map[labelSet]bool{}
	for dev, m := range recent {
		sets := make([]labelSet, 0, len(m))
		for ls := range m {
			sets = append(sets, ls)
		}
		sort.Slice(sets, func(i, j int) bool {
			if m[sets[i]] != m[sets[j]] {
				return m[sets[i]] > m[sets[j]]
			}
			return sets[i].values()[1]+sets[i].cgroup < sets[j].values()[1]+sets[j].cgroup
		})
		keep := map[labelSet]bool{}
		for i, ls := range sets {
			if e.topCgroups <= 0 || i < e.topCgroups {
				keep[ls] = true
			}
		}
		out[dev] = keep
	}
	return out
}

type seriesKey struct {
	dev, op string
	ls      labelSet
}

func (e *Exporter) collectSeries(ch chan<- prometheus.Metric, s *collector.Snapshot, keep map[string]map[labelSet]bool) {
	// several cgroups can end up with the same labels (container restarted,
	// or folded into _other) so sum before emitting. if one of them goes
	// away the sum drops, prometheus treats that as a counter reset
	agg := map[seriesKey]*hist.Hist{}
	var order []seriesKey
	for _, ser := range s.Series {
		ls := toLabelSet(ser.Labels)
		if !keep[ser.Device][ls] {
			ls = otherSet
		}
		k := seriesKey{ser.Device, ser.Key.Op.String(), ls}
		h := agg[k]
		if h == nil {
			h = &hist.Hist{}
			agg[k] = h
			order = append(order, k)
		}
		h.Add(&ser.Cum)
	}
	for _, k := range order {
		h := agg[k]
		lv := append([]string{k.dev, k.op}, k.ls.values()...)
		ch <- prometheus.MustNewConstHistogram(descDevTime, h.Count, float64(h.DeviceNs)/1e9, hist.Cumulative(&h.Device), lv...)
		ch <- prometheus.MustNewConstHistogram(descTotTime, h.Count, float64(h.TotalNs)/1e9, hist.Cumulative(&h.Total), lv...)
		ch <- prometheus.MustNewConstMetric(descBytes, prometheus.CounterValue, float64(h.Bytes), lv...)
		ch <- prometheus.MustNewConstMetric(descErrors, prometheus.CounterValue, float64(h.Errors), lv...)
	}
}

func (e *Exporter) collectCgroups(ch chan<- prometheus.Metric, s *collector.Snapshot, keep map[string]map[labelSet]bool) {
	type bk struct {
		dev, dir string
		ls       labelSet
	}
	bytes := map[bk]float64{}
	type pk struct {
		kind string
		ls   labelSet
	}
	pressure := map[pk]float64{}

	for _, cg := range s.Cgroups {
		ls := toLabelSet(cg.Labels)
		for _, st := range cg.IOStat {
			dev := s.DevName(st.Major, st.Minor)
			l := ls
			if k, ok := keep[dev]; ok && !k[ls] {
				l = otherSet
			}
			bytes[bk{dev, "read", l}] += float64(st.RBytes)
			bytes[bk{dev, "write", l}] += float64(st.WBytes)
			bytes[bk{dev, "discard", l}] += float64(st.DBytes)
		}
		if cg.HasPSI {
			pressure[pk{"some", ls}] += float64(cg.Pressure.Some.Total) / 1e6
			if cg.Pressure.HasFull {
				pressure[pk{"full", ls}] += float64(cg.Pressure.Full.Total) / 1e6
			}
		}
	}
	for k, v := range bytes {
		ch <- prometheus.MustNewConstMetric(descCgBytes, prometheus.CounterValue, v,
			append([]string{k.dev, k.dir}, k.ls.values()...)...)
	}
	for k, v := range pressure {
		ch <- prometheus.MustNewConstMetric(descCgPSI, prometheus.CounterValue, v,
			append([]string{k.kind}, k.ls.values()...)...)
	}
}
