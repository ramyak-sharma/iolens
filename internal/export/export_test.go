package export

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ramyak-sharma/iolens/internal/collector"
	"github.com/ramyak-sharma/iolens/internal/diskstats"
	"github.com/ramyak-sharma/iolens/internal/hist"
	"github.com/ramyak-sharma/iolens/internal/probe"
)

type fixed struct{ s *collector.Snapshot }

func (f fixed) Latest() *collector.Snapshot { return f.s }

func series(cg uint64, pod string, recent, count uint64, us uint64) *collector.Series {
	h := hist.Hist{Count: count, Bytes: count * 4096, TotalNs: count * us * 1000, DeviceNs: count * us * 1000}
	h.Total[hist.Index(us)] = count
	h.Device[hist.Index(us)] = count
	return &collector.Series{
		Key:    probe.Key{Cgroup: cg, Op: probe.OpRead},
		Device: "vdb",
		Labels: collector.Labels{Namespace: "default", Pod: pod},
		Cum:    h,
		Recent: recent,
	}
}

func snapshot() *collector.Snapshot {
	return &collector.Snapshot{
		Time: time.Now(), Interval: time.Second, BPF: true,
		Devices: []diskstats.Rates{{Name: "vdb", RPS: 100, AquSz: 1.5, Util: 0.4}},
		Series: []*collector.Series{
			series(1, "db", 1000, 500, 300),
			series(2, "web", 500, 100, 1500),
			series(3, "batch", 10, 50, 3000),
			// same pod labels, different cgroup (container restart)
			series(4, "db", 5, 20, 300),
		},
		Findings: []collector.Finding{{Rule: "noisy-neighbour", Device: "vdb", Victim: "default/db", Culprit: "default/web", Severity: "warning"}},
	}
}

func TestMetricsLint(t *testing.T) {
	e := New(fixed{snapshot()}, 50)
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(e)
	if _, err := reg.Gather(); err != nil {
		t.Fatal(err)
	}
	probs, err := testutil.CollectAndLint(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probs {
		t.Errorf("lint: %s: %s", p.Metric, p.Text)
	}
}

func TestCardinalityGuard(t *testing.T) {
	e := New(fixed{snapshot()}, 2)
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(e)
	want := `
# HELP iolens_request_bytes_total Bytes completed.
# TYPE iolens_request_bytes_total counter
iolens_request_bytes_total{cgroup="",container="",device="vdb",namespace="",op="read",pod="_other"} 204800
iolens_request_bytes_total{cgroup="",container="",device="vdb",namespace="default",op="read",pod="db"} 2.12992e+06
iolens_request_bytes_total{cgroup="",container="",device="vdb",namespace="default",op="read",pod="web"} 409600
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "iolens_request_bytes_total"); err != nil {
		t.Error(err)
	}
}

func TestHistogramBuckets(t *testing.T) {
	e := New(fixed{snapshot()}, 50)
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(e)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "iolens_request_total_seconds" {
			continue
		}
		for _, m := range mf.Metric {
			h := m.GetHistogram()
			if len(h.Bucket) != hist.MaxOrder+1 {
				t.Errorf("got %d buckets", len(h.Bucket))
			}
			last := h.Bucket[len(h.Bucket)-1]
			if last.GetCumulativeCount() != h.GetSampleCount() {
				t.Errorf("top bucket %d != count %d", last.GetCumulativeCount(), h.GetSampleCount())
			}
		}
		return
	}
	t.Fatal("no total histogram exported")
}
