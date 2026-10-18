package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/ramyak-sharma/iolens/internal/collector"
	"github.com/ramyak-sharma/iolens/internal/diskstats"
	"github.com/ramyak-sharma/iolens/internal/hist"
	"github.com/ramyak-sharma/iolens/internal/probe"
)

func TestRender(t *testing.T) {
	h := hist.Hist{Count: 200, Bytes: 200 * 4096}
	h.Total[hist.Index(900)] = 200
	now := time.Now()
	s := &collector.Snapshot{
		Time: now, Interval: time.Second, BPF: true,
		Devices: []diskstats.Rates{{Name: "vdb", RPS: 200}},
		Series: []*collector.Series{{Key: probe.Key{Op: probe.OpRead}, Device: "vdb",
			Labels: collector.Labels{Namespace: "default", Pod: "db", Container: "fio"}, Win: h}},
		Findings: []collector.Finding{{Rule: "noisy-neighbour", Severity: "warning",
			Sentence: "vdb: default/db read p99 rose 0.9ms -> 25ms", Since: now.Add(-12 * time.Second)}},
	}
	out := Render(s)
	for _, want := range []string{"vdb", "default/db/fio", "noisy-neighbour", "for 12s"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
	s.Findings, s.Warming = nil, true
	if out := Render(s); !strings.Contains(out, "warming up") {
		t.Error("should show warming up")
	}
}

func TestTrim(t *testing.T) {
	if got := trim("kubepods.slice/very/long/path", 10); len(got) != 10 || !strings.HasPrefix(got, "...") {
		t.Errorf("trim = %q", got)
	}
}
