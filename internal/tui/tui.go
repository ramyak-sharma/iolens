// package tui is the `iolens top` view. plain ansi redraw every interval,
// no curses library, it only needs to work in a normal terminal
package tui

import (
	"context"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ramyak-sharma/iolens/internal/collector"
	"github.com/ramyak-sharma/iolens/internal/hist"
)

const (
	clear   = "\x1b[H\x1b[2J"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[31m"
	yellow  = "\x1b[33m"
	reset   = "\x1b[0m"
	maxRows = 15
)

func Run(ctx context.Context, w io.Writer, snaps <-chan *collector.Snapshot) {
	for {
		select {
		case <-ctx.Done():
			return
		case s, ok := <-snaps:
			if !ok {
				return
			}
			fmt.Fprint(w, clear+Render(s))
		}
	}
}

type row struct {
	who, dev, op      string
	iops, mbps        float64
	p50, p99, p999    float64
	queueMs, deviceMs float64
}

// Render draws one frame. separate from Run so its testable
func Render(s *collector.Snapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%siolens%s  %s  interval %s", bold, reset, s.Time.Format("15:04:05"), s.Interval.Round(time.Millisecond))
	if !s.BPF {
		b.WriteString("  " + yellow + "(no bpf: diskstats/psi/io.stat only)" + reset)
	}
	fmt.Fprintf(&b, "  psi some %4.1f%% full %4.1f%%\n\n", s.NodePSI.Some*100, s.NodePSI.Full*100)

	fmt.Fprintf(&b, "%s%-10s %8s %8s %9s %9s %8s %8s %6s %6s%s\n", dim,
		"DEVICE", "r/s", "w/s", "rMB/s", "wMB/s", "r_await", "w_await", "aqu", "util", reset)
	for _, d := range s.Devices {
		fmt.Fprintf(&b, "%-10s %8.0f %8.0f %9.1f %9.1f %8.2f %8.2f %6.1f %5.0f%%\n",
			d.Name, d.RPS, d.WPS, d.RKBps/1024, d.WKBps/1024, d.RAwaitMs, d.WAwaitMs, d.AquSz, d.Util*100)
	}

	if s.BPF {
		b.WriteString("\n")
		fmt.Fprintf(&b, "%s%-36s %-8s %-6s %7s %7s %8s %8s %8s %7s %7s%s\n", dim,
			"POD / CGROUP", "DEVICE", "OP", "iops", "MB/s", "p50", "p99", "p99.9", "queue", "device", reset)
		rows := rowsFor(s)
		for i, r := range rows {
			if i == maxRows {
				fmt.Fprintf(&b, "%s... %d more%s\n", dim, len(rows)-maxRows, reset)
				break
			}
			fmt.Fprintf(&b, "%-36s %-8s %-6s %7.0f %7.1f %8s %8s %8s %6.2fm %6.2fm\n",
				trim(r.who, 36), r.dev, r.op, r.iops, r.mbps, ms(r.p50), ms(r.p99), ms(r.p999), r.queueMs, r.deviceMs)
		}
	}

	b.WriteString("\n" + bold + "findings" + reset + "\n")
	switch {
	case s.Warming:
		b.WriteString(dim + "  warming up baselines..." + reset + "\n")
	case len(s.Findings) == 0:
		b.WriteString(dim + "  none" + reset + "\n")
	}
	for _, f := range s.Findings {
		col := yellow
		if f.Severity == "critical" {
			col = red
		}
		fmt.Fprintf(&b, "  %s%-8s%s %-18s %s %s(for %s)%s\n", col, f.Severity, reset, f.Rule, f.Sentence,
			dim, s.Time.Sub(f.Since).Round(time.Second), reset)
	}
	return b.String()
}

func rowsFor(s *collector.Snapshot) []row {
	sec := s.Interval.Seconds()
	if sec == 0 {
		sec = 1
	}
	var rows []row
	for _, ser := range s.Series {
		h := &ser.Win
		if h.Count == 0 {
			continue
		}
		rows = append(rows, row{
			who:      ser.Labels.Display(),
			dev:      ser.Device,
			op:       ser.Key.Op.String(),
			iops:     float64(h.Count) / sec,
			mbps:     float64(h.Bytes) / sec / (1 << 20),
			p50:      q(h, 0.5),
			p99:      q(h, 0.99),
			p999:     q(h, 0.999),
			queueMs:  h.MeanQueueUs() / 1000,
			deviceMs: h.MeanDeviceUs() / 1000,
		})
	}
	// worst tail first, thats what youre looking for
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].p99, rows[j].p99
		if math.IsNaN(a) {
			a = -1
		}
		if math.IsNaN(b) {
			b = -1
		}
		if a != b {
			return a > b
		}
		return rows[i].iops > rows[j].iops
	})
	return rows
}

func q(h *hist.Hist, p float64) float64 {
	v, _ := hist.Quantile(&h.Total, p)
	return v
}

func ms(us float64) string {
	if math.IsNaN(us) {
		return "-"
	}
	if us >= 1000 {
		return fmt.Sprintf("%.1fms", us/1000)
	}
	return fmt.Sprintf("%.0fus", us)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n+3:]
}
