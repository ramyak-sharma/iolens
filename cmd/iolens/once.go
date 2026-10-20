package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"os"
	"time"

	"github.com/ramyak-sharma/iolens/internal/collector"
	"github.com/ramyak-sharma/iolens/internal/diskstats"
	"github.com/ramyak-sharma/iolens/internal/hist"
)

// json output of `iolens once`. the validation scripts read this, keep
// field names stable
type onceOut struct {
	Start    time.Time          `json:"start"`
	Duration float64            `json:"duration_seconds"`
	BPF      bool               `json:"bpf"`
	Windows  []onceWindow       `json:"windows"`
	Summary  []onceSeries       `json:"summary"` // whole run folded together
	BPFStats map[string]float64 `json:"bpf_ns_per_event,omitempty"`
}

type onceWindow struct {
	Time     time.Time         `json:"time"`
	Interval float64           `json:"interval_seconds"`
	Devices  []diskstats.Rates `json:"devices"`
	Series   []onceSeries      `json:"series"`
	PSISome  float64           `json:"psi_some"`
	PSIFull  float64           `json:"psi_full"`
}

type onceSeries struct {
	Cgroup   uint64   `json:"cgroup_id"`
	Who      string   `json:"who"`
	Path     string   `json:"cgroup_path,omitempty"`
	Device   string   `json:"device"`
	Op       string   `json:"op"`
	Count    uint64   `json:"count"`
	Bytes    uint64   `json:"bytes"`
	Errors   uint64   `json:"errors"`
	TotP50   *float64 `json:"total_p50_us"`
	TotP99   *float64 `json:"total_p99_us"`
	TotP999  *float64 `json:"total_p999_us"`
	DevP50   *float64 `json:"device_p50_us"`
	DevP99   *float64 `json:"device_p99_us"`
	QueueAvg float64  `json:"queue_mean_us"`
	DevAvg   float64  `json:"device_mean_us"`
}

func runOnce(ctx context.Context, o options) error {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if o.logFile != "" {
		l, done, err := logger("once", o)
		if err != nil {
			return err
		}
		defer done()
		log = l
	}
	c, cleanup, err := setup(ctx, o, log, nil)
	if err != nil {
		return err
	}
	defer cleanup()

	if o.align {
		// iostat samples on its own start time, the v2 script starts it on a
		// whole second, so we do the same and both see the same windows
		now := time.Now()
		time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now))
	}
	out := onceOut{Start: time.Now()}
	if _, err := c.Collect(); err != nil { // baseline sample
		return err
	}
	type sk struct {
		cg      uint64
		dev, op string
	}
	total := map[sk]*hist.Hist{}
	meta := map[sk]*collector.Series{}
	var last *collector.Snapshot

	t := time.NewTicker(o.interval)
	defer t.Stop()
	deadline := time.After(o.duration)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-deadline:
			break loop
		case <-t.C:
			s, err := c.Collect()
			if err != nil {
				return err
			}
			last = s
			out.BPF = s.BPF
			win := onceWindow{Time: s.Time, Interval: s.Interval.Seconds(), Devices: s.Devices,
				PSISome: s.NodePSI.Some, PSIFull: s.NodePSI.Full}
			for _, ser := range s.Series {
				if ser.Win.Count == 0 {
					continue
				}
				win.Series = append(win.Series, toOnce(ser, &ser.Win))
				k := sk{ser.Key.Cgroup, ser.Device, ser.Key.Op.String()}
				if total[k] == nil {
					total[k] = &hist.Hist{}
					meta[k] = ser
				}
				total[k].Add(&ser.Win)
			}
			out.Windows = append(out.Windows, win)
		}
	}
	out.Duration = time.Since(out.Start).Seconds()
	for k, h := range total {
		out.Summary = append(out.Summary, toOnce(meta[k], h))
	}
	if last != nil && len(last.Agent.BPF) > 0 {
		out.BPFStats = map[string]float64{}
		for n, st := range last.Agent.BPF {
			out.BPFStats[n] = st.NsPerEvent()
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func toOnce(ser *collector.Series, h *hist.Hist) onceSeries {
	return onceSeries{
		Cgroup: ser.Key.Cgroup, Who: ser.Labels.Display(), Path: ser.Labels.Cgroup,
		Device: ser.Device, Op: ser.Key.Op.String(),
		Count: h.Count, Bytes: h.Bytes, Errors: h.Errors,
		TotP50: num(hist.Quantile(&h.Total, 0.5)), TotP99: num(hist.Quantile(&h.Total, 0.99)),
		TotP999: num(hist.Quantile(&h.Total, 0.999)),
		DevP50:  num(hist.Quantile(&h.Device, 0.5)), DevP99: num(hist.Quantile(&h.Device, 0.99)),
		QueueAvg: h.MeanQueueUs(), DevAvg: h.MeanDeviceUs(),
	}
}

// missing percentiles become null instead of NaN, which json cant hold
func num(v float64, ok bool) *float64 {
	if !ok || math.IsNaN(v) {
		return nil
	}
	return &v
}
