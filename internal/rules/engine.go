package rules

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ramyak-sharma/iolens/internal/collector"
	"github.com/ramyak-sharma/iolens/internal/hist"
)

type Engine struct {
	cfg Config
	log *slog.Logger

	ring  []*collector.Snapshot
	base  *baselines
	start time.Time
	state map[string]*tracked

	mu      sync.RWMutex
	active  []collector.Finding
	warming bool
}

type tracked struct {
	finding  collector.Finding
	trueRun  int
	falseRun int
	active   bool
	// baseline keys this finding is about, frozen while it is active
	involves []string
}

func New(cfg Config, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{
		cfg:     cfg,
		log:     log,
		base:    newBaselines(cfg.HalfLife),
		state:   map[string]*tracked{},
		warming: true,
	}
}

// Findings is plugged into the collector, returns a copy
func (e *Engine) Findings() ([]collector.Finding, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]collector.Finding, len(e.active))
	copy(out, e.active)
	return out, e.warming
}

func (e *Engine) Run(ctx context.Context, snaps <-chan *collector.Snapshot) {
	for {
		select {
		case <-ctx.Done():
			return
		case s, ok := <-snaps:
			if !ok {
				return
			}
			e.Observe(s)
		}
	}
}

// candidate is a condition that is true in this evaluation
type candidate struct {
	id       string
	finding  collector.Finding
	involves []string
}

// Observe evaluates all rules against the window ending at s
func (e *Engine) Observe(s *collector.Snapshot) {
	if s.Interval == 0 {
		return // first snapshot has no deltas
	}
	if e.start.IsZero() {
		e.start = s.Time
	}
	e.ring = append(e.ring, s)
	if len(e.ring) > e.cfg.Window {
		e.ring = e.ring[len(e.ring)-e.cfg.Window:]
	}
	now := s.Time
	w := buildWindow(e.ring)
	warming := now.Sub(e.start) < e.cfg.WarmUp

	var cands []candidate
	if !warming {
		cands = append(cands, e.noisyNeighbour(w, now)...)
		cands = append(cands, e.deviceSlow(w, now)...)
		cands = append(cands, e.saturated(w)...)
		cands = append(cands, e.queueingDominant(w)...)
		cands = append(cands, e.ioStall(w)...)
		cands = append(cands, e.ioErrors(w)...)
	}
	e.step(now, cands)
	e.updateBaselines(w, now)
	e.base.gc(now, 30*time.Minute)

	var act []collector.Finding
	for _, t := range e.state {
		if t.active {
			act = append(act, t.finding)
		}
	}
	sort.Slice(act, func(i, j int) bool {
		if act[i].Since.Equal(act[j].Since) {
			return act[i].Sentence < act[j].Sentence
		}
		return act[i].Since.Before(act[j].Since)
	})
	e.mu.Lock()
	e.active, e.warming = act, warming
	e.mu.Unlock()
}

// step applies hysteresis: fire after FireAfter trues in a row, clear
// after ClearAfter falses in a row. stops findings flapping on a threshold
func (e *Engine) step(now time.Time, cands []candidate) {
	seen := map[string]bool{}
	for _, c := range cands {
		seen[c.id] = true
		t := e.state[c.id]
		if t == nil {
			t = &tracked{}
			e.state[c.id] = t
		}
		t.trueRun++
		t.falseRun = 0
		t.involves = c.involves
		since := t.finding.Since
		t.finding = c.finding
		if t.active {
			t.finding.Since = since
			continue
		}
		if t.trueRun >= e.cfg.FireAfter {
			t.active = true
			t.finding.Since = now
			e.log.Warn("finding fired", "event", "fire", "rule", c.finding.Rule,
				"severity", c.finding.Severity, "device", c.finding.Device,
				"victim", c.finding.Victim, "culprit", c.finding.Culprit,
				"evidence", c.finding.Evidence, "sentence", c.finding.Sentence)
		}
	}
	for id, t := range e.state {
		if seen[id] {
			continue
		}
		t.trueRun = 0
		t.falseRun++
		if !t.active {
			delete(e.state, id)
			continue
		}
		if t.falseRun >= e.cfg.ClearAfter {
			e.log.Info("finding cleared", "event", "clear", "rule", t.finding.Rule,
				"device", t.finding.Device, "victim", t.finding.Victim,
				"culprit", t.finding.Culprit, "duration", now.Sub(t.finding.Since).String())
			delete(e.state, id)
		}
	}
}

// frozen are baseline keys that a pending or active finding is about.
// they dont learn, otherwise a long incident slowly becomes the new normal
func (e *Engine) frozen() map[string]bool {
	f := map[string]bool{}
	for _, t := range e.state {
		for _, k := range t.involves {
			f[k] = true
		}
	}
	return f
}

func (e *Engine) updateBaselines(w *window, now time.Time) {
	frozen := e.frozen()
	upd := func(k string, v float64) {
		if !frozen[k] {
			e.base.update(k, now, v)
		}
	}
	for k, sh := range w.series {
		if sh.Count >= e.cfg.MinRequests {
			if p99, ok := hist.Quantile(&sh.Total, 0.99); ok {
				upd(keyP99(k.dev, k.pod, k.op), p99)
			}
		}
	}
	for dev, d := range w.devices {
		upd(keyIOPS(dev), d.iops)
		if d.all.Count >= e.cfg.MinRequests {
			if p99, ok := hist.Quantile(&d.all.Device, 0.99); ok {
				upd(keyDevP99(dev), p99)
			}
		}
		for pod, b := range d.podBytes {
			upd(keyBps(dev, pod), b/w.seconds)
			if d.bytes > 0 {
				upd(keyShare(dev, pod), b/d.bytes)
			}
		}
	}
}

func keyP99(dev, pod, op string) string { return "p99|" + dev + "|" + pod + "|" + op }
func keyBps(dev, pod string) string     { return "bps|" + dev + "|" + pod }
func keyShare(dev, pod string) string   { return "share|" + dev + "|" + pod }
func keyDevP99(dev string) string       { return "devp99|" + dev }
func keyIOPS(dev string) string         { return "iops|" + dev }

// baselineOrZero is for culprits: a pod that wasnt doing io before has no
// baseline, and going from nothing to most of the disk definitely counts
func (e *Engine) baselineOrZero(key string, now time.Time) float64 {
	b := e.base.get(key)
	if !b.ready(now, e.cfg.WarmUp) {
		return 0
	}
	return b.value
}

func (e *Engine) noisyNeighbour(w *window, now time.Time) []candidate {
	var out []candidate
	for vk, vh := range w.series {
		if vh.Count < e.cfg.MinRequests {
			continue
		}
		bkey := keyP99(vk.dev, vk.pod, vk.op)
		base := e.base.get(bkey)
		if !base.ready(now, e.cfg.WarmUp) || base.value <= 0 {
			continue
		}
		p99, ok := hist.Quantile(&vh.Total, 0.99)
		if !ok || p99 < e.cfg.NoisyLatencyFactor*base.value {
			continue
		}
		d := w.devices[vk.dev]
		if d == nil || (d.bytes == 0 && d.ios == 0) {
			continue
		}
		type cand struct {
			pod       string
			share     float64
			increase  float64
			bps, base float64
		}
		var cs []cand
		for pod, b := range d.podBytes {
			if pod == vk.pod {
				continue
			}
			byteShare, ioShare := 0.0, 0.0
			if d.bytes > 0 {
				byteShare = b / d.bytes
			}
			if d.ios > 0 {
				ioShare = d.podIOs[pod] / d.ios
			}
			if byteShare < e.cfg.NoisyShare && ioShare < e.cfg.NoisyShare {
				continue
			}
			bps := b / w.seconds
			bb := e.baselineOrZero(keyBps(vk.dev, pod), now)
			if bps < e.cfg.NoisyThroughputFactor*bb {
				continue
			}
			inc := byteShare - e.baselineOrZero(keyShare(vk.dev, pod), now)
			cs = append(cs, cand{pod, byteShare, inc, bps, bb})
		}
		if len(cs) == 0 {
			continue
		}
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].increase == cs[j].increase {
				return cs[i].pod < cs[j].pod
			}
			return cs[i].increase > cs[j].increase
		})
		top := cs[0]
		k := p99 / base.value
		sentence := fmt.Sprintf("%s: %s %s p99 rose %s -> %s (%.0fx) while %s went to %.0f%% of device bytes",
			vk.dev, vk.pod, vk.op, fmtUs(base.value), fmtUs(p99), k, top.pod, top.share*100)
		var others []string
		for _, c := range cs[1:] {
			if len(others) == 2 {
				break
			}
			others = append(others, c.pod)
		}
		if len(others) > 0 {
			sentence += " (also: " + strings.Join(others, ", ") + ")"
		}
		out = append(out, candidate{
			id: "noisy-neighbour|" + vk.dev + "|" + vk.pod + "|" + vk.op,
			finding: collector.Finding{
				Rule: "noisy-neighbour", Severity: "warning",
				Device: vk.dev, Victim: vk.pod, Culprit: top.pod,
				Evidence: map[string]float64{
					"victim_p99_us": p99, "victim_p99_baseline_us": base.value, "factor": k,
					"culprit_byte_share": top.share, "culprit_bytes_per_sec": top.bps,
					"culprit_bytes_per_sec_baseline": top.base,
				},
				Sentence: sentence,
			},
			involves: []string{bkey, keyBps(vk.dev, top.pod), keyShare(vk.dev, top.pod)},
		})
	}
	return out
}

func (e *Engine) deviceSlow(w *window, now time.Time) []candidate {
	var out []candidate
	for dev, d := range w.devices {
		if d.all.Count < e.cfg.MinRequests {
			continue
		}
		base := e.base.get(keyDevP99(dev))
		iopsBase := e.base.get(keyIOPS(dev))
		if !base.ready(now, e.cfg.WarmUp) || !iopsBase.ready(now, e.cfg.WarmUp) || base.value <= 0 {
			continue
		}
		p99, ok := hist.Quantile(&d.all.Device, 0.99)
		if !ok || p99 < e.cfg.SlowDeviceFactor*base.value {
			continue
		}
		// "no more load than usual". 10% slack so normal jitter doesnt hide it
		if d.depth >= 1 || d.iops > iopsBase.value*1.1 {
			continue
		}
		out = append(out, candidate{
			id: "device-slow|" + dev,
			finding: collector.Finding{
				Rule: "device-slow", Severity: "warning", Device: dev,
				Evidence: map[string]float64{
					"device_p99_us": p99, "device_p99_baseline_us": base.value,
					"queue_depth": d.depth, "iops": d.iops, "iops_baseline": iopsBase.value,
				},
				Sentence: fmt.Sprintf("%s: device time p99 %s -> %s with no increase in load",
					dev, fmtUs(base.value), fmtUs(p99)),
			},
			involves: []string{keyDevP99(dev), keyIOPS(dev)},
		})
	}
	return out
}

func (e *Engine) saturated(w *window) []candidate {
	var out []candidate
	for dev, d := range w.devices {
		if d.depth < e.cfg.SaturatedDepth || w.psiSome < e.cfg.SaturatedPSI {
			continue
		}
		out = append(out, candidate{
			id: "saturated|" + dev,
			finding: collector.Finding{
				Rule: "saturated", Severity: "warning", Device: dev,
				Evidence: map[string]float64{"queue_depth": d.depth, "psi_some": w.psiSome},
				Sentence: fmt.Sprintf("%s: queue depth %.1f, tasks stalled on I/O %.0f%% of the time",
					dev, d.depth, w.psiSome*100),
			},
		})
	}
	return out
}

func (e *Engine) queueingDominant(w *window) []candidate {
	// per pod and device, all ops together
	type pk struct{ dev, pod string }
	agg := map[pk]*hist.Hist{}
	for k, h := range w.series {
		a := agg[pk{k.dev, k.pod}]
		if a == nil {
			a = &hist.Hist{}
			agg[pk{k.dev, k.pod}] = a
		}
		a.Add(h)
	}
	var out []candidate
	for k, h := range agg {
		if h.Count < e.cfg.MinRequests {
			continue
		}
		q, d := h.MeanQueueUs(), h.MeanDeviceUs()
		if q <= d {
			continue
		}
		out = append(out, candidate{
			id: "queueing-dominant|" + k.dev + "|" + k.pod,
			finding: collector.Finding{
				Rule: "queueing-dominant", Severity: "info", Device: k.dev, Victim: k.pod,
				Evidence: map[string]float64{"mean_queue_us": q, "mean_device_us": d},
				Sentence: fmt.Sprintf("%s on %s: %.1f ms of %.1f ms is queueing",
					k.pod, k.dev, q/1000, (q+d)/1000),
			},
		})
	}
	return out
}

func (e *Engine) ioStall(w *window) []candidate {
	var out []candidate
	mk := func(scope string, full float64) candidate {
		return candidate{
			id: "io-stall|" + scope,
			finding: collector.Finding{
				Rule: "io-stall", Severity: "critical", Victim: scope,
				Evidence: map[string]float64{"psi_full": full},
				Sentence: fmt.Sprintf("%s: all runnable tasks stalled on I/O %.0f%% of the time", scope, full*100),
			},
		}
	}
	if w.psiFull >= e.cfg.StallFull {
		out = append(out, mk("node", w.psiFull))
	}
	for pod, full := range w.podPSIFull {
		if full >= e.cfg.StallFull {
			out = append(out, mk(pod, full))
		}
	}
	return out
}

func (e *Engine) ioErrors(w *window) []candidate {
	var out []candidate
	for k, h := range w.series {
		if h.Errors == 0 {
			continue
		}
		id := "io-errors|" + k.dev + "|" + k.op
		// several pods can error on same device, sum them into one finding
		found := false
		for i := range out {
			if out[i].id == id {
				out[i].finding.Evidence["errors"] += float64(h.Errors)
				n := out[i].finding.Evidence["errors"]
				out[i].finding.Sentence = fmt.Sprintf("%s: %.0f I/O errors (%s)", k.dev, n, k.op)
				found = true
			}
		}
		if found {
			continue
		}
		out = append(out, candidate{
			id: id,
			finding: collector.Finding{
				Rule: "io-errors", Severity: "critical", Device: k.dev,
				Evidence: map[string]float64{"errors": float64(h.Errors)},
				Sentence: fmt.Sprintf("%s: %d I/O errors (%s)", k.dev, h.Errors, k.op),
			},
		})
	}
	return out
}

// fmtUs prints a latency the way people read them
func fmtUs(us float64) string {
	switch {
	case math.IsNaN(us):
		return "-"
	case us >= 1e6:
		return fmt.Sprintf("%.2fs", us/1e6)
	case us >= 1000:
		return fmt.Sprintf("%.1fms", us/1000)
	}
	return fmt.Sprintf("%.0fus", us)
}
