package rules

import (
	"math"
	"time"
)

// ewma with a half life instead of a fixed alpha, so it behaves the same
// whatever the tick interval is
type ewma struct {
	value float64
	first time.Time
	last  time.Time
	set   bool
}

func (e *ewma) update(now time.Time, v float64, halfLife time.Duration) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	if !e.set {
		e.value, e.first, e.last, e.set = v, now, now, true
		return
	}
	dt := now.Sub(e.last)
	if dt <= 0 {
		return
	}
	alpha := 1 - math.Exp2(-dt.Seconds()/halfLife.Seconds())
	e.value += alpha * (v - e.value)
	e.last = now
}

// ready once it has seen warmUp worth of data
func (e *ewma) ready(now time.Time, warmUp time.Duration) bool {
	return e != nil && e.set && now.Sub(e.first) >= warmUp
}

type baselines struct {
	m        map[string]*ewma
	halfLife time.Duration
}

func newBaselines(h time.Duration) *baselines {
	return &baselines{m: map[string]*ewma{}, halfLife: h}
}

func (b *baselines) get(key string) *ewma { return b.m[key] }

func (b *baselines) update(key string, now time.Time, v float64) {
	e := b.m[key]
	if e == nil {
		e = &ewma{}
		b.m[key] = e
	}
	e.update(now, v, b.halfLife)
}

// drop baselines not touched in a while, pods come and go
func (b *baselines) gc(now time.Time, maxAge time.Duration) {
	for k, e := range b.m {
		if now.Sub(e.last) > maxAge {
			delete(b.m, k)
		}
	}
}
