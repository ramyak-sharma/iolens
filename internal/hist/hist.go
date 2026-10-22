// package hist is the user space side of the kernel histograms. the bucket
// function here must match bucket_index() in bpf/iolens.bpf.c exactly,
// the table test keeps them honest.
//
// buckets are log-linear over microseconds: values 0..3 get their own slot,
// after that each power of two is split in 4 equal parts. worst case error
// of a bucket is its width over its lower bound, which is 25%.
package hist

import "math"

const (
	SubBits  = 2
	Sub      = 1 << SubBits // sub buckets per octave
	MaxOrder = 25           // highest power of two we keep, 2^25 us is ~33s
	NumSlots = (MaxOrder-1)*Sub + Sub
	// anything at or above this goes in the last slot
	MaxUs = (1 << (MaxOrder + 1)) - 1
)

// Index returns the slot for a latency in microseconds
func Index(us uint64) int {
	if us > MaxUs {
		us = MaxUs
	}
	if us < Sub*1 {
		return int(us)
	}
	// position of highest set bit, same bounded walk as the C version
	order := 0
	for i := MaxOrder; i > 0; i-- {
		if us>>uint(i) != 0 {
			order = i
			break
		}
	}
	sub := (us >> uint(order-SubBits)) & (Sub - 1)
	return (order-1)*Sub + int(sub)
}

// Lower is the inclusive lower bound of slot i in microseconds
func Lower(i int) float64 {
	if i < Sub {
		return float64(i)
	}
	order := i/Sub + 1
	sub := i % Sub
	return float64(uint64(1)<<uint(order) + uint64(sub)<<uint(order-SubBits))
}

// Upper is the exclusive upper bound of slot i in microseconds
func Upper(i int) float64 {
	if i < Sub {
		return float64(i + 1)
	}
	order := i/Sub + 1
	return Lower(i) + float64(uint64(1)<<uint(order-SubBits))
}

// Hist mirrors struct hist in the bpf program
type Hist struct {
	Device [NumSlots]uint64 // complete - issue
	Total  [NumSlots]uint64 // complete - insert (or issue if never inserted)

	Count    uint64
	Bytes    uint64
	Errors   uint64
	QueueNs  uint64 // sums, for the means
	DeviceNs uint64
	TotalNs  uint64
}

// Sub returns h - prev. kernel counters only go up, so if anything went down
// the key was deleted and recreated in between and h is the whole window
func (h *Hist) Sub(prev *Hist) Hist {
	if prev == nil || h.Count < prev.Count {
		return *h
	}
	var d Hist
	for i := 0; i < NumSlots; i++ {
		if h.Device[i] < prev.Device[i] || h.Total[i] < prev.Total[i] {
			return *h
		}
		d.Device[i] = h.Device[i] - prev.Device[i]
		d.Total[i] = h.Total[i] - prev.Total[i]
	}
	d.Count = h.Count - prev.Count
	d.Bytes = sat(h.Bytes, prev.Bytes)
	d.Errors = sat(h.Errors, prev.Errors)
	d.QueueNs = sat(h.QueueNs, prev.QueueNs)
	d.DeviceNs = sat(h.DeviceNs, prev.DeviceNs)
	d.TotalNs = sat(h.TotalNs, prev.TotalNs)
	return d
}

func sat(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// Add folds o into h
func (h *Hist) Add(o *Hist) {
	for i := 0; i < NumSlots; i++ {
		h.Device[i] += o.Device[i]
		h.Total[i] += o.Total[i]
	}
	h.Count += o.Count
	h.Bytes += o.Bytes
	h.Errors += o.Errors
	h.QueueNs += o.QueueNs
	h.DeviceNs += o.DeviceNs
	h.TotalNs += o.TotalNs
}

// MinCount is how many requests a window needs before percentile q means
// anything. below it we report missing, not a number that looks real
func MinCount(q float64) uint64 {
	switch {
	case q > 0.99:
		return 1000
	case q > 0.5:
		return 100
	default:
		return 20
	}
}

// Quantile returns the q-th quantile in microseconds, linearly interpolated
// inside the bucket it lands in. ok is false when there arent enough samples
func Quantile(slots *[NumSlots]uint64, q float64) (us float64, ok bool) {
	var n uint64
	for _, c := range slots {
		n += c
	}
	if n == 0 || n < MinCount(q) {
		return math.NaN(), false
	}
	return quantile(slots, n, q), true
}

// QuantileAny is Quantile without the minimum sample check, for tests
// and for the tui where a rough number on a quiet device is fine
func QuantileAny(slots *[NumSlots]uint64, q float64) float64 {
	var n uint64
	for _, c := range slots {
		n += c
	}
	if n == 0 {
		return math.NaN()
	}
	return quantile(slots, n, q)
}

func quantile(slots *[NumSlots]uint64, n uint64, q float64) float64 {
	target := q * float64(n)
	var cum float64
	for i, c := range slots {
		if c == 0 {
			continue
		}
		fc := float64(c)
		if cum+fc >= target {
			frac := (target - cum) / fc
			lo, hi := Lower(i), Upper(i)
			return lo + frac*(hi-lo)
		}
		cum += fc
	}
	// rounding, return top of the last used bucket
	for i := NumSlots - 1; i >= 0; i-- {
		if slots[i] > 0 {
			return Upper(i)
		}
	}
	return math.NaN()
}

// mean helpers, in microseconds. zero when the window is empty
func (h *Hist) MeanQueueUs() float64  { return mean(h.QueueNs, h.Count) }
func (h *Hist) MeanDeviceUs() float64 { return mean(h.DeviceNs, h.Count) }
func (h *Hist) MeanTotalUs() float64  { return mean(h.TotalNs, h.Count) }

func mean(ns, n uint64) float64 {
	if n == 0 {
		return 0
	}
	return float64(ns) / float64(n) / 1000
}

// OctaveBounds are the prometheus bucket upper bounds in seconds: 1us,
// 2us, 4us ... 2^MaxOrder us. every internal slot ends on or before one of
// these so the exported buckets are exact sums with no rounding
func OctaveBounds() []float64 {
	b := make([]float64, 0, MaxOrder+1)
	for k := 0; k <= MaxOrder; k++ {
		b = append(b, float64(uint64(1)<<uint(k))/1e6)
	}
	return b
}

// Cumulative turns slots into prometheus style cumulative bucket counts
// keyed by OctaveBounds. the last slot holds everything >= 2^25us which only
// shows up in +Inf, same as the overflow would anyway
func Cumulative(slots *[NumSlots]uint64) map[float64]uint64 {
	out := make(map[float64]uint64, MaxOrder+1)
	var cum uint64
	i := 0
	for k := 0; k <= MaxOrder; k++ {
		limit := float64(uint64(1) << uint(k))
		for i < NumSlots && Upper(i) <= limit {
			cum += slots[i]
			i++
		}
		out[float64(uint64(1)<<uint(k))/1e6] = cum
	}
	return out
}
