package hist

import (
	"math"
	"testing"
)

// same table is in the comment above bucket_index() in the C file
func TestIndexTable(t *testing.T) {
	cases := []struct {
		us   uint64
		want int
	}{
		{0, 0}, {1, 1}, {2, 2}, {3, 3},
		{4, 4}, {5, 5}, {6, 6}, {7, 7},
		{8, 8}, {9, 8}, {10, 9}, {15, 11},
		{16, 12}, {17, 12}, {31, 15}, {32, 16},
		{1000, 35}, {1023, 35}, {1024, 36}, {1025, 36},
		{1 << 25, 96}, {(1 << 26) - 1, 99}, {1 << 26, 99}, {1 << 40, 99},
	}
	for _, c := range cases {
		if got := Index(c.us); got != c.want {
			t.Errorf("Index(%d) = %d, want %d", c.us, got, c.want)
		}
	}
}

// every power of two plus and minus one lands in a slot whose bounds hold it
func TestIndexBounds(t *testing.T) {
	check := func(v uint64) {
		i := Index(v)
		if i < 0 || i >= NumSlots {
			t.Fatalf("Index(%d) = %d out of range", v, i)
		}
		if v <= MaxUs && (float64(v) < Lower(i) || float64(v) >= Upper(i)) {
			t.Errorf("v=%d slot %d [%v,%v)", v, i, Lower(i), Upper(i))
		}
	}
	for k := 0; k <= MaxOrder+1; k++ {
		p := uint64(1) << uint(k)
		check(p - 1)
		check(p)
		check(p + 1)
	}
	for v := uint64(0); v < 5000; v++ {
		check(v)
	}
}

func TestSlotsContiguous(t *testing.T) {
	for i := 1; i < NumSlots; i++ {
		if Lower(i) != Upper(i-1) {
			t.Errorf("gap between slot %d and %d", i-1, i)
		}
	}
	if NumSlots != 100 {
		t.Errorf("NumSlots = %d, the C side assumes 100", NumSlots)
	}
}

func TestWorstCaseError(t *testing.T) {
	for i := Sub; i < NumSlots; i++ {
		if e := (Upper(i) - Lower(i)) / Lower(i); e > 0.25+1e-12 {
			t.Errorf("slot %d relative width %v", i, e)
		}
	}
}

func fill(us uint64, n uint64) *[NumSlots]uint64 {
	var s [NumSlots]uint64
	s[Index(us)] = n
	return &s
}

func TestQuantileSingleBucket(t *testing.T) {
	// fixed 5ms latency, like null_blk with completion_nsec=5000000
	s := fill(5000, 1000)
	for _, q := range []float64{0.5, 0.99} {
		got, ok := Quantile(s, q)
		if !ok {
			t.Fatalf("q=%v not ok", q)
		}
		if rel := math.Abs(got-5000) / 5000; rel > 0.25 {
			t.Errorf("q=%v got %v, %.0f%% off", q, got, rel*100)
		}
	}
}

func TestQuantileKnown(t *testing.T) {
	// 99 fast requests at 2us and one slow at 3us. p50 is in the 2 slot
	var s [NumSlots]uint64
	s[2] = 990
	s[3] = 10
	p50, _ := Quantile(&s, 0.5)
	if p50 < 2 || p50 >= 3 {
		t.Errorf("p50 = %v", p50)
	}
	// p99.9 target is 999, which is 9/10 into slot 3
	p999, ok := Quantile(&s, 0.999)
	if !ok || math.Abs(p999-3.9) > 1e-9 {
		t.Errorf("p99.9 = %v ok=%v", p999, ok)
	}
}

func TestQuantileMinCount(t *testing.T) {
	s := fill(100, 50)
	if _, ok := Quantile(s, 0.5); !ok {
		t.Error("50 samples should be enough for p50")
	}
	if _, ok := Quantile(s, 0.99); ok {
		t.Error("50 samples should not be enough for p99")
	}
	var empty [NumSlots]uint64
	if v, ok := Quantile(&empty, 0.5); ok || !math.IsNaN(v) {
		t.Error("empty histogram should be missing")
	}
}

func TestSub(t *testing.T) {
	a := Hist{Count: 10, Bytes: 4096}
	a.Device[5] = 10
	b := a
	b.Count = 15
	b.Device[5] = 12
	b.Device[6] = 3
	b.Bytes = 8192
	d := b.Sub(&a)
	if d.Count != 5 || d.Device[5] != 2 || d.Device[6] != 3 || d.Bytes != 4096 {
		t.Errorf("delta = %+v", d)
	}
	// key recreated, count went down: whole thing is the window
	c := Hist{Count: 2}
	if d := c.Sub(&b); d.Count != 2 {
		t.Errorf("reset delta count = %d", d.Count)
	}
}

func TestCumulative(t *testing.T) {
	var s [NumSlots]uint64
	s[Index(3)] = 1    // under 4us
	s[Index(5)] = 2    // under 8us
	s[Index(1500)] = 4 // under 2048us
	c := Cumulative(&s)
	b := OctaveBounds()
	if len(b) != MaxOrder+1 {
		t.Fatalf("bounds len %d", len(b))
	}
	want := map[float64]uint64{1e-6: 0, 2e-6: 0, 4e-6: 1, 8e-6: 3, 1024e-6: 3, 2048e-6: 7}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("le=%v got %d want %d", k, c[k], v)
		}
	}
}
