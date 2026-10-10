package psi

import (
	"math"
	"strings"
	"testing"
	"time"
)

const sample = `some avg10=1.50 avg60=0.75 avg300=0.20 total=1234567
full avg10=0.30 avg60=0.10 avg300=0.02 total=345678
`

func TestParse(t *testing.T) {
	p, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if p.Some.Avg10 != 1.5 || p.Some.Total != 1234567 {
		t.Errorf("some = %+v", p.Some)
	}
	if !p.HasFull || p.Full.Avg60 != 0.1 || p.Full.Total != 345678 {
		t.Errorf("full = %+v", p.Full)
	}
}

func TestParseSomeOnly(t *testing.T) {
	p, err := Parse(strings.NewReader("some avg10=0.00 avg60=0.00 avg300=0.00 total=10\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.HasFull {
		t.Error("HasFull should be false")
	}
}

func TestParseBad(t *testing.T) {
	for _, in := range []string{"", "weird avg10=1\n", "some avg10\n", "some total=x\n"} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestBetween(t *testing.T) {
	prev := Pressure{Some: Line{Total: 1_000_000}, Full: Line{Total: 500_000}}
	cur := Pressure{Some: Line{Total: 1_250_000}, Full: Line{Total: 550_000}}
	s := Between(prev, cur, time.Second)
	if math.Abs(s.Some-0.25) > 1e-9 || math.Abs(s.Full-0.05) > 1e-9 {
		t.Errorf("share = %+v", s)
	}
}
