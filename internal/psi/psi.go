// Package psi parses pressure stall information files, the node wide
// /proc/pressure/io and the per cgroup io.pressure. both use same format:
//
//	some avg10=0.00 avg60=0.00 avg300=0.00 total=0
//	full avg10=0.00 avg60=0.00 avg300=0.00 total=0
package psi

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type Line struct {
	Avg10, Avg60, Avg300 float64 // percent, as kernel prints them
	Total                uint64  // cumulative stall time in microseconds
}

type Pressure struct {
	Some, Full Line
	// old kernels dont print a full line for io in the root, track it
	HasFull bool
}

func Parse(r io.Reader) (Pressure, error) {
	var p Pressure
	sc := bufio.NewScanner(r)
	seenSome := false
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		var dst *Line
		switch f[0] {
		case "some":
			dst = &p.Some
			seenSome = true
		case "full":
			dst = &p.Full
			p.HasFull = true
		default:
			return p, fmt.Errorf("psi: unknown line kind %q", f[0])
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return p, fmt.Errorf("psi: bad field %q", kv)
			}
			var err error
			switch k {
			case "avg10":
				dst.Avg10, err = strconv.ParseFloat(v, 64)
			case "avg60":
				dst.Avg60, err = strconv.ParseFloat(v, 64)
			case "avg300":
				dst.Avg300, err = strconv.ParseFloat(v, 64)
			case "total":
				dst.Total, err = strconv.ParseUint(v, 10, 64)
			}
			if err != nil {
				return p, fmt.Errorf("psi: %s: %w", k, err)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return p, err
	}
	if !seenSome {
		return p, fmt.Errorf("psi: no some line")
	}
	return p, nil
}

func ReadFile(path string) (Pressure, error) {
	f, err := os.Open(path)
	if err != nil {
		return Pressure{}, err
	}
	defer f.Close()
	return Parse(f)
}

// Share is the fraction (0..1) of wall time stalled over one interval.
// we compute it from the totals ourselves instead of using avg10 so the
// window lines up exactly with the rest of the snapshot
type Share struct {
	Some, Full float64
}

func Between(prev, cur Pressure, dt time.Duration) Share {
	us := float64(dt.Microseconds())
	if us <= 0 {
		return Share{}
	}
	s := Share{
		Some: frac(prev.Some.Total, cur.Some.Total, us),
		Full: frac(prev.Full.Total, cur.Full.Total, us),
	}
	return s
}

func frac(a, b uint64, us float64) float64 {
	if b < a {
		return 0
	}
	f := float64(b-a) / us
	if f > 1 {
		f = 1
	}
	return f
}
