// Package diskstats reads /proc/diskstats and turns two samples into
// iostat -x style rates.
package diskstats

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Stat is one line of /proc/diskstats. all counters are cumulative since boot.
// see Documentation/admin-guide/iostats.rst for what each one is
type Stat struct {
	Major, Minor uint32
	Name         string

	ReadIOs, ReadMerges, ReadSectors, ReadTicks     uint64
	WriteIOs, WriteMerges, WriteSectors, WriteTicks uint64
	InFlight, IOTicks, TimeInQueue                  uint64

	// 4.18+
	DiscardIOs, DiscardMerges, DiscardSectors, DiscardTicks uint64
	// 5.5+
	FlushIOs, FlushTicks uint64
}

// Parse reads diskstats format. line length depends on kernel version:
// 14 fields total on old kernels, 18 once discard stats were added (4.18)
// and 20 with flush stats (5.5). anything else is rejected so we notice
// if a new kernel adds more
func Parse(r io.Reader) ([]Stat, error) {
	var out []Stat
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch len(f) {
		case 14, 18, 20:
		default:
			return nil, fmt.Errorf("diskstats line %d: unexpected %d fields", lineNo, len(f))
		}
		var s Stat
		maj, err := strconv.ParseUint(f[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("diskstats line %d: major: %w", lineNo, err)
		}
		min, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("diskstats line %d: minor: %w", lineNo, err)
		}
		s.Major, s.Minor, s.Name = uint32(maj), uint32(min), f[2]

		nums := make([]uint64, len(f)-3)
		for i, v := range f[3:] {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("diskstats line %d field %d: %w", lineNo, i+4, err)
			}
			nums[i] = n
		}
		dst := []*uint64{
			&s.ReadIOs, &s.ReadMerges, &s.ReadSectors, &s.ReadTicks,
			&s.WriteIOs, &s.WriteMerges, &s.WriteSectors, &s.WriteTicks,
			&s.InFlight, &s.IOTicks, &s.TimeInQueue,
			&s.DiscardIOs, &s.DiscardMerges, &s.DiscardSectors, &s.DiscardTicks,
			&s.FlushIOs, &s.FlushTicks,
		}
		for i, n := range nums {
			*dst[i] = n
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// ReadFile parses a diskstats file, normally /proc/diskstats
func ReadFile(path string) ([]Stat, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Rates are the derived per second values for one device over one interval.
// names follow iostat -x so they can be compared column by column
type Rates struct {
	Name  string `json:"device"`
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`

	// completed ios per second
	RPS float64 `json:"r_s"`
	WPS float64 `json:"w_s"`
	DPS float64 `json:"d_s"`
	FPS float64 `json:"f_s"`

	RKBps float64 `json:"rkB_s"`
	WKBps float64 `json:"wkB_s"`

	// average, includes queue time
	RAwaitMs float64 `json:"r_await"`
	WAwaitMs float64 `json:"w_await"`

	Util  float64 `json:"util"`   // 0..1, share of time with something in flight
	AquSz float64 `json:"aqu_sz"` // avg requests in flight
}

// diskstats sectors are always 512 bytes no matter what the device uses
const sectorBytes = 512

// Rate computes rates between two samples of the same device. a counter that
// went backwards (device removed and re added) gives zero instead of garbage
func Rate(prev, cur Stat, dt time.Duration) Rates {
	r := Rates{Name: cur.Name, Major: cur.Major, Minor: cur.Minor}
	sec := dt.Seconds()
	if sec <= 0 {
		return r
	}
	ms := sec * 1000

	rios := delta(prev.ReadIOs, cur.ReadIOs)
	wios := delta(prev.WriteIOs, cur.WriteIOs)
	r.RPS = float64(rios) / sec
	r.WPS = float64(wios) / sec
	r.DPS = float64(delta(prev.DiscardIOs, cur.DiscardIOs)) / sec
	r.FPS = float64(delta(prev.FlushIOs, cur.FlushIOs)) / sec
	r.RKBps = float64(delta(prev.ReadSectors, cur.ReadSectors)) * sectorBytes / 1024 / sec
	r.WKBps = float64(delta(prev.WriteSectors, cur.WriteSectors)) * sectorBytes / 1024 / sec
	if rios > 0 {
		r.RAwaitMs = float64(delta(prev.ReadTicks, cur.ReadTicks)) / float64(rios)
	}
	if wios > 0 {
		r.WAwaitMs = float64(delta(prev.WriteTicks, cur.WriteTicks)) / float64(wios)
	}
	r.Util = float64(delta(prev.IOTicks, cur.IOTicks)) / ms
	if r.Util > 1 {
		// io_ticks is sampled in jiffies on some kernels, can overshoot a bit
		r.Util = 1
	}
	r.AquSz = float64(delta(prev.TimeInQueue, cur.TimeInQueue)) / ms
	return r
}

func delta(a, b uint64) uint64 {
	if b < a {
		return 0
	}
	return b - a
}

// Filter drops devices iolens doesnt care about by default: ram disks,
// devices that never did any io (unused loop/nbd), and partitions since
// we report whole disks.
// isPartition is injected so tests dont need sysfs
func Filter(in []Stat, isPartition func(name string) bool) []Stat {
	out := in[:0:0]
	for _, s := range in {
		if strings.HasPrefix(s.Name, "ram") || strings.HasPrefix(s.Name, "zram") {
			continue
		}
		if s.ReadIOs == 0 && s.WriteIOs == 0 && s.DiscardIOs == 0 {
			continue
		}
		if isPartition != nil && isPartition(s.Name) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// SysfsIsPartition checks /sys/class/block/<name>/partition which only
// exists for partitions
func SysfsIsPartition(name string) bool {
	_, err := os.Stat("/sys/class/block/" + name + "/partition")
	return err == nil
}
