package diskstats

import (
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseFormats(t *testing.T) {
	cases := []struct {
		file  string
		n     int
		first Stat
	}{
		{"testdata/diskstats_14", 4, Stat{Major: 8, Minor: 0, Name: "sda",
			ReadIOs: 145287, ReadMerges: 2817, ReadSectors: 7346652, ReadTicks: 81920,
			WriteIOs: 523874, WriteMerges: 391044, WriteSectors: 24735928, WriteTicks: 1453210,
			InFlight: 0, IOTicks: 489300, TimeInQueue: 1535024}},
		{"testdata/diskstats_18", 3, Stat{Major: 259, Minor: 0, Name: "nvme0n1",
			ReadIOs: 812345, ReadMerges: 12034, ReadSectors: 51234566, ReadTicks: 210345,
			WriteIOs: 1203445, WriteMerges: 803222, WriteSectors: 98234560, WriteTicks: 3401230,
			InFlight: 3, IOTicks: 1023400, TimeInQueue: 3612000,
			DiscardIOs: 1234, DiscardSectors: 2468000, DiscardTicks: 120}},
		{"testdata/diskstats_20", 3, Stat{Major: 254, Minor: 0, Name: "vda",
			ReadIOs: 294, ReadMerges: 1, ReadSectors: 11386, ReadTicks: 64,
			WriteIOs: 1417, WriteMerges: 6784, WriteSectors: 2750032, WriteTicks: 3496,
			IOTicks: 268, TimeInQueue: 3683,
			DiscardIOs: 82, DiscardSectors: 125178856, DiscardTicks: 5,
			FlushIOs: 315, FlushTicks: 117}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			f, err := os.Open(c.file)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			got, err := Parse(f)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != c.n {
				t.Fatalf("got %d devices, want %d", len(got), c.n)
			}
			if got[0] != c.first {
				t.Errorf("first line\n got %+v\nwant %+v", got[0], c.first)
			}
		})
	}
}

func TestParseRejectsUnknownLength(t *testing.T) {
	_, err := Parse(strings.NewReader("8 0 sda 1 2 3\n"))
	if err == nil {
		t.Fatal("expected error for short line")
	}
}

func TestRate(t *testing.T) {
	prev := Stat{Name: "vdb", ReadIOs: 1000, ReadSectors: 8000, ReadTicks: 500,
		WriteIOs: 200, WriteSectors: 4096, WriteTicks: 1000, IOTicks: 100, TimeInQueue: 1500}
	cur := prev
	cur.ReadIOs += 2000      // 1000/s over 2s
	cur.ReadSectors += 16000 // 8000 KiB over 2s
	cur.ReadTicks += 1000    // 0.5 ms each
	cur.WriteIOs += 100
	cur.WriteSectors += 2048
	cur.WriteTicks += 400   // 4 ms each
	cur.IOTicks += 1000     // 50% of 2000 ms
	cur.TimeInQueue += 3000 // 1.5 in flight on avg

	r := Rate(prev, cur, 2*time.Second)
	check := func(name string, got, want float64) {
		t.Helper()
		if math.Abs(got-want) > 1e-9 {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	check("r/s", r.RPS, 1000)
	check("w/s", r.WPS, 50)
	check("rkB/s", r.RKBps, 4000)
	check("wkB/s", r.WKBps, 512)
	check("r_await", r.RAwaitMs, 0.5)
	check("w_await", r.WAwaitMs, 4)
	check("util", r.Util, 0.5)
	check("aqu-sz", r.AquSz, 1.5)
}

func TestRateCounterWentBackwards(t *testing.T) {
	prev := Stat{ReadIOs: 100}
	cur := Stat{ReadIOs: 10}
	if r := Rate(prev, cur, time.Second); r.RPS != 0 {
		t.Errorf("r/s = %v, want 0", r.RPS)
	}
}

func TestFilter(t *testing.T) {
	f, _ := os.Open("testdata/diskstats_14")
	defer f.Close()
	all, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	got := Filter(all, func(n string) bool { return n == "sda1" })
	if len(got) != 1 || got[0].Name != "sda" {
		t.Errorf("filter kept %v", got)
	}

	f2, _ := os.Open("testdata/diskstats_18")
	defer f2.Close()
	all, _ = Parse(f2)
	got = Filter(all, func(n string) bool { return strings.Contains(n, "p1") })
	// loop0 did io so it stays
	if len(got) != 2 {
		t.Errorf("filter kept %d, want 2", len(got))
	}
}
