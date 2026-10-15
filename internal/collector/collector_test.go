package collector

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ramyak-sharma/iolens/internal/hist"
	"github.com/ramyak-sharma/iolens/internal/probe"
)

type fakeSource struct {
	h map[probe.Key]*hist.Hist
}

func (f *fakeSource) Read() (map[probe.Key]*hist.Hist, error) {
	out := map[probe.Key]*hist.Hist{}
	for k, v := range f.h {
		c := *v
		out[k] = &c
	}
	return out, nil
}
func (f *fakeSource) Delete([]probe.Key) error          { return nil }
func (f *fakeSource) Stats() map[string]probe.ProgStats { return nil }
func (f *fakeSource) InflightEntries() (int, error)     { return 0, nil }
func (f *fakeSource) Close() error                      { return nil }

func fakeProc(t *testing.T, reads int) string {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "pressure"), 0o755)
	line := " 254      16 vdb " + itoa(reads) + " 0 " + itoa(reads*8) + " 10 0 0 0 0 0 5 10 0 0 0 0 0 0\n"
	os.WriteFile(filepath.Join(dir, "diskstats"), []byte(line), 0o644)
	os.WriteFile(filepath.Join(dir, "pressure/io"),
		[]byte("some avg10=0 avg60=0 avg300=0 total="+itoa(reads*100)+"\nfull avg10=0 avg60=0 avg300=0 total=0\n"), 0o644)
	return dir
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestCollectDeltas(t *testing.T) {
	key := probe.Key{Cgroup: 0, Dev: 254<<20 | 16, Op: probe.OpRead}
	h := &hist.Hist{Count: 10}
	h.Device[hist.Index(200)] = 10
	src := &fakeSource{h: map[probe.Key]*hist.Hist{key: h}}

	proc := fakeProc(t, 100)
	c := New(Config{Source: src, ProcRoot: proc, SysRoot: t.TempDir()})
	if _, err := c.Collect(); err != nil {
		t.Fatal(err)
	}

	h.Count = 25
	h.Device[hist.Index(200)] = 25
	os.WriteFile(filepath.Join(proc, "diskstats"),
		[]byte(" 254      16 vdb 300 0 2400 10 0 0 0 0 0 5 10 0 0 0 0 0 0\n"), 0o644)
	c.lastTime = c.lastTime.Add(-time.Second) // pretend a second went by
	s, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Series) != 1 || s.Series[0].Win.Count != 15 || s.Series[0].Cum.Count != 25 {
		t.Fatalf("series = %+v", s.Series)
	}
	if s.Series[0].Device != "254:16" {
		t.Errorf("device name fallback = %q", s.Series[0].Device)
	}
	if s.Series[0].Labels.Display() != Unattributed {
		t.Errorf("label = %q", s.Series[0].Labels.Display())
	}
	if len(s.Devices) != 1 || s.Devices[0].RPS < 150 || s.Devices[0].RPS > 250 {
		t.Errorf("devices = %+v", s.Devices)
	}
}

func TestSubscribeDropsStale(t *testing.T) {
	c := New(Config{})
	ch := c.Subscribe()
	c.publish(&Snapshot{Seq: 1})
	c.publish(&Snapshot{Seq: 2})
	if s := <-ch; s.Seq != 2 {
		t.Errorf("got seq %d, want newest", s.Seq)
	}
	if c.Latest().Seq != 2 {
		t.Error("latest not updated")
	}
}

func TestRecentRing(t *testing.T) {
	var r recentRing
	t0 := time.Unix(0, 0)
	for i := 0; i <= 600; i++ {
		got := r.observe(t0.Add(time.Duration(i)*time.Second), uint64(i*10))
		if i == 600 && (got < 2500 || got > 3100) {
			// about 5 minutes worth of 10/s
			t.Errorf("recent = %d", got)
		}
	}
}

func TestLabelsDisplay(t *testing.T) {
	cases := map[string]Labels{
		"default/db/fio":                {Namespace: "default", Pod: "db", Container: "fio"},
		"default/db":                    {Namespace: "default", Pod: "db"},
		"system.slice/postgres.service": {Cgroup: "system.slice/postgres.service"},
		Unattributed:                    {},
	}
	for want, l := range cases {
		if got := l.Display(); got != want {
			t.Errorf("Display() = %q, want %q", got, want)
		}
	}
}
