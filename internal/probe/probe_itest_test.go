//go:build itest && linux

package probe

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ramyak-sharma/iolens/internal/hist"
)

// needs root. makes a loop device from a temp file, reads it with O_DIRECT
// and checks histogram shows up under our own cgroup
func TestLoadAttachRead(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	img := filepath.Join(t.TempDir(), "disk.img")
	run(t, "dd", "if=/dev/zero", "of="+img, "bs=1M", "count=64", "status=none")
	dev := strings.TrimSpace(run(t, "losetup", "--direct-io=on", "-f", "--show", img))
	defer exec.Command("losetup", "-d", dev).Run()

	var st syscall.Stat_t
	if err := syscall.Stat(dev, &st); err != nil {
		t.Fatal(err)
	}
	maj, min := uint32(st.Rdev>>8&0xfff), uint32(st.Rdev&0xff|(st.Rdev>>12)&0xfff00)
	devt := maj<<20 | min

	before, err := p.Read()
	if err != nil {
		t.Fatal(err)
	}
	run(t, "dd", "if="+dev, "of=/dev/null", "bs=4k", "count=2000", "iflag=direct", "status=none")
	time.Sleep(100 * time.Millisecond)
	after, err := p.Read()
	if err != nil {
		t.Fatal(err)
	}

	myCg := selfCgroupID(t)
	var reads uint64
	var mine bool
	for k, h := range after {
		if k.Dev != devt || k.Op != OpRead {
			continue
		}
		d := h.Sub(before[k])
		reads += d.Count
		if k.Cgroup == myCg && d.Count > 0 {
			mine = true
		}
		t.Logf("%v count=%d p50=%.1fus", k, d.Count, hist.QuantileAny(&d.Device, 0.5))
	}
	if reads < 2000 {
		t.Errorf("saw %d reads on %s, want >= 2000", reads, dev)
	}
	if !mine {
		t.Errorf("no reads charged to our cgroup id %d", myCg)
	}

	n, err := p.InflightEntries()
	if err != nil {
		t.Error(err)
	}
	t.Logf("inflight entries: %d", n)
	for name, s := range p.Stats() {
		t.Logf("%s: %d events, %.0f ns/event", name, s.RunCount, s.NsPerEvent())
	}
}

func selfCgroupID(t *testing.T) uint64 {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	// cgroup v2 line is 0::/path
	path := strings.TrimPrefix(strings.TrimSpace(string(b)), "0::")
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join("/sys/fs/cgroup", path), &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}
