package cgroupmap

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParsePath(t *testing.T) {
	const ctr = "4f1c2b3a4f1c2b3a4f1c2b3a4f1c2b3a4f1c2b3a4f1c2b3a4f1c2b3a4f1c2b3a"
	cases := []struct {
		name, path string
		want       PodRef
		ok         bool
	}{
		{"systemd burstable",
			"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod8a1e7c2d_51b2_4c4e_9f0a_3b7d2e1f6a90.slice/cri-containerd-" + ctr + ".scope",
			PodRef{PodUID: "8a1e7c2d-51b2-4c4e-9f0a-3b7d2e1f6a90", ContainerID: ctr, QoS: "burstable"}, true},
		{"systemd guaranteed",
			"kubepods.slice/kubepods-pod8a1e7c2d_51b2_4c4e_9f0a_3b7d2e1f6a90.slice/cri-containerd-" + ctr + ".scope",
			PodRef{PodUID: "8a1e7c2d-51b2-4c4e-9f0a-3b7d2e1f6a90", ContainerID: ctr, QoS: "guaranteed"}, true},
		{"cgroupfs besteffort",
			"/kubepods/besteffort/pod8a1e7c2d-51b2-4c4e-9f0a-3b7d2e1f6a90/" + ctr,
			PodRef{PodUID: "8a1e7c2d-51b2-4c4e-9f0a-3b7d2e1f6a90", ContainerID: ctr, QoS: "besteffort"}, true},
		{"cgroupfs guaranteed",
			"kubepods/pod8a1e7c2d-51b2-4c4e-9f0a-3b7d2e1f6a90/" + ctr,
			PodRef{PodUID: "8a1e7c2d-51b2-4c4e-9f0a-3b7d2e1f6a90", ContainerID: ctr, QoS: "guaranteed"}, true},
		{"kind nested",
			"system.slice/docker-" + ctr + ".scope/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod8a1e7c2d_51b2_4c4e_9f0a_3b7d2e1f6a90.slice/cri-containerd-" + ctr + ".scope",
			PodRef{PodUID: "8a1e7c2d-51b2-4c4e-9f0a-3b7d2e1f6a90", ContainerID: ctr, QoS: "besteffort"}, true},
		{"pod slice only",
			"kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod8a1e7c2d_51b2_4c4e_9f0a_3b7d2e1f6a90.slice",
			PodRef{PodUID: "8a1e7c2d-51b2-4c4e-9f0a-3b7d2e1f6a90", QoS: "besteffort"}, true},
		{"systemd service", "system.slice/postgresql.service", PodRef{}, false},
		{"root", "/", PodRef{}, false},
		{"docker outside k8s", "system.slice/docker-" + ctr + ".scope", PodRef{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParsePath(c.path)
			if ok != c.ok || got != c.want {
				t.Errorf("got %+v %v, want %+v %v", got, ok, c.want, c.ok)
			}
		})
	}
}

// builds fixture trees from testdata/*.txt (one path per line) and checks
// every leaf resolves through the id cache back to its path
func TestResolverFixtures(t *testing.T) {
	for _, fx := range []string{"systemd.txt", "cgroupfs.txt"} {
		t.Run(fx, func(t *testing.T) {
			root := t.TempDir()
			b, err := os.ReadFile(filepath.Join("testdata", fx))
			if err != nil {
				t.Fatal(err)
			}
			paths := strings.Fields(string(b))
			for _, p := range paths {
				if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			r := NewResolver(root)
			pods := 0
			for _, p := range paths {
				var st syscall.Stat_t
				if err := syscall.Stat(filepath.Join(root, p), &st); err != nil {
					t.Fatal(err)
				}
				got, ok := r.Lookup(st.Ino)
				if !ok || got != p {
					t.Errorf("Lookup(%d) = %q %v, want %q", st.Ino, got, ok, p)
				}
				if _, ok := ParsePath(got); ok {
					pods++
				}
			}
			if pods < 3 {
				t.Errorf("only %d paths parsed as pods", pods)
			}
		})
	}
}

func TestResolverRateLimit(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(1000, 0)
	r := NewResolver(root)
	r.now = func() time.Time { return now }
	r.Rescan(true)

	os.Mkdir(filepath.Join(root, "new"), 0o755)
	var st syscall.Stat_t
	syscall.Stat(filepath.Join(root, "new"), &st)
	if _, ok := r.Lookup(st.Ino); ok {
		t.Error("rescan should be rate limited")
	}
	now = now.Add(2 * time.Second)
	if p, ok := r.Lookup(st.Ino); !ok || p != "new" {
		t.Errorf("after limit got %q %v", p, ok)
	}
}

func TestGone(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(1000, 0)
	r := NewResolver(root)
	r.now = func() time.Time { return now }
	dir := filepath.Join(root, "pod")
	os.Mkdir(dir, 0o755)
	var st syscall.Stat_t
	syscall.Stat(dir, &st)
	r.Rescan(true)

	if g := r.Gone([]uint64{st.Ino}, 5*time.Minute); len(g) != 0 {
		t.Errorf("live cgroup reported gone: %v", g)
	}
	os.Remove(dir)
	now = now.Add(2 * time.Second)
	if g := r.Gone([]uint64{st.Ino}, 5*time.Minute); len(g) != 0 {
		t.Errorf("gone too early: %v", g)
	}
	now = now.Add(5 * time.Minute)
	if g := r.Gone([]uint64{st.Ino}, 5*time.Minute); len(g) != 1 {
		t.Errorf("expected gone after grace, got %v", g)
	}
}

func TestParseIOStat(t *testing.T) {
	in := "254:16 rbytes=1459200 wbytes=314773504 rios=192 wios=353 dbytes=0 dios=0\n" +
		"254:0 rbytes=4096 wbytes=0 rios=1 wios=0 dbytes=0 dios=0 cost.usage=12 cost.wait=x\n"
	got, err := ParseIOStat(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d lines", len(got))
	}
	want := IOStat{Major: 254, Minor: 16, RBytes: 1459200, WBytes: 314773504, RIOs: 192, WIOs: 353}
	if got[0] != want {
		t.Errorf("got %+v", got[0])
	}
}
