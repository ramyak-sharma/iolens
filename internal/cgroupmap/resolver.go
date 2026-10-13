// Package cgroupmap turns cgroup v2 ids from the kernel back into paths and
// pods, and reads the per cgroup io.stat and io.pressure files.
package cgroupmap

import (
	"io/fs"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Resolver maps cgroup ids to paths. a cgroup v2 id is just the inode
// number of its directory under /sys/fs/cgroup, so we walk the tree and
// stat everything. rebuilt lazily when an unknown id shows up
type Resolver struct {
	root     string
	minEvery time.Duration
	now      func() time.Time

	mu       sync.RWMutex
	byID     map[uint64]string
	lastScan time.Time
	// first time each id was seen missing, for cleanup
	missing map[uint64]time.Time
}

func NewResolver(root string) *Resolver {
	return &Resolver{
		root:     root,
		minEvery: time.Second,
		now:      time.Now,
		byID:     map[uint64]string{},
		missing:  map[uint64]time.Time{},
	}
}

// Lookup returns path relative to the cgroup root, like
// kubepods.slice/kubepods-burstable.slice/... ok is false if id is unknown
// even after a rescan
func (r *Resolver) Lookup(id uint64) (string, bool) {
	if id == 0 {
		return "", false
	}
	r.mu.RLock()
	p, ok := r.byID[id]
	r.mu.RUnlock()
	if ok {
		return p, true
	}
	r.Rescan(false)
	r.mu.RLock()
	p, ok = r.byID[id]
	r.mu.RUnlock()
	return p, ok
}

// Rescan walks the tree again. rate limited to once per minEvery unless
// force is set, so a burst of new pods doesnt cause a rescan storm
func (r *Resolver) Rescan(force bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if !force && now.Sub(r.lastScan) < r.minEvery {
		return nil
	}
	r.lastScan = now

	ids := map[uint64]string{}
	err := filepath.WalkDir(r.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// cgroups come and go while we walk, ignore those
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		var st syscall.Stat_t
		if err := syscall.Stat(path, &st); err != nil {
			return nil
		}
		rel, _ := filepath.Rel(r.root, path)
		if rel == "." {
			rel = "/"
		}
		ids[st.Ino] = rel
		return nil
	})
	r.byID = ids
	return err
}

// Path returns the absolute directory of a relative cgroup path
func (r *Resolver) Path(rel string) string {
	return filepath.Join(r.root, rel)
}

// Gone reports ids that have been missing from the tree for at least
// grace. the collector uses it to delete hists keys of dead pods
func (r *Resolver) Gone(ids []uint64, grace time.Duration) []uint64 {
	r.Rescan(false)
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var out []uint64
	seen := map[uint64]bool{}
	for _, id := range ids {
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		if _, ok := r.byID[id]; ok {
			delete(r.missing, id)
			continue
		}
		first, ok := r.missing[id]
		if !ok {
			r.missing[id] = now
			continue
		}
		if now.Sub(first) >= grace {
			out = append(out, id)
			delete(r.missing, id)
		}
	}
	return out
}
