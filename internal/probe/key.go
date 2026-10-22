// package probe loads the bpf program, attaches it and reads the
// histograms back out.
package probe

import (
	"fmt"

	"github.com/ramyak-sharma/iolens/internal/hist"
)

type Op uint8

// values match enum iolens_op in bpf/iolens.h
const (
	OpRead Op = iota
	OpWrite
	OpFlush
	OpDiscard
	OpOther
)

func (o Op) String() string {
	switch o {
	case OpRead:
		return "read"
	case OpWrite:
		return "write"
	case OpFlush:
		return "flush"
	case OpDiscard:
		return "discard"
	}
	return "other"
}

// Key identifies one histogram
type Key struct {
	Cgroup uint64 // cgroup v2 id, 0 means unattributed
	Dev    uint32 // kernel dev_t, major<<20 | minor
	Op     Op
}

func (k Key) Major() uint32 { return k.Dev >> 20 }
func (k Key) Minor() uint32 { return k.Dev & (1<<20 - 1) }

func (k Key) String() string {
	return fmt.Sprintf("cg=%d dev=%d:%d op=%s", k.Cgroup, k.Major(), k.Minor(), k.Op)
}

// ProgStats is the kernel run time accounting for one program,
// only filled in while bpf stats are enabled
type ProgStats struct {
	RunNs    uint64
	RunCount uint64
}

func (s ProgStats) NsPerEvent() float64 {
	if s.RunCount == 0 {
		return 0
	}
	return float64(s.RunNs) / float64(s.RunCount)
}

// Source is what the collector needs from a probe. lets tests and --no-bpf
// mode swap in something else
type Source interface {
	Read() (map[Key]*hist.Hist, error)
	Delete(keys []Key) error
	Stats() map[string]ProgStats
	InflightEntries() (int, error)
	Close() error
}
