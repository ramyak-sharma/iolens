// Package collector ticks once per interval, reads everything (bpf maps,
// diskstats, psi, io.stat) and publishes one immutable Snapshot. readers
// (prometheus, tui, rules) only ever look at the latest snapshot and never
// touch the kernel themselves.
package collector

import (
	"fmt"
	"time"

	"github.com/ramyak-sharma/iolens/internal/cgroupmap"
	"github.com/ramyak-sharma/iolens/internal/diskstats"
	"github.com/ramyak-sharma/iolens/internal/hist"
	"github.com/ramyak-sharma/iolens/internal/probe"
	"github.com/ramyak-sharma/iolens/internal/psi"
)

// Labels say who a cgroup belongs to. inside k8s namespace/pod/container
// are set, outside it only Cgroup (the path) is
type Labels struct {
	Namespace string
	Pod       string
	Container string
	Cgroup    string
}

const Unattributed = "unattributed"

// Display is the short name used in the tui and finding sentences
func (l Labels) Display() string {
	switch {
	case l.Pod != "" && l.Container != "":
		return l.Namespace + "/" + l.Pod + "/" + l.Container
	case l.Pod != "":
		return l.Namespace + "/" + l.Pod
	case l.Cgroup != "":
		return l.Cgroup
	}
	return Unattributed
}

// PodName is namespace/pod, or Display() when not a pod. rules work at
// pod level since thats what people get paged about
func (l Labels) PodName() string {
	if l.Pod != "" {
		return l.Namespace + "/" + l.Pod
	}
	return l.Display()
}

// Series is one (cgroup, device, op) histogram
type Series struct {
	Key    probe.Key
	Device string
	Labels Labels

	Cum hist.Hist // cumulative since the kernel created the key
	Win hist.Hist // just this interval

	// requests in roughly the last 5 minutes, used by the cardinality guard
	Recent uint64
}

// CgroupIO is the kernels own per cgroup accounting, independent of bpf
type CgroupIO struct {
	ID       uint64
	Labels   Labels
	IOStat   []cgroupmap.IOStat // cumulative
	Pressure psi.Pressure       // cumulative
	Share    psi.Share          // this interval
	HasPSI   bool
}

type Finding struct {
	Rule     string             `json:"rule"`
	Severity string             `json:"severity"`
	Device   string             `json:"device,omitempty"`
	Victim   string             `json:"victim,omitempty"`
	Culprit  string             `json:"culprit,omitempty"`
	Since    time.Time          `json:"since"`
	Evidence map[string]float64 `json:"evidence"`
	Sentence string             `json:"sentence"`
}

type AgentStats struct {
	BPF            map[string]probe.ProgStats
	Inflight       int
	CollectSeconds float64
}

type Snapshot struct {
	Time     time.Time
	Interval time.Duration // real elapsed time since previous snapshot
	Seq      uint64

	Devices    []diskstats.Rates
	NodePSI    psi.Share
	NodePSICum psi.Pressure

	BPF     bool // false in --no-bpf mode
	Series  []*Series
	Cgroups []*CgroupIO

	Findings []Finding
	Warming  bool // rules still building baselines

	// dev_t (major<<20 | minor) -> name, for everything seen this tick
	DevNames map[uint32]string

	Agent AgentStats
}

// DevName returns the name for major:minor, or "maj:min" if unknown
func (s *Snapshot) DevName(major, minor uint32) string {
	if n, ok := s.DevNames[major<<20|minor]; ok {
		return n
	}
	return fmt.Sprintf("%d:%d", major, minor)
}

// DeviceRates finds a device by name
func (s *Snapshot) DeviceRates(name string) (diskstats.Rates, bool) {
	for _, d := range s.Devices {
		if d.Name == name {
			return d, true
		}
	}
	return diskstats.Rates{}, false
}
