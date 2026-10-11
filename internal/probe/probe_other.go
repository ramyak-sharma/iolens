//go:build !linux

package probe

import "errors"

// Probe only exists on linux. this stub keeps the rest building on a mac
type Probe struct{ Source }

func Load() (*Probe, error) {
	return nil, errors.New("ebpf probe needs linux, use --no-bpf")
}
