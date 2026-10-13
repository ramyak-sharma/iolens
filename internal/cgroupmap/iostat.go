package cgroupmap

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// IOStat is one device line from a cgroups io.stat:
//
//	254:16 rbytes=1459200 wbytes=314773504 rios=192 wios=353 dbytes=0 dios=0
type IOStat struct {
	Major, Minor   uint32
	RBytes, WBytes uint64
	RIOs, WIOs     uint64
	DBytes, DIOs   uint64
}

func ParseIOStat(r io.Reader) ([]IOStat, error) {
	var out []IOStat
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		var s IOStat
		if _, err := fmt.Sscanf(f[0], "%d:%d", &s.Major, &s.Minor); err != nil {
			return nil, fmt.Errorf("io.stat: bad device %q", f[0])
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				// newer kernels add things like cost.usage, skip non numbers
				continue
			}
			switch k {
			case "rbytes":
				s.RBytes = n
			case "wbytes":
				s.WBytes = n
			case "rios":
				s.RIOs = n
			case "wios":
				s.WIOs = n
			case "dbytes":
				s.DBytes = n
			case "dios":
				s.DIOs = n
			}
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

func ReadIOStat(path string) ([]IOStat, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseIOStat(f)
}
