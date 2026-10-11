//go:build linux

package probe

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/ramyak-sharma/iolens/internal/bpfsrc"
	"github.com/ramyak-sharma/iolens/internal/hist"
)

type Probe struct {
	objs  bpfsrc.IolensObjects
	links []link.Link
	stats io.Closer

	// reused between reads so we dont allocate 4096 * 1.7KB every second
	keyBuf  []bpfsrc.IolensHistKey
	valBuf  []bpfsrc.IolensHist
	noBatch bool
}

// Load loads and attaches the program. caller must Close it, closing the
// links is what detaches from the kernel
func Load() (*Probe, error) {
	// only matters on kernels that still charge bpf memory to memlock (<5.11)
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	p := &Probe{}
	if err := bpfsrc.LoadIolensObjects(&p.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier: %+v", ve)
		}
		return nil, fmt.Errorf("load: %w", err)
	}

	progs := []*ebpf.Program{p.objs.OnInsert, p.objs.OnIssue, p.objs.OnComplete}
	for _, prog := range progs {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("attach %s: %w", prog, err)
		}
		p.links = append(p.links, l)
	}

	// run time stats are on as long as this fd is open. not fatal if
	// kernel says no, we just dont report ns per event
	if c, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME)); err == nil {
		p.stats = c
	}

	n := int(p.objs.Hists.MaxEntries())
	p.keyBuf = make([]bpfsrc.IolensHistKey, n)
	p.valBuf = make([]bpfsrc.IolensHist, n)
	return p, nil
}

func (p *Probe) Close() error {
	for _, l := range p.links {
		l.Close()
	}
	p.links = nil
	if p.stats != nil {
		p.stats.Close()
		p.stats = nil
	}
	return p.objs.Close()
}

// Read returns every histogram in the map. values are cumulative,
// the kernel never resets them
func (p *Probe) Read() (map[Key]*hist.Hist, error) {
	out := make(map[Key]*hist.Hist)
	if !p.noBatch {
		err := p.readBatch(out)
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, ebpf.ErrNotSupported) {
			return nil, err
		}
		p.noBatch = true
		clear(out)
	}
	var k bpfsrc.IolensHistKey
	var v bpfsrc.IolensHist
	it := p.objs.Hists.Iterate()
	for it.Next(&k, &v) {
		out[fromKey(k)] = fromHist(&v)
	}
	return out, it.Err()
}

func (p *Probe) readBatch(out map[Key]*hist.Hist) error {
	var cursor ebpf.MapBatchCursor
	for {
		n, err := p.objs.Hists.BatchLookup(&cursor, p.keyBuf, p.valBuf, nil)
		for i := 0; i < n; i++ {
			out[fromKey(p.keyBuf[i])] = fromHist(&p.valBuf[i])
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil // done
		}
		if err != nil {
			return err
		}
	}
}

// Delete drops histograms for cgroups that went away
func (p *Probe) Delete(keys []Key) error {
	var errs []error
	for _, k := range keys {
		bk := toKey(k)
		if err := p.objs.Hists.Delete(&bk); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *Probe) Stats() map[string]ProgStats {
	out := map[string]ProgStats{}
	for name, prog := range map[string]*ebpf.Program{
		"insert": p.objs.OnInsert, "issue": p.objs.OnIssue, "complete": p.objs.OnComplete,
	} {
		st, err := prog.Stats()
		if err != nil {
			continue
		}
		out[name] = ProgStats{RunNs: uint64(st.Runtime.Nanoseconds()), RunCount: st.RunCount}
	}
	return out
}

// InflightEntries counts the in flight map. walks keys only
func (p *Probe) InflightEntries() (int, error) {
	var k, next uint64
	n := 0
	m := p.objs.Inflight
	err := m.NextKey(nil, &next)
	for err == nil {
		n++
		k = next
		err = m.NextKey(&k, &next)
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return n, nil
	}
	return n, err
}

func fromKey(k bpfsrc.IolensHistKey) Key {
	return Key{Cgroup: k.Cgid, Dev: k.Dev, Op: Op(k.Op)}
}

func toKey(k Key) bpfsrc.IolensHistKey {
	return bpfsrc.IolensHistKey{Cgid: k.Cgroup, Dev: k.Dev, Op: uint8(k.Op)}
}

func fromHist(v *bpfsrc.IolensHist) *hist.Hist {
	h := &hist.Hist{
		Device:   v.DevSlots,
		Total:    v.TotSlots,
		Count:    v.Count,
		Bytes:    v.Bytes,
		Errors:   v.Errors,
		QueueNs:  v.QueueNs,
		DeviceNs: v.DevNs,
		TotalNs:  v.TotNs,
	}
	return h
}
