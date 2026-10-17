package rules

import (
	"github.com/ramyak-sharma/iolens/internal/collector"
	"github.com/ramyak-sharma/iolens/internal/hist"
)

type seriesKey struct {
	dev, pod, op string
}

type deviceAgg struct {
	all      hist.Hist // every series on the device
	bytes    float64
	ios      float64
	podBytes map[string]float64
	podIOs   map[string]float64
	depth    float64 // mean aqu-sz over window
	iops     float64 // mean, from diskstats
}

// window is the last N snapshots folded together
type window struct {
	seconds    float64
	series     map[seriesKey]*hist.Hist
	devices    map[string]*deviceAgg
	psiSome    float64
	psiFull    float64
	podPSIFull map[string]float64
}

func buildWindow(ring []*collector.Snapshot) *window {
	w := &window{
		series:     map[seriesKey]*hist.Hist{},
		devices:    map[string]*deviceAgg{},
		podPSIFull: map[string]float64{},
	}
	dev := func(name string) *deviceAgg {
		d := w.devices[name]
		if d == nil {
			d = &deviceAgg{podBytes: map[string]float64{}, podIOs: map[string]float64{}}
			w.devices[name] = d
		}
		return d
	}
	n := float64(len(ring))
	for _, s := range ring {
		w.seconds += s.Interval.Seconds()
		w.psiSome += s.NodePSI.Some / n
		w.psiFull += s.NodePSI.Full / n
		for _, r := range s.Devices {
			d := dev(r.Name)
			d.depth += r.AquSz / n
			d.iops += (r.RPS + r.WPS) / n
		}
		for _, ser := range s.Series {
			pod := ser.Labels.PodName()
			k := seriesKey{ser.Device, pod, ser.Key.Op.String()}
			h := w.series[k]
			if h == nil {
				h = &hist.Hist{}
				w.series[k] = h
			}
			h.Add(&ser.Win)
			d := dev(ser.Device)
			d.all.Add(&ser.Win)
			d.bytes += float64(ser.Win.Bytes)
			d.ios += float64(ser.Win.Count)
			d.podBytes[pod] += float64(ser.Win.Bytes)
			d.podIOs[pod] += float64(ser.Win.Count)
		}
		// a pod can have several container cgroups, take the worst one
		worst := map[string]float64{}
		for _, cg := range s.Cgroups {
			if cg.HasPSI && cg.Labels.Pod != "" {
				pod := cg.Labels.PodName()
				if cg.Share.Full > worst[pod] {
					worst[pod] = cg.Share.Full
				}
			}
		}
		for pod, v := range worst {
			w.podPSIFull[pod] += v / n
		}
	}
	if w.seconds == 0 {
		w.seconds = 1
	}
	return w
}
