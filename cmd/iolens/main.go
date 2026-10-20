// iolens: per pod block io latency for linux nodes.
//
//	iolens serve            collect, run rules, serve metrics (daemonset mode)
//	iolens top              same plus a terminal view
//	iolens once --duration  collect for a while, print json, exit
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ramyak-sharma/iolens/internal/cgroupmap"
	"github.com/ramyak-sharma/iolens/internal/collector"
	"github.com/ramyak-sharma/iolens/internal/k8s"
	"github.com/ramyak-sharma/iolens/internal/probe"
)

type options struct {
	interval   time.Duration
	listen     string
	devices    string
	topCgroups int
	k8s        string
	noBPF      bool
	config     string
	cgroupRoot string
	duration   time.Duration
	logFile    string
	align      bool
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: iolens <serve|top|once> [flags]

commands:
  serve   agent mode: collect, run rules, serve metrics
  top     agent plus terminal view
  once    collect for --duration, print a json summary, exit

flags:
`)
	flag.PrintDefaults()
}

func main() {
	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-") {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]

	var o options
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.DurationVar(&o.interval, "interval", time.Second, "snapshot period")
	fs.StringVar(&o.listen, "listen", ":9187", "metrics address, empty to disable")
	fs.StringVar(&o.devices, "devices", "", "comma separated device filter, default all non virtual")
	fs.IntVar(&o.topCgroups, "top-cgroups", 50, "per device cgroups with their own series, rest go to pod=_other")
	fs.StringVar(&o.k8s, "k8s", "auto", "pod informer: on, off, or auto (on if NODE_NAME is set)")
	fs.BoolVar(&o.noBPF, "no-bpf", false, "procfs, psi and io.stat only, for kernels without btf")
	fs.StringVar(&o.config, "config", "", "yaml file with rule thresholds")
	fs.StringVar(&o.cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "cgroup v2 mount")
	fs.DurationVar(&o.duration, "duration", 10*time.Second, "how long `once` collects")
	fs.BoolVar(&o.align, "align", false, "once: tick on whole seconds so windows line up with iostat")
	fs.StringVar(&o.logFile, "log-file", "", "log here instead of stderr (top discards logs otherwise)")
	flag.CommandLine = fs
	fs.Usage = usage
	fs.Parse(os.Args[2:])

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "serve", "top":
		err = runAgent(ctx, cmd, o)
	case "once":
		err = runOnce(ctx, o)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "iolens:", err)
		os.Exit(1)
	}
}

func logger(cmd string, o options) (*slog.Logger, func(), error) {
	var w io.Writer = os.Stderr
	done := func() {}
	if o.logFile != "" {
		f, err := os.OpenFile(o.logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, nil, err
		}
		w, done = f, func() { f.Close() }
	} else if cmd == "top" {
		w = io.Discard // would scribble over the screen
	}
	return slog.New(slog.NewJSONHandler(w, nil)), done, nil
}

// setup builds everything the commands share
func setup(ctx context.Context, o options, log *slog.Logger, findings func() ([]collector.Finding, bool)) (*collector.Collector, func(), error) {
	cleanup := func() {}
	var src probe.Source
	if !o.noBPF {
		p, err := probe.Load()
		if err != nil {
			return nil, nil, fmt.Errorf("%w (try --no-bpf)", err)
		}
		src = p
		cleanup = func() { p.Close() }
		log.Info("bpf program attached")
	}

	res := cgroupmap.NewResolver(o.cgroupRoot)
	if err := res.Rescan(true); err != nil {
		log.Warn("cgroup scan", "err", err)
	}

	var pods *k8s.Pods
	node := os.Getenv("NODE_NAME")
	if o.k8s == "on" || (o.k8s == "auto" && node != "") {
		if node == "" {
			cleanup()
			return nil, nil, errors.New("--k8s=on needs NODE_NAME")
		}
		var err error
		pods, err = k8s.Start(ctx, node)
		if err != nil {
			// not fatal, raw cgroup paths are still useful
			log.Warn("pod informer failed, showing cgroup paths", "err", err)
			pods = nil
		} else {
			log.Info("pod informer synced", "node", node)
		}
	}

	var devs []string
	if o.devices != "" {
		devs = strings.Split(o.devices, ",")
	}
	c := collector.New(collector.Config{
		Interval: o.interval,
		Source:   src,
		Resolver: res,
		Pods:     pods,
		Devices:  devs,
		Findings: findings,
		Log:      log,
	})
	return c, cleanup, nil
}
