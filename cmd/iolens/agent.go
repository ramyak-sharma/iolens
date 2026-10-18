package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ramyak-sharma/iolens/internal/export"
	"github.com/ramyak-sharma/iolens/internal/rules"
	"github.com/ramyak-sharma/iolens/internal/tui"
)

func runAgent(ctx context.Context, cmd string, o options) error {
	log, done, err := logger(cmd, o)
	if err != nil {
		return err
	}
	defer done()

	cfg, err := rules.Load(o.config)
	if err != nil {
		return err
	}
	eng := rules.New(cfg, log)

	c, cleanup, err := setup(ctx, o, log, eng.Findings)
	if err != nil {
		return err
	}
	// closing the links detaches the programs, nothing stays in the kernel
	defer cleanup()

	exp := export.New(c, o.topCgroups)
	go eng.Run(ctx, c.Subscribe())
	go func() {
		for s := range c.Subscribe() {
			exp.Observe(s)
		}
	}()

	var srv *http.Server
	if o.listen != "" {
		reg := prometheus.NewRegistry()
		reg.MustRegister(exp, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			if c.Latest() == nil {
				http.Error(w, "no snapshot yet", http.StatusServiceUnavailable)
				return
			}
			w.Write([]byte("ok\n"))
		})
		mux.HandleFunc("/findings", func(w http.ResponseWriter, r *http.Request) {
			f, warming := eng.Findings()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"warming": warming, "findings": f})
		})
		srv = &http.Server{Addr: o.listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("http server", "err", err)
			}
		}()
		log.Info("serving metrics", "addr", o.listen)
	}

	if cmd == "top" {
		go tui.Run(ctx, os.Stdout, c.Subscribe())
	}

	err = c.Run(ctx)
	if srv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}
	log.Info("shutting down")
	return err
}
