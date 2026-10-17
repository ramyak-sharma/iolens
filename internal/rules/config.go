// Package rules turns snapshots into findings a human can act on. rules are
// simple on purpose: every finding carries the numbers that made it fire so
// whoever reads it can check instead of trusting it.
package rules

import (
	"os"
	"time"

	"sigs.k8s.io/yaml"
)

type Config struct {
	Window      int           `json:"window"`      // snapshots per evaluation
	HalfLife    time.Duration `json:"halfLife"`    // baseline ewma half life
	WarmUp      time.Duration `json:"warmUp"`      // nothing fires before this
	FireAfter   int           `json:"fireAfter"`   // consecutive true evals to fire
	ClearAfter  int           `json:"clearAfter"`  // consecutive false evals to clear
	MinRequests uint64        `json:"minRequests"` // per series per window

	NoisyLatencyFactor    float64 `json:"noisyLatencyFactor"`
	NoisyShare            float64 `json:"noisyShare"`
	NoisyThroughputFactor float64 `json:"noisyThroughputFactor"`

	SlowDeviceFactor float64 `json:"slowDeviceFactor"`

	SaturatedDepth float64 `json:"saturatedDepth"`
	SaturatedPSI   float64 `json:"saturatedPSI"`

	StallFull float64 `json:"stallFull"`
}

func Defaults() Config {
	return Config{
		Window:      10,
		HalfLife:    150 * time.Second,
		WarmUp:      2 * time.Minute,
		FireAfter:   3,
		ClearAfter:  6,
		MinRequests: 100,

		NoisyLatencyFactor:    3,
		NoisyShare:            0.5,
		NoisyThroughputFactor: 3,

		SlowDeviceFactor: 3,

		SaturatedDepth: 8,
		SaturatedPSI:   0.10,

		StallFull: 0.05,
	}
}

// Load reads thresholds from yaml on top of the defaults. durations are
// written like "150s" or "2m"
func Load(path string) (Config, error) {
	c := Defaults()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	var raw struct {
		Config
		HalfLife string `json:"halfLife"`
		WarmUp   string `json:"warmUp"`
	}
	raw.Config = c
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return c, err
	}
	c = raw.Config
	if raw.HalfLife != "" {
		if c.HalfLife, err = time.ParseDuration(raw.HalfLife); err != nil {
			return c, err
		}
	} else {
		c.HalfLife = Defaults().HalfLife
	}
	if raw.WarmUp != "" {
		if c.WarmUp, err = time.ParseDuration(raw.WarmUp); err != nil {
			return c, err
		}
	} else {
		c.WarmUp = Defaults().WarmUp
	}
	return c, nil
}
