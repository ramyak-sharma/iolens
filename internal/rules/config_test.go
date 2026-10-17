package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOverrides(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.yaml")
	os.WriteFile(p, []byte("noisyShare: 0.7\nwarmUp: 30s\nsaturatedDepth: 16\n"), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.NoisyShare != 0.7 || c.WarmUp != 30*time.Second || c.SaturatedDepth != 16 {
		t.Errorf("got %+v", c)
	}
	// untouched values keep defaults
	if c.HalfLife != 150*time.Second || c.FireAfter != 3 {
		t.Errorf("defaults lost: %+v", c)
	}
}
