package runtimecfg

import (
	"testing"

	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

func TestManagerPersistsPublishesAndResets(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	defaults := Defaults(config.Default())
	manager, err := New(store, defaults)
	if err != nil {
		t.Fatal(err)
	}
	var observed Settings
	manager.Subscribe(func(settings Settings) { observed = settings })
	if observed.MaxAttempts != defaults.MaxAttempts {
		t.Fatalf("initial observed settings=%+v", observed)
	}

	next := defaults
	next.MaxAttempts = 8
	next.MetricsPublic = true
	next.LogLevel = "debug"
	next.Limits.MaxConcurrent = 96
	if err := manager.Update(next); err != nil {
		t.Fatal(err)
	}
	if observed.MaxAttempts != 8 || manager.Get().Limits.MaxConcurrent != 96 {
		t.Fatalf("updated=%+v observed=%+v", manager.Get(), observed)
	}

	reloaded, err := New(store, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Get(); got.MaxAttempts != 8 || !got.MetricsPublic || got.LogLevel != "debug" {
		t.Fatalf("reloaded=%+v", got)
	}
	if err := manager.Reset(); err != nil {
		t.Fatal(err)
	}
	if got := manager.Get(); got != defaults {
		t.Fatalf("reset=%+v defaults=%+v", got, defaults)
	}
}

func TestSettingsValidation(t *testing.T) {
	valid := Defaults(config.Default())
	tests := []struct {
		name string
		mut  func(*Settings)
	}{
		{"attempts", func(s *Settings) { s.MaxAttempts = 0 }},
		{"strategy", func(s *Settings) { s.LoadBalancing.Strategy = "random" }},
		{"cooldown", func(s *Settings) { s.LoadBalancing.CooldownMaxSec = 1 }},
		{"refresh", func(s *Settings) { s.Refresh.Workers = 65 }},
		{"log", func(s *Settings) { s.LogLevel = "trace" }},
		{"concurrency", func(s *Settings) { s.Limits.MaxConcurrent = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := valid
			test.mut(&settings)
			if err := settings.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
