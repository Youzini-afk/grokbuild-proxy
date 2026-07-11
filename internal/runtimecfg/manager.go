// Package runtimecfg owns validated, durable settings that can change without
// restarting the service.
package runtimecfg

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/GreyGunG/grokbuild-proxy/internal/config"
)

type Settings struct {
	MaxAttempts   int           `json:"max_attempts"`
	MetricsPublic bool          `json:"metrics_public"`
	LogLevel      string        `json:"log_level"`
	LoadBalancing LoadBalancing `json:"load_balancing"`
	Health        Health        `json:"health"`
	Refresh       Refresh       `json:"refresh"`
	Limits        RuntimeLimits `json:"limits"`
}

type LoadBalancing struct {
	Strategy        string `json:"strategy"`
	StickyTTLSec    int    `json:"sticky_ttl_sec"`
	CooldownBaseSec int    `json:"cooldown_base_sec"`
	CooldownMaxSec  int    `json:"cooldown_max_sec"`
}

type RuntimeLimits struct {
	MaxBodyBytes      int64 `json:"max_body_bytes"`
	RequestTimeoutSec int   `json:"request_timeout_sec"`
	MaxConcurrent     int   `json:"max_concurrent"`
	QueueWaitMS       int   `json:"queue_wait_ms"`
}

type Refresh struct {
	Workers         int `json:"workers"`
	IntervalSec     int `json:"interval_sec"`
	ActiveWindowSec int `json:"active_window_sec"`
}

type Health struct {
	AuthInitialSec     int `json:"auth_initial_sec"`
	AuthMaxSec         int `json:"auth_max_sec"`
	AuthAbnormalAfter  int `json:"auth_abnormal_after"`
	QuotaInitialSec    int `json:"quota_initial_sec"`
	QuotaMaxSec        int `json:"quota_max_sec"`
	RateInitialSec     int `json:"rate_initial_sec"`
	RateMaxSec         int `json:"rate_max_sec"`
	ProbeEveryRequests int `json:"probe_every_requests"`
	ProbeLeaseSec      int `json:"probe_lease_sec"`
}

type Store interface {
	LoadRuntimeSettingsJSON() ([]byte, error)
	SaveRuntimeSettingsJSON([]byte) error
	DeleteRuntimeSettings() error
}

type Manager struct {
	store    Store
	defaults Settings
	current  atomic.Pointer[Settings]

	mu        sync.Mutex
	listeners []func(Settings)
}

func Defaults(cfg config.Config) Settings {
	strategy := strings.ToLower(strings.TrimSpace(cfg.LB.Strategy))
	if strategy == "" {
		strategy = "priority_rr"
	}
	cooldownBase := cfg.LB.Cooldown.BaseSec
	if cooldownBase < 1 {
		cooldownBase = 300
	}
	cooldownMax := cfg.LB.Cooldown.MaxSec
	if cooldownMax < cooldownBase {
		cooldownMax = max(cooldownBase, 3600)
	}
	refreshInterval := cfg.LB.RefreshIntervalSec
	if refreshInterval < 5 {
		refreshInterval = 30
	}
	activeWindow := cfg.LB.RefreshActiveWindowSec
	if activeWindow < 60 {
		activeWindow = 1800
	}
	logLevel := strings.ToLower(strings.TrimSpace(cfg.Logging.Level))
	if logLevel == "" {
		logLevel = "info"
	}
	return Settings{
		MaxAttempts:   3,
		MetricsPublic: false,
		LogLevel:      logLevel,
		LoadBalancing: LoadBalancing{
			Strategy:        strategy,
			StickyTTLSec:    cfg.LB.StickyTTLSec,
			CooldownBaseSec: cooldownBase,
			CooldownMaxSec:  cooldownMax,
		},
		Health: Health{
			AuthInitialSec: 60, AuthMaxSec: 6 * 3600, AuthAbnormalAfter: 4,
			QuotaInitialSec: 5 * 60, QuotaMaxSec: 2 * 3600,
			RateInitialSec: 30, RateMaxSec: 30 * 60,
			ProbeEveryRequests: 20, ProbeLeaseSec: 120,
		},
		Refresh: Refresh{
			Workers:         cfg.LB.RefreshWorkers,
			IntervalSec:     refreshInterval,
			ActiveWindowSec: activeWindow,
		},
		Limits: RuntimeLimits{
			MaxBodyBytes:      cfg.Limits.MaxBodyBytes,
			RequestTimeoutSec: cfg.Limits.RequestTimeoutSec,
			MaxConcurrent:     cfg.Limits.MaxConcurrent,
			QueueWaitMS:       cfg.Limits.QueueWaitMS,
		},
	}
}

func New(store Store, defaults Settings) (*Manager, error) {
	if err := defaults.Validate(); err != nil {
		return nil, fmt.Errorf("runtime settings defaults: %w", err)
	}
	m := &Manager{store: store, defaults: defaults}
	current := defaults
	if store != nil {
		raw, err := store.LoadRuntimeSettingsJSON()
		if err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &current); err != nil {
				return nil, fmt.Errorf("runtime settings decode: %w", err)
			}
			if err := current.Validate(); err != nil {
				return nil, fmt.Errorf("runtime settings persisted value: %w", err)
			}
		}
	}
	m.current.Store(&current)
	return m, nil
}

func (m *Manager) Get() Settings {
	if m == nil || m.current.Load() == nil {
		return Settings{}
	}
	return *m.current.Load()
}

func (m *Manager) Defaults() Settings {
	if m == nil {
		return Settings{}
	}
	return m.defaults
}

func (m *Manager) Update(next Settings) error {
	if m == nil {
		return fmt.Errorf("runtime settings manager unavailable")
	}
	if err := next.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if m.store != nil {
		if err := m.store.SaveRuntimeSettingsJSON(raw); err != nil {
			return err
		}
	}
	m.publish(next)
	return nil
}

func (m *Manager) Reset() error {
	if m == nil {
		return fmt.Errorf("runtime settings manager unavailable")
	}
	if m.store != nil {
		if err := m.store.DeleteRuntimeSettings(); err != nil {
			return err
		}
	}
	m.publish(m.defaults)
	return nil
}

func (m *Manager) Subscribe(listener func(Settings)) {
	if m == nil || listener == nil {
		return
	}
	m.mu.Lock()
	m.listeners = append(m.listeners, listener)
	current := m.Get()
	m.mu.Unlock()
	listener(current)
}

func (m *Manager) publish(next Settings) {
	copyValue := next
	m.current.Store(&copyValue)
	m.mu.Lock()
	listeners := append([]func(Settings){}, m.listeners...)
	m.mu.Unlock()
	for _, listener := range listeners {
		listener(next)
	}
}

func (s Settings) Validate() error {
	if s.MaxAttempts < 1 || s.MaxAttempts > 20 {
		return fmt.Errorf("max_attempts must be between 1 and 20")
	}
	switch strings.ToLower(strings.TrimSpace(s.LogLevel)) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be debug, info, warn, or error")
	}
	switch strings.ToLower(strings.TrimSpace(s.LoadBalancing.Strategy)) {
	case "priority_rr", "round_robin":
	default:
		return fmt.Errorf("load_balancing.strategy must be priority_rr or round_robin")
	}
	if s.LoadBalancing.StickyTTLSec < 0 || s.LoadBalancing.StickyTTLSec > 7*24*3600 {
		return fmt.Errorf("sticky_ttl_sec must be between 0 and 604800")
	}
	if s.LoadBalancing.CooldownBaseSec < 1 || s.LoadBalancing.CooldownBaseSec > 24*3600 {
		return fmt.Errorf("cooldown_base_sec must be between 1 and 86400")
	}
	if s.LoadBalancing.CooldownMaxSec < s.LoadBalancing.CooldownBaseSec || s.LoadBalancing.CooldownMaxSec > 7*24*3600 {
		return fmt.Errorf("cooldown_max_sec must be >= base and <= 604800")
	}
	if s.Health.AuthInitialSec < 10 || s.Health.AuthInitialSec > 3600 ||
		s.Health.AuthMaxSec < s.Health.AuthInitialSec || s.Health.AuthMaxSec > 7*24*3600 {
		return fmt.Errorf("health auth cooldown must be 10..3600 initial and initial..604800 max")
	}
	if s.Health.AuthAbnormalAfter < 2 || s.Health.AuthAbnormalAfter > 20 {
		return fmt.Errorf("health.auth_abnormal_after must be between 2 and 20")
	}
	if s.Health.QuotaInitialSec < 30 || s.Health.QuotaInitialSec > 24*3600 ||
		s.Health.QuotaMaxSec < s.Health.QuotaInitialSec || s.Health.QuotaMaxSec > 7*24*3600 {
		return fmt.Errorf("health quota cooldown is invalid")
	}
	if s.Health.RateInitialSec < 5 || s.Health.RateInitialSec > 3600 ||
		s.Health.RateMaxSec < s.Health.RateInitialSec || s.Health.RateMaxSec > 24*3600 {
		return fmt.Errorf("health rate-limit cooldown is invalid")
	}
	if s.Health.ProbeEveryRequests < 1 || s.Health.ProbeEveryRequests > 10000 {
		return fmt.Errorf("health.probe_every_requests must be between 1 and 10000")
	}
	if s.Health.ProbeLeaseSec < 10 || s.Health.ProbeLeaseSec > 3600 {
		return fmt.Errorf("health.probe_lease_sec must be between 10 and 3600")
	}
	if s.Refresh.Workers < 0 || s.Refresh.Workers > 64 {
		return fmt.Errorf("refresh.workers must be between 0 and 64")
	}
	if s.Refresh.IntervalSec < 5 || s.Refresh.IntervalSec > 3600 {
		return fmt.Errorf("refresh.interval_sec must be between 5 and 3600")
	}
	if s.Refresh.ActiveWindowSec < 60 || s.Refresh.ActiveWindowSec > 7*24*3600 {
		return fmt.Errorf("refresh.active_window_sec must be between 60 and 604800")
	}
	if s.Limits.MaxBodyBytes < 1<<20 || s.Limits.MaxBodyBytes > 256<<20 {
		return fmt.Errorf("max_body_bytes must be between 1048576 and 268435456")
	}
	if s.Limits.RequestTimeoutSec < 10 || s.Limits.RequestTimeoutSec > 3600 {
		return fmt.Errorf("request_timeout_sec must be between 10 and 3600")
	}
	if s.Limits.MaxConcurrent < 1 || s.Limits.MaxConcurrent > 1024 {
		return fmt.Errorf("max_concurrent must be between 1 and 1024")
	}
	if s.Limits.QueueWaitMS < 0 || s.Limits.QueueWaitMS > 60000 {
		return fmt.Errorf("queue_wait_ms must be between 0 and 60000")
	}
	return nil
}
