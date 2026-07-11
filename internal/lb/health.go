package lb

import (
	"fmt"
	"strings"
	"time"
)

type FailureClass string

const (
	FailureAuth      FailureClass = "auth_invalid"
	FailureQuota     FailureClass = "quota_exhausted"
	FailureRateLimit FailureClass = "rate_limited"
	FailureTransient FailureClass = "transient"
	FailureModel     FailureClass = "model_unavailable"
	FailureOther     FailureClass = "other"
)

// FailureSignal is a sanitized semantic outcome. Code must never contain a
// token or response body.
type FailureSignal struct {
	Class      FailureClass
	Status     int
	Code       string
	RetryAfter time.Duration
}

func FailureSignalForStatus(status int, retryAfter time.Duration) FailureSignal {
	class := FailureOther
	switch {
	case status == 0 || status >= 500:
		class = FailureTransient
	case status == 401 || status == 403:
		class = FailureAuth
	case status == 402:
		class = FailureQuota
	case status == 429:
		class = FailureRateLimit
	}
	return FailureSignal{Class: class, Status: status, RetryAfter: retryAfter}
}

type AdaptiveConfig struct {
	AuthInitial       time.Duration
	AuthMax           time.Duration
	AuthAbnormalAfter int
	QuotaInitial      time.Duration
	QuotaMax          time.Duration
	RateInitial       time.Duration
	RateMax           time.Duration
	ProbeEvery        uint64
	ProbeLease        time.Duration
}

func DefaultAdaptiveConfig() AdaptiveConfig {
	return AdaptiveConfig{
		AuthInitial: time.Minute, AuthMax: 6 * time.Hour, AuthAbnormalAfter: 4,
		QuotaInitial: 5 * time.Minute, QuotaMax: 2 * time.Hour,
		RateInitial: 30 * time.Second, RateMax: 30 * time.Minute,
		ProbeEvery: 20, ProbeLease: 2 * time.Minute,
	}
}

func normalizeAdaptiveConfig(cfg AdaptiveConfig) AdaptiveConfig {
	defaults := DefaultAdaptiveConfig()
	if cfg.AuthInitial <= 0 {
		cfg.AuthInitial = defaults.AuthInitial
	}
	if cfg.AuthMax < cfg.AuthInitial {
		cfg.AuthMax = defaults.AuthMax
	}
	if cfg.AuthAbnormalAfter < 1 {
		cfg.AuthAbnormalAfter = defaults.AuthAbnormalAfter
	}
	if cfg.QuotaInitial <= 0 {
		cfg.QuotaInitial = defaults.QuotaInitial
	}
	if cfg.QuotaMax < cfg.QuotaInitial {
		cfg.QuotaMax = defaults.QuotaMax
	}
	if cfg.RateInitial <= 0 {
		cfg.RateInitial = defaults.RateInitial
	}
	if cfg.RateMax < cfg.RateInitial {
		cfg.RateMax = defaults.RateMax
	}
	if cfg.ProbeEvery == 0 {
		cfg.ProbeEvery = defaults.ProbeEvery
	}
	if cfg.ProbeLease <= 0 {
		cfg.ProbeLease = defaults.ProbeLease
	}
	return cfg
}

func (f FailureSignal) normalized() FailureSignal {
	switch f.Class {
	case FailureAuth, FailureQuota, FailureRateLimit, FailureTransient, FailureModel, FailureOther:
	default:
		f.Class = FailureOther
	}
	f.Code = sanitizeFailureCode(f.Code)
	return f
}

func (f FailureSignal) Label() string {
	f = f.normalized()
	code := f.Code
	if code == "" && f.Status > 0 {
		code = fmt.Sprintf("http-%d", f.Status)
	}
	if code == "" {
		code = "network"
	}
	return string(f.Class) + ":" + code
}

func sanitizeFailureCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if len(code) > 128 {
		code = code[:128]
	}
	var out strings.Builder
	for _, char := range code {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') ||
			char == ':' || char == '-' || char == '_' || char == '.' {
			out.WriteRune(char)
		}
	}
	return out.String()
}

func failureClassFromLabel(label string) FailureClass {
	prefix, _, _ := strings.Cut(strings.TrimSpace(label), ":")
	switch FailureClass(prefix) {
	case FailureAuth, FailureQuota, FailureRateLimit, FailureTransient, FailureModel, FailureOther:
		return FailureClass(prefix)
	}
	return FailureOther
}

func exponential(initial, maximum time.Duration, failures int, multiplier int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	if multiplier < 2 {
		multiplier = 2
	}
	duration := initial
	for i := 1; i < failures && duration < maximum; i++ {
		if duration > maximum/time.Duration(multiplier) {
			return maximum
		}
		duration *= time.Duration(multiplier)
	}
	if duration > maximum {
		return maximum
	}
	return duration
}

func (s *Selector) adaptiveCooldown(signal FailureSignal, failures int) time.Duration {
	signal = signal.normalized()
	cfg := normalizeAdaptiveConfig(s.adaptive)
	var duration time.Duration
	switch signal.Class {
	case FailureAuth:
		duration = exponential(cfg.AuthInitial, cfg.AuthMax, failures, 5)
	case FailureQuota:
		duration = exponential(cfg.QuotaInitial, cfg.QuotaMax, failures, 2)
	case FailureRateLimit:
		duration = exponential(cfg.RateInitial, cfg.RateMax, failures, 2)
		if signal.RetryAfter > duration {
			duration = signal.RetryAfter
		}
		if duration > cfg.RateMax {
			duration = cfg.RateMax
		}
	case FailureTransient:
		duration = exponential(15*time.Second, 5*time.Minute, failures, 2)
	case FailureModel:
		duration = exponential(time.Minute, time.Hour, failures, 2)
	default:
		duration = s.cooldownDuration(signal.Status, signal.RetryAfter, failures-1)
		return duration
	}
	return duration + jitter(duration)
}
