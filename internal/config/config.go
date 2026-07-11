// Package config loads and validates grokbuild-proxy configuration.
package config

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root runtime configuration for grokbuild-proxy.
type Config struct {
	Listen            string          `yaml:"listen"`
	DataDir           string          `yaml:"data_dir"`
	APIKey            string          `yaml:"api_key"`
	AdminKey          string          `yaml:"admin_key"`
	AllowPublicListen bool            `yaml:"allow_public_listen"`
	Upstream          UpstreamConfig  `yaml:"upstream"`
	OAuth             OAuthConfig     `yaml:"oauth"`
	ChatBackend       string          `yaml:"chat_backend"`
	Anthropic         AnthropicConfig `yaml:"anthropic"`
	LB                LBConfig        `yaml:"lb"`
	Limits            LimitsConfig    `yaml:"limits"`
	Logging           LoggingConfig   `yaml:"logging"`
}

// UpstreamConfig controls how requests are sent to cli-chat-proxy.grok.com.
type UpstreamConfig struct {
	BaseURL          string `yaml:"base_url"`
	ClientVersion    string `yaml:"client_version"`
	ClientIdentifier string `yaml:"client_identifier"`
	UserAgent        string `yaml:"user_agent"`
	TokenAuth        string `yaml:"token_auth"`
}

// OAuthConfig holds OIDC / device-flow settings for xAI auth.
type OAuthConfig struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	Scope        string `yaml:"scope"`
	CallbackAddr string `yaml:"callback_addr"`
}

// AnthropicConfig controls Claude Code / Anthropic Messages entry behavior.
type AnthropicConfig struct {
	Enabled             bool              `yaml:"enabled"`
	ModelAliases        map[string]string `yaml:"model_aliases"`
	PassthroughPrefixes []string          `yaml:"passthrough_prefixes"`
	StripUnknownBetas   bool              `yaml:"strip_unknown_betas"`
	CountTokens         bool              `yaml:"count_tokens"`
}

// LBConfig controls multi-credential selection and sticky sessions.
type LBConfig struct {
	Strategy               string         `yaml:"strategy"`
	StickyTTLSec           int            `yaml:"sticky_ttl_sec"`
	RefreshSkewSec         int            `yaml:"refresh_skew_sec"`
	RefreshWorkers         int            `yaml:"refresh_workers"`
	RefreshIntervalSec     int            `yaml:"refresh_interval_sec"`
	RefreshActiveWindowSec int            `yaml:"refresh_active_window_sec"`
	Cooldown               CooldownConfig `yaml:"cooldown"`
}

// CooldownConfig is exponential backoff bounds for failed credentials.
type CooldownConfig struct {
	BaseSec int `yaml:"base_sec"`
	MaxSec  int `yaml:"max_sec"`
}

// LimitsConfig enforces request size, timeout and concurrency caps.
type LimitsConfig struct {
	MaxBodyBytes      int64 `yaml:"max_body_bytes"`
	RequestTimeoutSec int   `yaml:"request_timeout_sec"`
	MaxConcurrent     int   `yaml:"max_concurrent"`
}

// LoggingConfig controls structured logging verbosity.
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// Default returns a Config aligned with plan.md defaults.
func Default() Config {
	return Config{
		Listen:            "127.0.0.1:8080",
		DataDir:           "./data",
		APIKey:            "",
		AdminKey:          "",
		AllowPublicListen: false,
		Upstream: UpstreamConfig{
			BaseURL:          "https://cli-chat-proxy.grok.com/v1",
			ClientVersion:    "0.2.93",
			ClientIdentifier: "grok-pager",
			UserAgent:        "grok-pager/0.2.93 grok-shell/0.2.93 (linux; x86_64)",
			TokenAuth:        "xai-grok-cli",
		},
		OAuth: OAuthConfig{
			Issuer:       "https://auth.x.ai",
			ClientID:     "b1a00492-073a-47ea-816f-4c329264a828",
			Scope:        "openid profile email offline_access grok-cli:access api:access",
			CallbackAddr: "127.0.0.1:56122",
		},
		ChatBackend: "responses",
		Anthropic: AnthropicConfig{
			Enabled: true,
			ModelAliases: map[string]string{
				"claude-sonnet-4":   "grok-4.5",
				"claude-sonnet-4-0": "grok-4.5",
				"claude-sonnet-4-6": "grok-4.5",
				"claude-sonnet-5":   "grok-4.5",
				"claude-opus-4":     "grok-4.5",
				"claude-opus-4-6":   "grok-4.5",
				"claude-opus-4-7":   "grok-4.5",
				"claude-opus-4-8":   "grok-4.5",
				"claude-haiku-4":    "grok-composer-2.5-fast",
				"claude-haiku-4-5":  "grok-composer-2.5-fast",
				"sonnet":            "grok-4.5",
				"opus":              "grok-4.5",
				"haiku":             "grok-composer-2.5-fast",
			},
			PassthroughPrefixes: []string{"grok-"},
			StripUnknownBetas:   true,
			CountTokens:         false,
		},
		LB: LBConfig{
			Strategy:               "priority_rr",
			StickyTTLSec:           3600,
			RefreshSkewSec:         180,
			RefreshWorkers:         4,
			RefreshIntervalSec:     30,
			RefreshActiveWindowSec: 1800,
			Cooldown: CooldownConfig{
				BaseSec: 300,
				MaxSec:  3600,
			},
		},
		Limits: LimitsConfig{
			MaxBodyBytes:      20 * 1024 * 1024,
			RequestTimeoutSec: 600,
			MaxConcurrent:     64,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

// Load reads a YAML file and merges it over Default().
// Missing file returns Default() with no error when path is empty.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		applyListenEnvironment(&cfg)
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, fmt.Errorf("config file not found: %s: %w", path, err)
		}
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return cfg, fmt.Errorf("parse config %s: multiple YAML documents are not supported", path)
		}
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	// Listen overrides must be applied before Validate. This lets an operator
	// safely narrow a config-file public bind to loopback at runtime.
	applyListenEnvironment(&cfg)
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyListenEnvironment(cfg *Config) {
	if cfg == nil {
		return
	}
	if value := strings.TrimSpace(os.Getenv("LISTEN")); value != "" {
		cfg.Listen = value
	}
	if value := strings.TrimSpace(os.Getenv("DATA_DIR")); value != "" {
		cfg.DataDir = value
	}
	if value := strings.TrimSpace(os.Getenv("API_KEY")); value != "" {
		cfg.APIKey = value
	}
	if value := strings.TrimSpace(os.Getenv("ADMIN_KEY")); value != "" {
		cfg.AdminKey = value
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ALLOW_PUBLIC_LISTEN"))) {
	case "1", "true", "yes", "on":
		cfg.AllowPublicListen = true
	}
}

// Validate checks required fields and numeric ranges.
func (c Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen must not be empty")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data_dir must not be empty")
	}
	if c.Upstream.BaseURL == "" {
		return fmt.Errorf("upstream.base_url must not be empty")
	}
	if u, err := url.Parse(c.Upstream.BaseURL); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("upstream.base_url must be an absolute https URL")
	}
	if c.ChatBackend != "responses" {
		return fmt.Errorf("chat_backend must be responses, got %q", c.ChatBackend)
	}
	issuer, err := url.Parse(c.OAuth.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		return fmt.Errorf("oauth.issuer must be an absolute https URL")
	}
	issuerHost := strings.ToLower(issuer.Hostname())
	if issuerHost != "x.ai" && !strings.HasSuffix(issuerHost, ".x.ai") {
		return fmt.Errorf("oauth.issuer host must be x.ai")
	}
	if c.LB.Strategy != "priority_rr" && c.LB.Strategy != "round_robin" {
		return fmt.Errorf("lb.strategy must be priority_rr or round_robin, got %q", c.LB.Strategy)
	}
	if c.LB.StickyTTLSec < 0 {
		return fmt.Errorf("lb.sticky_ttl_sec must be >= 0")
	}
	if c.LB.RefreshSkewSec < 0 {
		return fmt.Errorf("lb.refresh_skew_sec must be >= 0")
	}
	if c.LB.RefreshWorkers < 0 || c.LB.RefreshIntervalSec < 0 || c.LB.RefreshActiveWindowSec < 0 {
		return fmt.Errorf("lb refresh scheduler values must be >= 0")
	}
	if c.LB.Cooldown.BaseSec < 0 || c.LB.Cooldown.MaxSec < 0 {
		return fmt.Errorf("lb.cooldown base_sec/max_sec must be >= 0")
	}
	if c.LB.Cooldown.MaxSec > 0 && c.LB.Cooldown.BaseSec > c.LB.Cooldown.MaxSec {
		return fmt.Errorf("lb.cooldown.base_sec must be <= max_sec")
	}
	if c.Limits.MaxBodyBytes <= 0 {
		return fmt.Errorf("limits.max_body_bytes must be > 0")
	}
	if c.Limits.RequestTimeoutSec <= 0 {
		return fmt.Errorf("limits.request_timeout_sec must be > 0")
	}
	if c.Limits.MaxConcurrent <= 0 {
		return fmt.Errorf("limits.max_concurrent must be > 0")
	}
	switch strings.ToLower(strings.TrimSpace(c.Logging.Level)) {
	case "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("logging.level must be debug, info, warn, or error")
	}
	if c.Anthropic.CountTokens {
		return fmt.Errorf("anthropic.count_tokens is not implemented and must be false")
	}
	return c.ValidateListen(c.Listen)
}

// RequestTimeout returns the configured HTTP request timeout as a duration.
func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.Limits.RequestTimeoutSec) * time.Second
}

// ValidateListen enforces loopback-first operation. Public binds require an
// explicit opt-in because the proxy stores bearer credentials and consumes quota.
func (c Config) ValidateListen(addr string) error {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("listen address %q must be host:port: %w", addr, err)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("listen address %q has an invalid port", addr)
	}
	if !IsPublicListen(addr) {
		return nil
	}
	if !c.AllowPublicListen {
		return fmt.Errorf("public listen %q requires allow_public_listen: true or ALLOW_PUBLIC_LISTEN=true", addr)
	}
	return nil
}

// IsPublicListen reports whether addr binds all interfaces or a non-loopback IP.
// Hostnames are treated as public because their resolution may change.
func IsPublicListen(addr string) bool {
	addr = strings.TrimSpace(addr)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			return true
		}
		return true
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

// StickyTTL returns sticky session TTL as a duration.
func (c Config) StickyTTL() time.Duration {
	return time.Duration(c.LB.StickyTTLSec) * time.Second
}

// RefreshSkew returns pre-expiry refresh skew as a duration.
func (c Config) RefreshSkew() time.Duration {
	return time.Duration(c.LB.RefreshSkewSec) * time.Second
}

// ResolveModel maps an Anthropic/Claude model id to an upstream Grok model.
// If model already matches a passthrough prefix, it is returned unchanged.
// Unknown models are returned as-is (caller may still reject).
func (c Config) ResolveModel(model string) string {
	return c.Anthropic.ResolveModel(model)
}

// ResolveModel maps an Anthropic model id using explicit aliases only.
// Unknown future model ids are not guessed because their capabilities may
// differ from the configured target.
func (c AnthropicConfig) ResolveModel(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return model
	}
	for _, p := range c.PassthroughPrefixes {
		if p != "" && len(model) >= len(p) && model[:len(p)] == p {
			return model
		}
	}
	if alias, ok := c.ModelAliases[model]; ok && alias != "" {
		return alias
	}
	return model
}
