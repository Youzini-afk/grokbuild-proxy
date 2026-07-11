package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/anthropic"
	"github.com/GreyGunG/grokbuild-proxy/internal/openai"
	"github.com/GreyGunG/grokbuild-proxy/internal/runtimecfg"
)

// ClientAuthenticator validates client API keys (not admin).
type ClientAuthenticator interface {
	// AuthenticateClient returns true when the plaintext key is a valid client key.
	// Bootstrap api_key and hashed client keys both count.
	AuthenticateClient(plaintext string) (ok bool, err error)
}

type RuntimeSettings interface {
	Get() runtimecfg.Settings
}

// Middleware holds shared middleware dependencies.
type Middleware struct {
	Clients  ClientAuthenticator
	AdminKey string
	MaxBody  int64
	// MaxConcurrent limits in-flight authenticated API requests. Zero disables.
	MaxConcurrent int
	QueueWait     time.Duration
	// RequestTimeout bounds the complete request, including upstream streaming.
	RequestTimeout  time.Duration
	Logger          *slog.Logger
	Metrics         *Metrics
	RuntimeSettings RuntimeSettings

	semMu    sync.Mutex
	sem      chan struct{}
	semCap   int
	inflight atomic.Int64
}

// Timeout applies a request context deadline without using Server.WriteTimeout,
// which would terminate SSE writes without a protocol-level error.
func (m *Middleware) Timeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			next.ServeHTTP(w, r)
			return
		}
		timeout := m.RequestTimeout
		if m.RuntimeSettings != nil {
			timeout = time.Duration(m.RuntimeSettings.Get().Limits.RequestTimeoutSec) * time.Second
		}
		if timeout <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) semaphore(maxConcurrent int) chan struct{} {
	if maxConcurrent <= 0 {
		return nil
	}
	m.semMu.Lock()
	defer m.semMu.Unlock()
	if m.sem == nil || m.semCap != maxConcurrent {
		m.sem = make(chan struct{}, maxConcurrent)
		m.semCap = maxConcurrent
	}
	return m.sem
}

// extractAPIKey reads Authorization: Bearer or x-api-key.
func extractAPIKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := strings.TrimSpace(r.Header.Get("x-api-key")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Api-Key")); v != "" {
		return v
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) >= 7 && strings.EqualFold(authz[:7], "Bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	if v := strings.TrimSpace(r.Header.Get("anthropic-api-key")); v != "" {
		return v
	}
	return ""
}

func constantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// RequireClient enforces client API key auth. Admin keys are rejected as clients.
func (m *Middleware) RequireClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := extractAPIKey(r)
		if key == "" {
			writeRouteError(w, r, http.StatusUnauthorized, "missing api key")
			return
		}
		if m.AdminKey != "" && constantTimeEq(key, m.AdminKey) {
			writeRouteError(w, r, http.StatusUnauthorized, "admin key cannot be used as client key")
			return
		}
		if m.Clients == nil {
			writeRouteError(w, r, http.StatusServiceUnavailable, "auth not configured")
			return
		}
		ok, err := m.Clients.AuthenticateClient(key)
		if err != nil {
			writeRouteError(w, r, http.StatusInternalServerError, "auth lookup failed")
			return
		}
		if !ok {
			writeRouteError(w, r, http.StatusUnauthorized, "invalid api key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LimitConcurrency rejects with 503 when MaxConcurrent in-flight requests are active.
func (m *Middleware) LimitConcurrency(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maxConcurrent := m.MaxConcurrent
		wait := m.QueueWait
		if m.RuntimeSettings != nil {
			limits := m.RuntimeSettings.Get().Limits
			maxConcurrent = limits.MaxConcurrent
			wait = time.Duration(limits.QueueWaitMS) * time.Millisecond
		}
		sem := m.semaphore(maxConcurrent)
		if sem == nil {
			next.ServeHTTP(w, r)
			return
		}
		if wait <= 0 {
			wait = time.Nanosecond
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case sem <- struct{}{}:
			m.inflight.Add(1)
			defer func() {
				<-sem
				m.inflight.Add(-1)
			}()
			next.ServeHTTP(w, r)
		case <-timer.C:
			w.Header().Set("Retry-After", "1")
			writeRouteError(w, r, http.StatusServiceUnavailable, "too many concurrent requests")
		case <-r.Context().Done():
			writeRouteError(w, r, http.StatusRequestTimeout, "request cancelled while queued")
		}
	})
}

// LimitBody wraps the request body with MaxBytesReader when MaxBody > 0.
func (m *Middleware) LimitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maxBody := m.MaxBody
		if m.RuntimeSettings != nil {
			maxBody = m.RuntimeSettings.Get().Limits.MaxBodyBytes
		}
		if maxBody > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

// Chain applies middlewares in order (first is outermost).
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

func writeRouteError(w http.ResponseWriter, r *http.Request, status int, message string) {
	if r != nil && strings.HasPrefix(r.URL.Path, "/v1/messages") {
		anthropic.WriteError(w, status, message)
		return
	}
	openai.WriteError(w, status, message, "", "")
}

func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				const hex = "0123456789abcdef"
				b.WriteByte(hex[r>>4])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
