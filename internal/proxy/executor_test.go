package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/lb"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
	"github.com/GreyGunG/grokbuild-proxy/internal/upstream"
)

type memStore struct {
	mu      sync.Mutex
	creds   map[string]storage.Credential
	patches int
}

func newMemStore(creds ...storage.Credential) *memStore {
	m := &memStore{creds: make(map[string]storage.Credential)}
	for _, c := range creds {
		m.creds[c.ID] = c
	}
	return m
}

func (m *memStore) ListCredentials() ([]storage.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]storage.Credential, 0, len(m.creds))
	for _, c := range m.creds {
		out = append(out, c)
	}
	return out, nil
}

func (m *memStore) GetCredential(id string) (storage.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[id]
	if !ok {
		return storage.Credential{}, storageNotFound(id)
	}
	return c, nil
}

func (m *memStore) UpdateCredential(c storage.Credential) (storage.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[c.ID]; !ok {
		return storage.Credential{}, storageNotFound(c.ID)
	}
	m.creds[c.ID] = c
	return c, nil
}

func (m *memStore) PatchCredential(id string, mutate func(*storage.Credential) error) (storage.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.patches++
	c, ok := m.creds[id]
	if !ok {
		return storage.Credential{}, storageNotFound(id)
	}
	if mutate != nil {
		if err := mutate(&c); err != nil {
			return storage.Credential{}, err
		}
	}
	c.ID = id
	m.creds[id] = c
	return c, nil
}

func TestTouchLastUsedIsThrottled(t *testing.T) {
	credential := storage.Credential{ID: "cred-usage", Enabled: true}
	store := newMemStore(credential)
	now := time.Date(2026, 7, 10, 4, 0, 0, 0, time.UTC)
	executor := &Executor{Store: store, Now: func() time.Time { return now }}
	if err := executor.touchLastUsed(credential); err != nil {
		t.Fatal(err)
	}
	if err := executor.touchLastUsed(credential); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	patches := store.patches
	store.mu.Unlock()
	if patches != 1 {
		t.Fatalf("patches=%d want 1", patches)
	}
	now = now.Add(5*time.Minute + time.Second)
	if err := executor.touchLastUsed(credential); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	patches = store.patches
	store.mu.Unlock()
	if patches != 2 {
		t.Fatalf("patches=%d want 2", patches)
	}
}

type notFoundError string

func (e notFoundError) Error() string { return "storage: credential " + string(e) + " not found" }

func storageNotFound(id string) error { return notFoundError(id) }

type passthroughRefresher struct{}

func (passthroughRefresher) EnsureAccess(_ context.Context, _ string, current auth.TokenSet, _ auth.TokenPersistFunc) (auth.TokenSet, error) {
	return current, nil
}

func (passthroughRefresher) ForceRefresh(_ context.Context, _ string, current auth.TokenSet, _ auth.TokenPersistFunc) (auth.TokenSet, error) {
	return current, nil
}

func TestExecutorPostSuccess(t *testing.T) {
	var gotAuth string
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotModel = r.Header.Get("x-grok-model-override")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","status":"completed"}`))
	}))
	t.Cleanup(srv.Close)

	up := upstream.NewClient(upstream.Config{
		BaseURL:    srv.URL + "/v1",
		HTTPClient: srv.Client(),
	})
	store := newMemStore(storage.Credential{
		ID:          "cred_a",
		Name:        "a",
		AccessToken: "access-token-a",
		Enabled:     true,
		Priority:    100,
	})
	sel := lb.New(config.LBConfig{Strategy: "priority_rr", StickyTTLSec: 60})
	ex := &Executor{
		Store:     store,
		Selector:  sel,
		Upstream:  up,
		Refresher: passthroughRefresher{},
	}

	resp, err := ex.Post(context.Background(), "grok-4.5", "conv-1", []byte(`{"model":"grok-4.5","input":"hi"}`), false)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "resp_1") {
		t.Fatalf("body = %s", body)
	}
	if gotAuth != "Bearer access-token-a" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotModel != "grok-4.5" {
		t.Fatalf("model override = %q", gotModel)
	}
}

func TestExecutorPostFailoverOn429(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	keys := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		mu.Lock()
		hits[authz]++
		n := hits[authz]
		keys[authz] = r.Header.Get("Idempotency-Key")
		mu.Unlock()
		if strings.Contains(authz, "token-a") && n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "ok", "token": authz})
	}))
	t.Cleanup(srv.Close)

	up := upstream.NewClient(upstream.Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()})
	store := newMemStore(
		storage.Credential{ID: "cred_a", AccessToken: "token-a", Enabled: true, Priority: 200},
		storage.Credential{ID: "cred_b", AccessToken: "token-b", Enabled: true, Priority: 100},
	)
	ex := &Executor{
		Store:       store,
		Selector:    lb.New(config.LBConfig{Strategy: "priority_rr"}),
		Upstream:    up,
		Refresher:   passthroughRefresher{},
		MaxAttempts: 3,
	}
	resp, err := ex.Post(context.Background(), "grok-4.5", "", []byte(`{"model":"grok-4.5"}`), false)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "token-b") {
		t.Fatalf("expected failover to token-b, body=%s hits=%v", raw, hits)
	}
	if keys["Bearer token-a"] == "" || keys["Bearer token-a"] != keys["Bearer token-b"] {
		t.Fatalf("attempts must share an idempotency key: %v", keys)
	}
}

func TestExecutorPostFailoverOnPaymentRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "token-a") {
			w.WriteHeader(http.StatusPaymentRequired)
			_, _ = w.Write([]byte(`{"error":{"message":"quota exhausted"}}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"ok-from-b"}`))
	}))
	t.Cleanup(srv.Close)

	store := newMemStore(
		storage.Credential{ID: "cred_a", AccessToken: "token-a", Enabled: true, Priority: 200},
		storage.Credential{ID: "cred_b", AccessToken: "token-b", Enabled: true, Priority: 100},
	)
	ex := &Executor{
		Store:       store,
		Selector:    lb.New(config.LBConfig{Strategy: "priority_rr"}),
		Upstream:    upstream.NewClient(upstream.Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()}),
		Refresher:   passthroughRefresher{},
		MaxAttempts: 2,
	}
	resp, err := ex.Post(context.Background(), "grok-4.5", "", []byte(`{"model":"grok-4.5"}`), false)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "ok-from-b") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestExecutorDoesNotFailoverRegionalModelError(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"permission-denied","error":"The model grok-4.5 is not available in your region."}`))
	}))
	t.Cleanup(srv.Close)
	store := newMemStore(
		storage.Credential{ID: "cred_a", AccessToken: "token-a", Enabled: true, Priority: 200},
		storage.Credential{ID: "cred_b", AccessToken: "token-b", Enabled: true, Priority: 100},
	)
	ex := &Executor{
		Store: store, Selector: lb.New(config.LBConfig{Strategy: "priority_rr"}),
		Upstream:  upstream.NewClient(upstream.Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()}),
		Refresher: passthroughRefresher{}, MaxAttempts: 3,
	}
	resp, err := ex.Post(context.Background(), "grok-4.5", "", []byte(`{}`), false)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || hits.Load() != 1 {
		t.Fatalf("status=%d hits=%d", resp.StatusCode, hits.Load())
	}
}

func TestExecutorPreservesFinalUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"all accounts limited"}}`))
	}))
	t.Cleanup(srv.Close)
	store := newMemStore(storage.Credential{ID: "cred_a", AccessToken: "token-a", Enabled: true})
	ex := &Executor{
		Store:       store,
		Selector:    lb.New(config.LBConfig{Strategy: "priority_rr"}),
		Upstream:    upstream.NewClient(upstream.Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()}),
		Refresher:   passthroughRefresher{},
		MaxAttempts: 3,
	}
	resp, err := ex.Post(context.Background(), "grok-4.5", "", []byte(`{}`), false)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "7" {
		t.Fatalf("status=%d headers=%v", resp.StatusCode, resp.Header)
	}
	if !strings.Contains(string(raw), "all accounts limited") {
		t.Fatalf("body=%s", raw)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter("12"); d != 12*time.Second {
		t.Fatalf("got %v", d)
	}
	if d := parseRetryAfter(""); d != 0 {
		t.Fatalf("empty=%v", d)
	}
	now := time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC)
	if d := parseRetryAfterAt(now.Add(30*time.Second).Format(http.TimeFormat), now); d != 30*time.Second {
		t.Fatalf("date=%v", d)
	}
}
