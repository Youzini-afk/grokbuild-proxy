package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/GreyGunG/grokbuild-proxy/internal/runtimecfg"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
	"github.com/GreyGunG/grokbuild-proxy/internal/upstream"
)

type memStore struct {
	mu      sync.Mutex
	creds   map[string]storage.Credential
	patches int
	events  []storage.CallEvent
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

func (m *memStore) RecordCredentialCall(event storage.CallEvent) {
	m.mu.Lock()
	m.events = append(m.events, event)
	m.mu.Unlock()
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
	store.mu.Lock()
	events := append([]storage.CallEvent(nil), store.events...)
	store.mu.Unlock()
	if len(events) != 1 || !events[0].Success || events[0].Model != "grok-4.5" || events[0].Status != 200 {
		t.Fatalf("usage events=%+v", events)
	}
}

func TestExecutorPersistentStoreUsageIsImmediatelyVisible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_persisted","status":"completed"}`))
	}))
	t.Cleanup(srv.Close)

	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	credential, err := store.CreateCredential(storage.CreateCredentialInput{
		UserID: "persistent-usage-user", AccessToken: "access-token", RefreshToken: "refresh-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if credential.ID == "" {
		t.Fatal("created credential has no id")
	}

	executor := &Executor{
		Store:     store,
		Selector:  lb.New(config.LBConfig{Strategy: "priority_rr"}),
		Upstream:  upstream.NewClient(upstream.Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()}),
		Refresher: passthroughRefresher{},
	}
	resp, err := executor.Post(context.Background(), "grok-4.5", "", []byte(`{"model":"grok-4.5","input":"hello"}`), false)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	summary, err := store.UsageSummaryHours(24)
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalCount != 1 || summary.SuccessCount != 1 || summary.ActiveAccounts != 1 {
		t.Fatalf("usage summary immediately after request=%+v", summary)
	}
	usage := store.CredentialUsage(credential.ID)
	if usage.TotalCount != 1 || usage.LastStatus != http.StatusOK || usage.LastModel != "grok-4.5" {
		t.Fatalf("credential usage=%+v", usage)
	}
}

func TestExecutorUsesRuntimeMaxAttempts(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporary"}`))
	}))
	t.Cleanup(srv.Close)

	credentials := make([]storage.Credential, 5)
	for i := range credentials {
		credentials[i] = storage.Credential{
			ID: fmt.Sprintf("cred-runtime-%d", i), AccessToken: fmt.Sprintf("access-%d", i),
			Enabled: true, Priority: 100,
		}
	}
	settings, err := runtimecfg.New(nil, runtimecfg.Defaults(config.Default()))
	if err != nil {
		t.Fatal(err)
	}
	next := settings.Get()
	next.MaxAttempts = 5
	if err := settings.Update(next); err != nil {
		t.Fatal(err)
	}
	executor := &Executor{
		Store: newMemStore(credentials...), Selector: lb.New(config.Default().LB),
		Upstream:  upstream.NewClient(upstream.Config{BaseURL: srv.URL + "/v1", HTTPClient: srv.Client()}),
		Refresher: passthroughRefresher{}, MaxAttempts: 1, RuntimeSettings: settings,
	}
	resp, err := executor.Post(context.Background(), "grok-4.5", "", []byte(`{"model":"grok-4.5"}`), false)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := calls.Load(); got != 5 {
		t.Fatalf("upstream calls=%d want 5", got)
	}
}

func TestClassifyKnownGrokCredentialFailures(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		want     lb.FailureClass
		wantCode string
	}{
		{
			name: "bad credentials", status: http.StatusUnauthorized,
			body: `{"code":"unauthenticated:bad-credentials","error":"The OAuth2 access token could not be validated."}`,
			want: lb.FailureAuth, wantCode: "unauthenticated:bad-credentials",
		},
		{
			name: "spending limit", status: http.StatusForbidden,
			body: `{"code":"personal-team-blocked:spending-limit","error":"You have run out of credits or need a Grok subscription."}`,
			want: lb.FailureQuota, wantCode: "personal-team-blocked:spending-limit",
		},
		{
			name: "nested rate limit", status: http.StatusTooManyRequests,
			body: `{"error":{"code":"rate-limit","message":"slow down"}}`,
			want: lb.FailureRateLimit, wantCode: "rate-limit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: test.status, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(test.body)),
			}
			signal, regional := classifyUpstreamFailure(response, 0)
			if regional || signal.Class != test.want || signal.Code != test.wantCode {
				t.Fatalf("signal=%+v regional=%v", signal, regional)
			}
			restored, err := io.ReadAll(response.Body)
			if err != nil || string(restored) != test.body {
				t.Fatalf("response body was not restored: %q err=%v", restored, err)
			}
		})
	}
}

func TestClassifyTokenRefreshFailureSeparatesInvalidGrantFromOutage(t *testing.T) {
	authFailure := classifyTokenRefreshFailure(errors.New(`auth token: status 400: {"error":"invalid_grant"}`))
	if authFailure.Class != lb.FailureAuth || authFailure.Status != http.StatusUnauthorized {
		t.Fatalf("invalid grant signal=%+v", authFailure)
	}
	transient := classifyTokenRefreshFailure(errors.New("auth token: request: i/o timeout"))
	if transient.Class != lb.FailureTransient || transient.Status != 0 {
		t.Fatalf("network signal=%+v", transient)
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
