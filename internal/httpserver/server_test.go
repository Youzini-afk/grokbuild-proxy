package httpserver

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/admin"
	"github.com/GreyGunG/grokbuild-proxy/internal/anthropic"
	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/runtimecfg"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
)

type stubClientStore struct {
	keys map[string]storage.ClientKey
}

func (s stubClientStore) LookupClientByPlaintext(plaintext string) (storage.ClientKey, bool, error) {
	if s.keys == nil {
		return storage.ClientKey{}, false, nil
	}
	c, ok := s.keys[plaintext]
	return c, ok, nil
}

func TestMiddlewareRejectsMissingKey(t *testing.T) {
	opts := Options{
		Config:   config.Default(),
		AdminKey: "sk-admin-good",
		Store:    stubClientStore{},
	}
	h := New(opts)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "missing api key") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestAnthropicAuthErrorUsesAnthropicEnvelope(t *testing.T) {
	h := New(Options{
		Config:    config.Default(),
		Store:     stubClientStore{},
		Anthropic: &anthropic.Handlers{},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var env anthropic.ErrorEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != "error" || env.Error.Type != "authentication_error" {
		t.Fatalf("envelope=%+v", env)
	}
}

func TestMiddlewareRejectsAdminKeyAsClient(t *testing.T) {
	opts := Options{
		Config:   config.Default(),
		AdminKey: "sk-admin-good",
		Store:    stubClientStore{},
	}
	h := New(opts)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-admin-good")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareAcceptsAPIKey(t *testing.T) {
	cfg := config.Default()
	cfg.Anthropic.Enabled = true
	opts := Options{
		Config:   cfg,
		AdminKey: "sk-admin-good",
		Store: stubClientStore{keys: map[string]storage.ClientKey{
			"sk-api-good": {ID: "client-test"},
		}},
	}
	h := New(opts)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-api-good")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "object") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestHealthzNoAuth(t *testing.T) {
	h := New(Options{
		Config: config.Default(),
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "ok" {
		t.Fatalf("body=%q", rr.Body.String())
	}
}

func TestReadinessMetricsAndRequestID(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var logs bytes.Buffer
	metrics := &Metrics{}
	h := New(Options{
		Config:  config.Default(),
		Store:   store,
		Metrics: metrics,
		Logger:  slog.New(slog.NewJSONHandler(&logs, nil)),
	})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("X-Request-Id", "contract-ready-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty readiness status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("X-Request-Id") != "contract-ready-1" {
		t.Fatalf("request id=%q", rr.Header().Get("X-Request-Id"))
	}

	created, err := store.CreateCredential(storage.CreateCredentialInput{
		Name:         "ready",
		AccessToken:  "access",
		RefreshToken: "refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("ready status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := store.PatchCredential(created.ID, func(c *storage.Credential) error {
		c.RefreshToken = ""
		c.ExpiresAt = time.Now().Add(-time.Minute)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expired readiness status=%d body=%s", rr.Code, rr.Body.String())
	}

	metricsRR := httptest.NewRecorder()
	h.ServeHTTP(metricsRR, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metricsRR.Body.String(), "grokbuild_http_requests_total") {
		t.Fatalf("metrics=%s", metricsRR.Body.String())
	}
	if !strings.Contains(logs.String(), `"route":"/readyz"`) ||
		!strings.Contains(logs.String(), `"request_id":"contract-ready-1"`) {
		t.Fatalf("structured logs=%s", logs.String())
	}
}

func TestMetricsCanRequireAdminAndChangeAtRuntime(t *testing.T) {
	settings, err := runtimecfg.New(nil, runtimecfg.Defaults(config.Default()))
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Config: config.Default(), AdminKey: "admin-secret", RuntimeSettings: settings})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("private metrics status=%d body=%s", rr.Code, rr.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "grokbuild_http_requests_total") {
		t.Fatalf("authenticated metrics status=%d body=%s", rr.Code, rr.Body.String())
	}

	next := settings.Get()
	next.MetricsPublic = true
	if err := settings.Update(next); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("public metrics status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestXAPIKeyHeader(t *testing.T) {
	opts := Options{
		Config: config.Default(),
		Store: stubClientStore{keys: map[string]storage.ClientKey{
			"sk-from-header": {ID: "client-test"},
		}},
	}
	h := New(opts)
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("x-api-key", "sk-from-header")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestBootstrapClientCanBeRevoked(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	apiKey, _, _, _, err := store.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	clients, err := store.ListClients()
	if err != nil || len(clients) != 1 {
		t.Fatalf("clients=%d err=%v", len(clients), err)
	}

	h := New(Options{Config: config.Default(), Store: store})
	request := func() int {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if got := request(); got != http.StatusOK {
		t.Fatalf("before revoke status=%d", got)
	}
	if _, err := store.SetClientDisabled(clients[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if got := request(); got != http.StatusUnauthorized {
		t.Fatalf("after revoke status=%d", got)
	}
}

func TestAdminUIServesLoginWithoutAuth(t *testing.T) {
	h := New(Options{
		Config:   config.Default(),
		AdminKey: "sk-admin-good",
		Admin:    &admin.Handlers{},
	})

	for _, path := range []string{"/admin", "/admin/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
		ct := rr.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Fatalf("%s Content-Type=%q want text/html", path, ct)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "html") && !strings.Contains(body, "Admin") {
			t.Fatalf("%s body missing admin UI marker", path)
		}
	}
}

func TestAdminAPIStillRequiresAuth(t *testing.T) {
	h := New(Options{
		Config:   config.Default(),
		AdminKey: "sk-admin-good",
		Admin:    &admin.Handlers{},
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/system", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s want 401", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("API must not return HTML, got Content-Type=%q", rr.Header().Get("Content-Type"))
	}
}

func TestAdminUIAssetsServedWithoutAuth(t *testing.T) {
	h := New(Options{Config: config.Default()})

	req := httptest.NewRequest(http.MethodGet, "/admin/ui/app.js", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "javascript") {
		t.Fatalf("Content-Type=%q want javascript", ct)
	}
	if rr.Body.Len() == 0 {
		t.Fatal("empty app.js body")
	}
}

func TestCredentialsNotServedAsHTML(t *testing.T) {
	h := New(Options{
		Config:   config.Default(),
		AdminKey: "sk-admin-good",
		Admin:    &admin.Handlers{},
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/credentials", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s want 401", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "<!DOCTYPE html>") || strings.Contains(body, "<html") {
		t.Fatal("GET /admin/credentials must not return SPA HTML")
	}
}
