// Package admin implements the local admin HTTP API for credentials and clients.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GreyGunG/grokbuild-proxy/internal/auth"
	"github.com/GreyGunG/grokbuild-proxy/internal/config"
	"github.com/GreyGunG/grokbuild-proxy/internal/storage"
	"github.com/GreyGunG/grokbuild-proxy/internal/upstream"
)

// Version is reported by GET /admin/system. Overridden by main via linker or SetVersion.
var Version = "dev"

// Store is the storage surface used by admin handlers.
type Store interface {
	ListCredentials() ([]storage.Credential, error)
	GetCredential(id string) (storage.Credential, error)
	CreateCredential(in storage.CreateCredentialInput) (storage.Credential, error)
	UpdateCredential(c storage.Credential) (storage.Credential, error)
	DeleteCredential(id string) error
	SetCredentialEnabled(id string, enabled bool) (storage.Credential, error)
	SetCredentialPriority(id string, priority int) (storage.Credential, error)
	ListClients() ([]storage.ClientKey, error)
	CreateClient(name string) (storage.CreateClientResult, error)
	DeleteClient(id string) error
}

type credentialUpserter interface {
	UpsertCredential(in storage.CreateCredentialInput) (storage.Credential, bool, error)
}

type credentialBulkUpserter interface {
	BulkUpsertCredentials([]storage.CreateCredentialInput) ([]storage.BulkUpsertResult, error)
}

type credentialExporter interface {
	ExportCredentialsJSON() ([]byte, error)
}

type backupCreator interface {
	CreateBackup() (storage.BackupInfo, error)
}

type storageStatsProvider interface {
	Stats() storage.Stats
}

// TokenService refreshes credentials and fetches billing.
type TokenService interface {
	ForceRefreshToken(ctx context.Context, credID string) (auth.TokenSet, storage.Credential, error)
	GetBillingSnapshot(ctx context.Context, credID string) (*upstream.BillingSnapshot, error)
}

// Handlers serves /admin/* endpoints.
type Handlers struct {
	Store  Store
	Tokens TokenService
	OAuth  DeviceOAuth
	Config config.Config
	// AdminKey is the plaintext admin bearer secret (process-local).
	AdminKey string
	// Version overrides package Version when non-empty.
	Version string
	// MaxBody limits JSON body size.
	MaxBody int64

	deviceMu       sync.Mutex
	deviceSessions map[string]deviceSession
	importMu       sync.Mutex
	importJobs     map[string]*ImportJob
	importCancels  map[string]context.CancelFunc
	importSem      chan struct{}
}

// maskedCredential is a credential view with secrets redacted.
type maskedCredential struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Email         string         `json:"email,omitempty"`
	UserID        string         `json:"user_id,omitempty"`
	TeamID        string         `json:"team_id,omitempty"`
	OIDCClientID  string         `json:"oidc_client_id,omitempty"`
	AccessToken   string         `json:"access_token"`  // masked
	RefreshToken  string         `json:"refresh_token"` // masked
	HasAccess     bool           `json:"has_access_token"`
	HasRefresh    bool           `json:"has_refresh_token"`
	ExpiresAt     time.Time      `json:"expires_at"`
	Enabled       bool           `json:"enabled"`
	Priority      int            `json:"priority"`
	FailureCount  int            `json:"failure_count"`
	CooldownUntil *time.Time     `json:"cooldown_until,omitempty"`
	LastError     string         `json:"last_error,omitempty"`
	LastUsedAt    *time.Time     `json:"last_used_at,omitempty"`
	LastSuccessAt *time.Time     `json:"last_success_at,omitempty"`
	Billing       map[string]any `json:"billing,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

func maskCredential(c storage.Credential) maskedCredential {
	return maskedCredential{
		ID:            c.ID,
		Name:          c.Name,
		Email:         c.Email,
		UserID:        c.UserID,
		TeamID:        c.TeamID,
		OIDCClientID:  c.OIDCClientID,
		AccessToken:   maskSecret(c.AccessToken),
		RefreshToken:  maskSecret(c.RefreshToken),
		HasAccess:     strings.TrimSpace(c.AccessToken) != "",
		HasRefresh:    strings.TrimSpace(c.RefreshToken) != "",
		ExpiresAt:     c.ExpiresAt,
		Enabled:       c.Enabled,
		Priority:      c.Priority,
		FailureCount:  c.FailureCount,
		CooldownUntil: c.CooldownUntil,
		LastError:     c.LastError,
		LastUsedAt:    c.LastUsedAt,
		LastSuccessAt: c.LastSuccessAt,
		Billing:       c.Billing,
		CreatedAt:     c.CreatedAt,
		UpdatedAt:     c.UpdatedAt,
	}
}

// maskSecret never returns the full secret. Empty → empty; short → "***"; long → redacted.
// Only tokens longer than 24 chars expose a tiny fingerprint (2+2); never full short secrets.
func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= 24 {
		return "***"
	}
	return s[:2] + "***" + s[len(s)-2:]
}

func (h *Handlers) maxBody() int64 {
	if h != nil && h.MaxBody > 0 {
		return h.MaxBody
	}
	return 1 << 20
}

func (h *Handlers) maxImportBody() int64 {
	if h != nil && h.Config.Limits.MaxImportBytes > 0 {
		return h.Config.Limits.MaxImportBytes
	}
	return h.maxBody()
}

func (h *Handlers) version() string {
	if h != nil && h.Version != "" {
		return h.Version
	}
	return Version
}

// RequireAdmin is middleware that accepts only Authorization: Bearer <admin_key>.
func (h *Handlers) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h == nil || strings.TrimSpace(h.AdminKey) == "" {
			writeErr(w, http.StatusServiceUnavailable, "admin key not configured")
			return
		}
		got := bearerToken(r)
		if got == "" || !subtleConstantTimeEq(got, h.AdminKey) {
			writeErr(w, http.StatusUnauthorized, "invalid admin key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) >= 7 && strings.EqualFold(authz[:7], "Bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	// Also accept x-admin-key for convenience.
	if v := strings.TrimSpace(r.Header.Get("X-Admin-Key")); v != "" {
		return v
	}
	return ""
}

func subtleConstantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ListCredentials GET /admin/credentials
func (h *Handlers) ListCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := h.Store.ListCredentials()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	statusFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if query != "" || statusFilter != "" {
		now := time.Now()
		filtered := make([]storage.Credential, 0, len(creds))
		for _, credential := range creds {
			if query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{
				credential.ID, credential.Name, credential.Email, credential.UserID, credential.TeamID,
			}, " ")), query) {
				continue
			}
			cooling := credential.CooldownUntil != nil && credential.CooldownUntil.After(now)
			switch statusFilter {
			case "enabled":
				if !credential.Enabled {
					continue
				}
			case "disabled":
				if credential.Enabled {
					continue
				}
			case "cooling":
				if !credential.Enabled || !cooling {
					continue
				}
			case "available":
				if !credential.Enabled || cooling {
					continue
				}
			}
			filtered = append(filtered, credential)
		}
		creds = filtered
	}
	limit := queryInt(r, "limit", 100, 1, 1000)
	offset := queryInt(r, "offset", 0, 0, len(creds))
	end := offset + limit
	if end > len(creds) {
		end = len(creds)
	}
	out := make([]maskedCredential, 0, end-offset)
	for _, c := range creds[offset:end] {
		out = append(out, maskCredential(c))
	}
	nextOffset := 0
	if end < len(creds) {
		nextOffset = end
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credentials": out, "total": len(creds), "offset": offset,
		"limit": limit, "next_offset": nextOffset,
	})
}

// CreateCredential POST /admin/credentials
func (h *Handlers) CreateCredential(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name         string `json:"name"`
		Email        string `json:"email"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    string `json:"expires_at"`
		Priority     *int   `json:"priority"`
		Enabled      *bool  `json:"enabled"`
		OIDCClientID string `json:"oidc_client_id"`
		UserID       string `json:"user_id"`
		TeamID       string `json:"team_id"`
	}
	if err := decodeJSON(r, h.maxBody(), &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var exp time.Time
	if strings.TrimSpace(body.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, body.ExpiresAt)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		exp = t
	}
	created, err := h.Store.CreateCredential(storage.CreateCredentialInput{
		Name:         body.Name,
		Email:        body.Email,
		UserID:       body.UserID,
		TeamID:       body.TeamID,
		OIDCClientID: body.OIDCClientID,
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
		ExpiresAt:    exp,
		Enabled:      body.Enabled,
		Priority:     body.Priority,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, maskCredential(created))
}

// ExportCredentials GET /admin/credentials/export returns a portable secret
// snapshot. The admin bearer key is required by the enclosing router.
func (h *Handlers) ExportCredentials(w http.ResponseWriter, r *http.Request) {
	exporter, ok := h.Store.(credentialExporter)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "credential export unavailable")
		return
	}
	raw, err := exporter.ExportCredentialsJSON()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="grokbuild-credentials.json"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// ImportGrok POST /admin/credentials/import-grok
// Prefer body.raw JSON. path is optional and jailed to ~/.grok or data_dir.
func (h *Handlers) ImportGrok(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string          `json:"path"`
		Raw  json.RawMessage `json:"raw"`
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))), "multipart/form-data") {
		raw, err := readMultipartJSONFile(w, r, h.maxImportBody())
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		body.Raw = raw
	} else {
		// Body is optional; empty body → default path. Malformed JSON is 400 (not silent fallback).
		if err := decodeJSON(r, h.maxImportBody(), &body); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	var imported []auth.ImportedCredential
	var err error
	if len(body.Raw) > 0 {
		imported, err = auth.ParseGrokAuthJSON(body.Raw)
	} else {
		path := strings.TrimSpace(body.Path)
		var extraRoots []string
		if h != nil && strings.TrimSpace(h.Config.DataDir) != "" {
			extraRoots = append(extraRoots, h.Config.DataDir)
		}
		imported, err = auth.ImportGrokAuthFile(path, extraRoots...)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if queryBool(r, "async") {
		job := h.startImportJob(imported)
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
		return
	}
	outcome, persistErr := h.persistImported(imported)
	if persistErr != nil {
		writeErr(w, http.StatusInternalServerError, persistErr.Error())
		return
	}
	writeJSON(w, outcome.httpStatus(), outcome)
}

func readMultipartJSONFile(w http.ResponseWriter, r *http.Request, max int64) (json.RawMessage, error) {
	if r == nil || r.Body == nil {
		return nil, fmt.Errorf("missing body")
	}
	if max <= 0 {
		return nil, fmt.Errorf("invalid upload limit")
	}
	r.Body = http.MaxBytesReader(w, r.Body, max+(1<<20))
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, fmt.Errorf("invalid multipart upload: %w", err)
	}
	for {
		part, nextErr := reader.NextPart()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nil, fmt.Errorf("invalid multipart upload: %w", nextErr)
		}
		if part.FormName() != "file" {
			_ = part.Close()
			continue
		}
		name := strings.TrimSpace(part.FileName())
		if name == "" || !strings.HasSuffix(strings.ToLower(name), ".json") {
			_ = part.Close()
			return nil, fmt.Errorf("uploaded file must be a .json file")
		}
		raw, readErr := io.ReadAll(io.LimitReader(part, max+1))
		_ = part.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read uploaded file: %w", readErr)
		}
		if int64(len(raw)) > max {
			return nil, fmt.Errorf("uploaded file too large")
		}
		if len(strings.TrimSpace(string(raw))) == 0 {
			return nil, fmt.Errorf("uploaded file is empty")
		}
		if !json.Valid(raw) {
			return nil, fmt.Errorf("uploaded file contains invalid json")
		}
		return json.RawMessage(raw), nil
	}
	return nil, fmt.Errorf("multipart upload is missing file field")
}

// DisableCredential POST /admin/credentials/{id}/disable
func (h *Handlers) DisableCredential(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Enabled *bool `json:"enabled"`
		Disable *bool `json:"disable"`
	}
	_ = decodeJSON(r, h.maxBody(), &body)

	enabled := false
	if body.Enabled != nil {
		enabled = *body.Enabled
	} else if body.Disable != nil {
		enabled = !*body.Disable
	} else {
		// Toggle when no body fields.
		cur, err := h.Store.GetCredential(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		enabled = !cur.Enabled
	}
	updated, err := h.Store.SetCredentialEnabled(id, enabled)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, maskCredential(updated))
}

// SetPriority PUT /admin/credentials/{id}/priority
func (h *Handlers) SetPriority(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Priority int `json:"priority"`
	}
	if err := decodeJSON(r, h.maxBody(), &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := h.Store.SetCredentialPriority(id, body.Priority)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, maskCredential(updated))
}

// RefreshCredential POST /admin/credentials/{id}/refresh
func (h *Handlers) RefreshCredential(w http.ResponseWriter, r *http.Request, id string) {
	if h.Tokens == nil {
		writeErr(w, http.StatusServiceUnavailable, "token service not configured")
		return
	}
	_, cred, err := h.Tokens.ForceRefreshToken(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, maskCredential(cred))
}

// CredentialBilling GET /admin/credentials/{id}/billing
func (h *Handlers) CredentialBilling(w http.ResponseWriter, r *http.Request, id string) {
	if h.Tokens == nil {
		writeErr(w, http.StatusServiceUnavailable, "token service not configured")
		return
	}
	snap, err := h.Tokens.GetBillingSnapshot(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// DeleteCredential DELETE /admin/credentials/{id}
func (h *Handlers) DeleteCredential(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.Store.DeleteCredential(id); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// ListClients GET /admin/clients
func (h *Handlers) ListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.Store.ListClients()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

// CreateClient POST /admin/clients
func (h *Handlers) CreateClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	_ = decodeJSON(r, h.maxBody(), &body)
	res, err := h.Store.CreateClient(body.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client":    res.Client,
		"plaintext": res.Plaintext,
		"api_key":   res.Plaintext,
	})
}

// DeleteClient DELETE /admin/clients/{id}
func (h *Handlers) DeleteClient(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.Store.DeleteClient(id); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// System GET /admin/system
func (h *Handlers) System(w http.ResponseWriter, r *http.Request) {
	credentials, err := h.Store.ListCredentials()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "credential store unavailable")
		return
	}
	response := map[string]any{
		"version": h.version(),
		"listen":  h.Config.Listen,
		"upstream": map[string]any{
			"base_url":          h.Config.Upstream.BaseURL,
			"client_version":    h.Config.Upstream.ClientVersion,
			"client_identifier": h.Config.Upstream.ClientIdentifier,
			"user_agent":        h.Config.Upstream.UserAgent,
			"token_auth":        h.Config.Upstream.TokenAuth,
		},
		"data_dir":     h.Config.DataDir,
		"chat_backend": h.Config.ChatBackend,
		"anthropic": map[string]any{
			"enabled": h.Config.Anthropic.Enabled,
		},
		"limits": h.Config.Limits,
		"pool":   summarizePool(credentials, time.Now()),
	}
	if provider, ok := h.Store.(storageStatsProvider); ok {
		response["storage"] = provider.Stats()
	}
	writeJSON(w, http.StatusOK, response)
}

// CreateBackup POST /admin/system/backup creates a verified online snapshot.
func (h *Handlers) CreateBackup(w http.ResponseWriter, r *http.Request) {
	creator, ok := h.Store.(backupCreator)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "backup unavailable")
		return
	}
	backup, err := creator.CreateBackup()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"backup": backup})
}

func queryInt(r *http.Request, key string, fallback, minimum, maximum int) int {
	if r == nil {
		return fallback
	}
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < minimum {
		return fallback
	}
	if maximum >= minimum && n > maximum {
		return maximum
	}
	return n
}

func decodeJSON(r *http.Request, max int64, dest any) error {
	if r == nil || r.Body == nil {
		return fmt.Errorf("missing body")
	}
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, max+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(raw)) > max {
		return fmt.Errorf("request body too large")
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    "admin_error",
			"code":    status,
		},
	})
}
