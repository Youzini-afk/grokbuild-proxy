package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GrokAuthEntry is one credential entry inside ~/.grok/auth.json.
// The CLI stores entries keyed by "https://auth.x.ai::<client_id>".
type GrokAuthEntry struct {
	// Key is the access JWT (CLI field name).
	Key           string `json:"key"`
	AuthMode      string `json:"auth_mode,omitempty"`
	CreateTime    string `json:"create_time,omitempty"`
	UserID        string `json:"user_id,omitempty"`
	Email         string `json:"email,omitempty"`
	FirstName     string `json:"first_name,omitempty"`
	ProfileImage  string `json:"profile_image_asset_id,omitempty"`
	PrincipalType string `json:"principal_type,omitempty"`
	PrincipalID   string `json:"principal_id,omitempty"`
	TeamID        string `json:"team_id,omitempty"`
	CodingOptOut  bool   `json:"coding_data_retention_opt_out,omitempty"`
	RefreshToken  string `json:"refresh_token"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	OIDCIssuer    string `json:"oidc_issuer,omitempty"`
	OIDCClientID  string `json:"oidc_client_id,omitempty"`
}

// ImportedCredential is a normalized credential produced from auth.json.
type ImportedCredential struct {
	// SourceKey is the map key in auth.json (issuer::client_id).
	SourceKey    string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Email        string
	UserID       string
	TeamID       string
	OIDCIssuer   string
	OIDCClientID string
	AuthMode     string
	Raw          GrokAuthEntry
}

// DefaultGrokAuthPath returns ~/.grok/auth.json.
func DefaultGrokAuthPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".grok", "auth.json")
	}
	return filepath.Join(home, ".grok", "auth.json")
}

// DefaultGrokAuthDir returns ~/.grok (import path jail root).
func DefaultGrokAuthDir() string {
	return filepath.Dir(DefaultGrokAuthPath())
}

// ResolveGrokAuthPath validates and resolves a path for reading Grok auth files.
// Empty path → DefaultGrokAuthPath(). Non-empty paths must resolve inside allowed roots
// (default: ~/.grok; optional extraRoots, e.g. proxy data_dir).
func ResolveGrokAuthPath(path string, extraRoots ...string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultGrokAuthPath()
	}
	// Reject null bytes before Abs.
	if strings.Contains(path, "\x00") {
		return "", fmt.Errorf("import grok auth: invalid path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("import grok auth: resolve path: %w", err)
	}
	// Resolve symlinks when the path exists so jail checks use the real target.
	// Empty/default paths go through the same checks (no symlink escape from ~/.grok).
	resolved := abs
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		resolved = real
	} else if !os.IsNotExist(err) {
		// Keep abs when target is missing (ReadFile will fail later with a clean error).
		// Other eval errors (permission) still use abs for allowlist check.
	}

	roots := make([]string, 0, 1+len(extraRoots))
	// Eval default root when possible so jail matches realpath of ~/.grok.
	defRoot := DefaultGrokAuthDir()
	if ar, err := filepath.Abs(defRoot); err == nil {
		defRoot = ar
		if real, err := filepath.EvalSymlinks(ar); err == nil {
			defRoot = real
		}
	}
	roots = append(roots, defRoot)
	for _, r := range extraRoots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		ar, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		if real, err := filepath.EvalSymlinks(ar); err == nil {
			ar = real
		}
		roots = append(roots, ar)
	}

	if !pathUnderAnyRoot(resolved, roots) {
		return "", fmt.Errorf("import grok auth: path not allowed (must be under ~/.grok or data_dir)")
	}
	return resolved, nil
}

func pathUnderAnyRoot(path string, roots []string) bool {
	clean := filepath.Clean(path)
	for _, root := range roots {
		root = filepath.Clean(root)
		if root == "" {
			continue
		}
		// Exact root match (directory itself) is not a file we want, but keep prefix rule.
		if clean == root {
			return true
		}
		prefix := root + string(os.PathSeparator)
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}

// ImportGrokAuthFile reads and parses a Grok CLI auth.json file.
// Empty path uses DefaultGrokAuthPath(). Paths outside ~/.grok (and optional extraRoots) are rejected.
func ImportGrokAuthFile(path string, extraRoots ...string) ([]ImportedCredential, error) {
	resolved, err := ResolveGrokAuthPath(path, extraRoots...)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		// Avoid echoing absolute path details beyond basename for missing/denied files.
		return nil, fmt.Errorf("import grok auth: read failed: %w", err)
	}
	return ParseGrokAuthJSON(data)
}

// ParseGrokAuthJSON parses the Grok CLI auth.json document.
//
// Accepted shapes:
//  1. Map keyed by "issuer::client_id" → entry (canonical CLI shape)
//  2. Single entry object with key/refresh_token fields
//  3. {"accounts":[...]} or {"credentials":[...]} arrays of entries
func ParseGrokAuthJSON(data []byte) ([]ImportedCredential, error) {
	data = bytesTrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("import grok auth: empty document")
	}

	// Shape 1: map of entries.
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &asMap); err == nil && looksLikeAuthMap(asMap) {
		out := make([]ImportedCredential, 0, len(asMap))
		for k, raw := range asMap {
			// Skip non-entry top-level keys if mixed.
			var entry GrokAuthEntry
			if err := json.Unmarshal(raw, &entry); err != nil {
				continue
			}
			if strings.TrimSpace(entry.Key) == "" && strings.TrimSpace(entry.RefreshToken) == "" {
				continue
			}
			cred, err := normalizeEntry(k, entry)
			if err != nil {
				return nil, err
			}
			out = append(out, cred)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("import grok auth: no credential entries found")
		}
		return out, nil
	}

	// Shape 3: wrapper with arrays.
	var wrapper struct {
		Accounts    []GrokAuthEntry `json:"accounts"`
		Credentials []GrokAuthEntry `json:"credentials"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil {
		entries := wrapper.Accounts
		if len(entries) == 0 {
			entries = wrapper.Credentials
		}
		if len(entries) > 0 {
			out := make([]ImportedCredential, 0, len(entries))
			for i, entry := range entries {
				cred, err := normalizeEntry(fmt.Sprintf("entry[%d]", i), entry)
				if err != nil {
					return nil, err
				}
				// Array positions repeat in every import document and therefore are
				// labels, not stable account identities. Persisting entry[0], entry[1],
				// ... as source keys can overwrite unrelated accounts in later batches.
				cred.SourceKey = ""
				out = append(out, cred)
			}
			return out, nil
		}
	}

	// Shape 2: bare entry.
	var entry GrokAuthEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("import grok auth: parse: %w", err)
	}
	if strings.TrimSpace(entry.Key) == "" && strings.TrimSpace(entry.RefreshToken) == "" {
		return nil, fmt.Errorf("import grok auth: missing key/refresh_token")
	}
	cred, err := normalizeEntry("default", entry)
	if err != nil {
		return nil, err
	}
	// "default" is shared by every bare-entry document and is not an identity.
	cred.SourceKey = ""
	return []ImportedCredential{cred}, nil
}

// ToTokenSet converts an imported credential into a TokenSet.
func (c ImportedCredential) ToTokenSet() TokenSet {
	return TokenSet{
		AccessToken:  c.AccessToken,
		RefreshToken: c.RefreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    c.ExpiresAt,
	}
}

func normalizeEntry(sourceKey string, entry GrokAuthEntry) (ImportedCredential, error) {
	access := strings.TrimSpace(entry.Key)
	refresh := strings.TrimSpace(entry.RefreshToken)
	if access == "" && refresh == "" {
		return ImportedCredential{}, fmt.Errorf("import grok auth: entry %q has no tokens", sourceKey)
	}
	var exp time.Time
	if strings.TrimSpace(entry.ExpiresAt) != "" {
		t, err := parseFlexibleTime(entry.ExpiresAt)
		if err != nil {
			return ImportedCredential{}, fmt.Errorf("import grok auth: entry %q expires_at: %w", sourceKey, err)
		}
		exp = t
	}
	clientID := strings.TrimSpace(entry.OIDCClientID)
	issuer := strings.TrimSpace(entry.OIDCIssuer)
	if clientID == "" || issuer == "" {
		// Try parse from map key: https://auth.x.ai::b1a00492-...
		if iss, cid, ok := splitSourceKey(sourceKey); ok {
			if issuer == "" {
				issuer = iss
			}
			if clientID == "" {
				clientID = cid
			}
		}
	}
	if issuer == "" {
		issuer = Issuer
	}
	if clientID == "" {
		clientID = DefaultClientID
	}
	return ImportedCredential{
		SourceKey:    sourceKey,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    exp,
		Email:        strings.TrimSpace(entry.Email),
		UserID:       firstNonEmpty(strings.TrimSpace(entry.UserID), strings.TrimSpace(entry.PrincipalID)),
		TeamID:       strings.TrimSpace(entry.TeamID),
		OIDCIssuer:   issuer,
		OIDCClientID: clientID,
		AuthMode:     strings.TrimSpace(entry.AuthMode),
		Raw:          entry,
	}, nil
}

func looksLikeAuthMap(m map[string]json.RawMessage) bool {
	if len(m) == 0 {
		return false
	}
	// Prefer keys that look like issuer::client_id, or values that look like entries.
	for k, raw := range m {
		if strings.Contains(k, "::") {
			return true
		}
		var probe struct {
			Key          string `json:"key"`
			RefreshToken string `json:"refresh_token"`
		}
		if json.Unmarshal(raw, &probe) == nil && (probe.Key != "" || probe.RefreshToken != "") {
			return true
		}
	}
	return false
}

func splitSourceKey(key string) (issuer, clientID string, ok bool) {
	// Format: https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828
	parts := strings.SplitN(key, "::", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	issuer = strings.TrimSpace(parts[0])
	clientID = strings.TrimSpace(parts[1])
	if issuer == "" || clientID == "" {
		return "", "", false
	}
	return issuer, clientID, true
}

func parseFlexibleTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
	}
	var last error
	for _, layout := range layouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t.UTC(), nil
		}
		last = err
	}
	return time.Time{}, last
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
