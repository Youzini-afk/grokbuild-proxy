package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrNoSupportedCredential identifies a valid JSON document that contains no
// Grok/xAI credential. Bundle imports may safely skip these files.
var ErrNoSupportedCredential = errors.New("no supported Grok/CPA/sub2api credential entries")

var ErrRawSSORequiresExchange = errors.New("raw SSO cookies require OAuth exchange before import")

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
	Name         string
	Enabled      *bool
	Priority     *int
	Raw          GrokAuthEntry
}

// cpaAuthEntry is the common CPA/sub2api xAI OAuth credential shape.
type cpaAuthEntry struct {
	Type          string         `json:"type"`
	AccessToken   string         `json:"access_token"`
	RefreshToken  string         `json:"refresh_token"`
	IDToken       string         `json:"id_token"`
	AuthKind      string         `json:"auth_kind"`
	LastRefresh   string         `json:"last_refresh"`
	Expired       stringOrNumber `json:"expired"`
	ExpiresAt     stringOrNumber `json:"expires_at"`
	Email         string         `json:"email"`
	Sub           string         `json:"sub"`
	UserID        string         `json:"user_id"`
	TeamID        string         `json:"team_id"`
	PrincipalID   string         `json:"principal_id"`
	PrincipalType string         `json:"principal_type"`
	OIDCIssuer    string         `json:"oidc_issuer"`
	OIDCClientID  string         `json:"oidc_client_id"`
	Disabled      *bool          `json:"disabled"`
}

// stringOrNumber accepts the two timestamp encodings found in CPA exports:
// RFC3339 strings and JSON Unix numbers. Keeping the original lexical value
// lets parseFlexibleTime handle seconds, milliseconds, microseconds and
// nanoseconds without losing integer precision during JSON decoding.
type stringOrNumber string

func (value *stringOrNumber) UnmarshalJSON(raw []byte) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		*value = ""
		return nil
	}
	if strings.HasPrefix(trimmed, `"`) {
		var decoded string
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return err
		}
		*value = stringOrNumber(decoded)
		return nil
	}
	if _, err := strconv.ParseFloat(trimmed, 64); err != nil {
		return fmt.Errorf("must be a timestamp string or number")
	}
	*value = stringOrNumber(trimmed)
	return nil
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

// ParseGrokAuthJSON parses canonical Grok auth, CPA type=xai, and sub2api
// credential documents. Arrays and accounts[].credentials wrappers are
// accepted and normalized into one credential representation.
func ParseGrokAuthJSON(data []byte) ([]ImportedCredential, error) {
	data = bytesTrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("import grok auth: empty document")
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("import grok auth: parse: %w", err)
	}
	out, err := parseCredentialNode(document, "", true)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		if root, ok := document.(map[string]any); ok {
			if _, rawSSO := root["ssoBasic"]; rawSSO {
				return nil, fmt.Errorf("import grok auth: %w", ErrRawSSORequiresExchange)
			}
		}
		return nil, fmt.Errorf("import grok auth: %w", ErrNoSupportedCredential)
	}
	return DeduplicateImportedCredentials(out), nil
}

func parseCredentialNode(node any, sourceKey string, root bool) ([]ImportedCredential, error) {
	switch value := node.(type) {
	case []any:
		out := make([]ImportedCredential, 0, len(value))
		for _, item := range value {
			parsed, err := parseCredentialNode(item, "", false)
			if err != nil {
				return nil, err
			}
			out = append(out, parsed...)
		}
		return out, nil
	case map[string]any:
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("import grok auth: normalize object: %w", err)
		}
		_, hasAccessToken := value["access_token"]
		if hasAccessToken || strings.EqualFold(stringValue(value["type"]), "xai") {
			credential, supported, normalizeErr := normalizeCPAEntry(raw)
			if normalizeErr != nil {
				return nil, normalizeErr
			}
			if supported {
				credential.SourceKey = sourceKey
				return []ImportedCredential{credential}, nil
			}
		}
		_, hasKey := value["key"]
		_, hasRefreshToken := value["refresh_token"]
		if hasKey || (hasRefreshToken && !hasAccessToken) {
			var entry GrokAuthEntry
			if err := json.Unmarshal(raw, &entry); err != nil {
				return nil, fmt.Errorf("import grok auth: entry decode: %w", err)
			}
			credential, normalizeErr := normalizeEntry(sourceKey, entry)
			if normalizeErr != nil {
				return nil, normalizeErr
			}
			return []ImportedCredential{credential}, nil
		}
		if accounts, ok := value["accounts"]; ok {
			parsed, parseErr := parseCredentialNode(accounts, "", false)
			if parseErr != nil {
				return nil, parseErr
			}
			if len(parsed) > 0 {
				return parsed, nil
			}
		}
		if nested, ok := value["credentials"]; ok {
			platform := strings.ToLower(strings.TrimSpace(stringValue(value["platform"])))
			if platform != "" && platform != "grok" && platform != "xai" {
				return nil, nil
			}
			parsed, parseErr := parseCredentialNode(nested, "", false)
			if parseErr != nil {
				return nil, parseErr
			}
			applySub2APIAccountMetadata(parsed, value)
			return parsed, nil
		}
		out := make([]ImportedCredential, 0, len(value))
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := value[key]
			parsed, parseErr := parseCredentialNode(child, key, false)
			if parseErr != nil {
				return nil, parseErr
			}
			out = append(out, parsed...)
		}
		if root && len(out) == 1 && out[0].SourceKey == "default" {
			out[0].SourceKey = ""
		}
		return out, nil
	default:
		return nil, nil
	}
}

func normalizeCPAEntry(raw []byte) (ImportedCredential, bool, error) {
	var entry cpaAuthEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return ImportedCredential{}, false, fmt.Errorf("import grok auth: CPA entry decode: %w", err)
	}
	provider := strings.ToLower(strings.TrimSpace(entry.Type))
	if provider != "" && provider != "xai" && provider != "grok" {
		return ImportedCredential{}, false, nil
	}
	access := strings.TrimSpace(entry.AccessToken)
	refresh := strings.TrimSpace(entry.RefreshToken)
	if access == "" && refresh == "" {
		return ImportedCredential{}, false, nil
	}
	claims := tokenMetadataClaims(entry.IDToken, access)
	expiresAt, err := cpaExpiry(entry, claims)
	if err != nil {
		return ImportedCredential{}, false, err
	}
	userID := firstNonEmpty(strings.TrimSpace(entry.Sub), strings.TrimSpace(entry.UserID), firstMetadataClaim(claims, "sub", "user_id", "principal_id"))
	email := firstNonEmpty(strings.TrimSpace(entry.Email), firstMetadataClaim(claims, "email"))
	teamID := firstNonEmpty(strings.TrimSpace(entry.TeamID), firstMetadataClaim(claims, "team_id"))
	principalID := firstNonEmpty(strings.TrimSpace(entry.PrincipalID), firstMetadataClaim(claims, "principal_id"), userID)
	principalType := firstNonEmpty(strings.TrimSpace(entry.PrincipalType), firstMetadataClaim(claims, "principal_type"), "User")
	issuer := firstNonEmpty(strings.TrimSpace(entry.OIDCIssuer), Issuer)
	clientID := firstNonEmpty(strings.TrimSpace(entry.OIDCClientID), DefaultClientID)
	var enabled *bool
	if entry.Disabled != nil {
		value := !*entry.Disabled
		enabled = &value
	}
	return ImportedCredential{
		AccessToken: access, RefreshToken: refresh, ExpiresAt: expiresAt,
		Email: email, UserID: userID, TeamID: teamID,
		OIDCIssuer: issuer, OIDCClientID: clientID,
		AuthMode: firstNonEmpty(strings.TrimSpace(entry.AuthKind), "oidc"),
		Enabled:  enabled,
		Raw: GrokAuthEntry{
			Key: access, AuthMode: "oidc", CreateTime: strings.TrimSpace(entry.LastRefresh),
			UserID: userID, Email: email, PrincipalID: principalID, PrincipalType: principalType,
			TeamID: teamID, RefreshToken: refresh, ExpiresAt: formatOptionalTime(expiresAt),
			OIDCIssuer: issuer, OIDCClientID: clientID,
		},
	}, true, nil
}

func cpaExpiry(entry cpaAuthEntry, claims map[string]any) (time.Time, error) {
	value := firstNonEmpty(strings.TrimSpace(string(entry.Expired)), strings.TrimSpace(string(entry.ExpiresAt)))
	if value != "" {
		if parsed, err := parseFlexibleTime(value); err == nil {
			return parsed, nil
		} else if claimTime := numericDateClaim(claims, "exp"); !claimTime.IsZero() {
			return claimTime, nil
		} else {
			return time.Time{}, fmt.Errorf("import grok auth: CPA expires_at: %w", err)
		}
	}
	return numericDateClaim(claims, "exp"), nil
}

func applySub2APIAccountMetadata(credentials []ImportedCredential, account map[string]any) {
	name := strings.TrimSpace(stringValue(account["name"]))
	priority, hasPriority := intValue(account["priority"])
	disabled, hasDisabled := boolValue(account["disabled"])
	for i := range credentials {
		if credentials[i].Name == "" {
			credentials[i].Name = name
		}
		if hasPriority {
			value := priority
			credentials[i].Priority = &value
		}
		if hasDisabled && credentials[i].Enabled == nil {
			value := !disabled
			credentials[i].Enabled = &value
		}
	}
}

func tokenMetadataClaims(tokens ...string) map[string]any {
	claims := make(map[string]any)
	for _, token := range tokens {
		parts := strings.Split(strings.TrimSpace(token), ".")
		if len(parts) < 2 {
			continue
		}
		payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
		if err != nil {
			continue
		}
		var current map[string]any
		if json.Unmarshal(payload, &current) != nil {
			continue
		}
		for key, value := range current {
			claims[key] = value
		}
	}
	return claims
}

func firstMetadataClaim(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := claims[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func numericDateClaim(claims map[string]any, key string) time.Time {
	var seconds float64
	switch value := claims[key].(type) {
	case float64:
		seconds = value
	case json.Number:
		seconds, _ = value.Float64()
	case int64:
		seconds = float64(value)
	case int:
		seconds = float64(value)
	}
	if seconds <= 0 {
		return time.Time{}
	}
	whole := int64(seconds)
	nanos := int64((seconds - float64(whole)) * float64(time.Second))
	return time.Unix(whole, nanos).UTC()
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func intValue(value any) (int, bool) {
	switch number := value.(type) {
	case float64:
		return int(number), number == float64(int(number))
	case int:
		return number, true
	case json.Number:
		parsed, err := number.Int64()
		return int(parsed), err == nil
	default:
		return 0, false
	}
}

func boolValue(value any) (bool, bool) {
	boolean, ok := value.(bool)
	return boolean, ok
}

// DeduplicateImportedCredentials keeps the newest token rotation for each
// stable account identity. It deliberately does not use array positions or
// generic canonical map keys as cross-document identities.
func DeduplicateImportedCredentials(credentials []ImportedCredential) []ImportedCredential {
	out := make([]ImportedCredential, 0, len(credentials))
	indexes := make(map[string]int, len(credentials))
	for _, credential := range credentials {
		identity := importedCredentialIdentity(credential)
		if identity == "" {
			out = append(out, credential)
			continue
		}
		index, exists := indexes[identity]
		if !exists {
			indexes[identity] = len(out)
			out = append(out, credential)
			continue
		}
		if preferImportedCredential(out[index], credential) {
			credential = mergeImportedMetadata(credential, out[index])
			out[index] = credential
		} else {
			out[index] = mergeImportedMetadata(out[index], credential)
		}
	}
	return out
}

func importedCredentialIdentity(credential ImportedCredential) string {
	if credential.UserID != "" {
		identity := "user:" + credential.UserID
		if credential.TeamID != "" {
			identity += "\x00team:" + credential.TeamID
		}
		return identity
	}
	if credential.Email != "" {
		return "email:" + strings.ToLower(credential.Email) + "\x00client:" + credential.OIDCClientID
	}
	if credential.RefreshToken != "" {
		return "refresh:" + credential.RefreshToken
	}
	if credential.AccessToken != "" {
		return "access:" + credential.AccessToken
	}
	return ""
}

func preferImportedCredential(existing, candidate ImportedCredential) bool {
	if existing.ExpiresAt.IsZero() != candidate.ExpiresAt.IsZero() {
		return !candidate.ExpiresAt.IsZero()
	}
	if !candidate.ExpiresAt.Equal(existing.ExpiresAt) {
		return candidate.ExpiresAt.After(existing.ExpiresAt)
	}
	existingRefresh := importedCredentialRefreshTime(existing)
	candidateRefresh := importedCredentialRefreshTime(candidate)
	if !candidateRefresh.Equal(existingRefresh) {
		return candidateRefresh.After(existingRefresh)
	}
	return existing.RefreshToken == "" && candidate.RefreshToken != ""
}

func importedCredentialRefreshTime(credential ImportedCredential) time.Time {
	if value := strings.TrimSpace(credential.Raw.CreateTime); value != "" {
		if parsed, err := parseFlexibleTime(value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func mergeImportedMetadata(primary, fallback ImportedCredential) ImportedCredential {
	primary.Name = firstNonEmpty(primary.Name, fallback.Name)
	primary.Email = firstNonEmpty(primary.Email, fallback.Email)
	primary.UserID = firstNonEmpty(primary.UserID, fallback.UserID)
	primary.TeamID = firstNonEmpty(primary.TeamID, fallback.TeamID)
	primary.OIDCIssuer = firstNonEmpty(primary.OIDCIssuer, fallback.OIDCIssuer)
	primary.OIDCClientID = firstNonEmpty(primary.OIDCClientID, fallback.OIDCClientID)
	primary.AuthMode = firstNonEmpty(primary.AuthMode, fallback.AuthMode)
	if primary.Enabled == nil {
		primary.Enabled = fallback.Enabled
	}
	if primary.Priority == nil {
		primary.Priority = fallback.Priority
	}
	return primary
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
	claims := tokenMetadataClaims(access)
	var exp time.Time
	if strings.TrimSpace(entry.ExpiresAt) != "" {
		t, err := parseFlexibleTime(entry.ExpiresAt)
		if err != nil {
			if claimTime := numericDateClaim(claims, "exp"); !claimTime.IsZero() {
				exp = claimTime
			} else {
				return ImportedCredential{}, fmt.Errorf("import grok auth: entry %q expires_at: %w", sourceKey, err)
			}
		} else {
			exp = t
		}
	} else {
		exp = numericDateClaim(claims, "exp")
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
	userID := firstNonEmpty(strings.TrimSpace(entry.UserID), strings.TrimSpace(entry.PrincipalID), firstMetadataClaim(claims, "sub", "user_id", "principal_id"))
	email := firstNonEmpty(strings.TrimSpace(entry.Email), firstMetadataClaim(claims, "email"))
	teamID := firstNonEmpty(strings.TrimSpace(entry.TeamID), firstMetadataClaim(claims, "team_id"))
	return ImportedCredential{
		SourceKey:    sourceKey,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    exp,
		Email:        email,
		UserID:       userID,
		TeamID:       teamID,
		OIDCIssuer:   issuer,
		OIDCClientID: clientID,
		AuthMode:     strings.TrimSpace(entry.AuthMode),
		Raw:          entry,
	}, nil
}

func splitSourceKey(key string) (issuer, clientID string, ok bool) {
	// Optional suffixes after client id identify an account in merged exports.
	parts := strings.Split(key, "::")
	if len(parts) < 2 {
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
	if numeric, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(numeric) && !math.IsInf(numeric, 0) {
		absolute := math.Abs(numeric)
		divisor := float64(1)
		switch {
		case absolute >= 1e18:
			divisor = 1e9 // nanoseconds
		case absolute >= 1e15:
			divisor = 1e6 // microseconds
		case absolute >= 1e12:
			divisor = 1e3 // milliseconds
		}
		seconds, fraction := math.Modf(numeric / divisor)
		return time.Unix(int64(seconds), int64(math.Round(fraction*1e9))).UTC(), nil
	}
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
