package auth

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseGrokAuthJSONCPAFormat(t *testing.T) {
	raw := `{
		"type":"xai",
		"access_token":"cpa-access",
		"refresh_token":"cpa-refresh",
		"expired":"2026-07-12T12:00:00Z",
		"last_refresh":"2026-07-12T06:00:00Z",
		"sub":"cpa-user",
		"email":"cpa@example.com",
		"disabled":true
	}`
	credentials, err := ParseGrokAuthJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 {
		t.Fatalf("credentials=%d", len(credentials))
	}
	credential := credentials[0]
	if credential.AccessToken != "cpa-access" || credential.RefreshToken != "cpa-refresh" ||
		credential.UserID != "cpa-user" || credential.Email != "cpa@example.com" {
		t.Fatalf("credential=%+v", credential)
	}
	if credential.Enabled == nil || *credential.Enabled {
		t.Fatalf("disabled CPA credential was not preserved: %+v", credential.Enabled)
	}
	if credential.ExpiresAt != time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("expires=%v", credential.ExpiresAt)
	}
}

func TestParseGrokAuthJSONCPAUsesJWTMetadataFallback(t *testing.T) {
	access := syntheticJWT(t, map[string]any{
		"sub": "jwt-user", "email": "jwt@example.com", "team_id": "jwt-team",
		"exp": float64(time.Date(2026, 7, 13, 1, 2, 3, 0, time.UTC).Unix()),
	})
	raw, _ := json.Marshal(map[string]any{
		"type": "xai", "access_token": access, "refresh_token": "jwt-refresh",
	})
	credentials, err := ParseGrokAuthJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	credential := credentials[0]
	if credential.UserID != "jwt-user" || credential.Email != "jwt@example.com" || credential.TeamID != "jwt-team" {
		t.Fatalf("JWT metadata=%+v", credential)
	}
	if credential.ExpiresAt.Unix() != time.Date(2026, 7, 13, 1, 2, 3, 0, time.UTC).Unix() {
		t.Fatalf("JWT expires=%v", credential.ExpiresAt)
	}
}

func TestParseGrokAuthJSONCPAAcceptsNumericExpiry(t *testing.T) {
	want := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	for name, expiresAt := range map[string]any{
		"seconds":      want.Unix(),
		"milliseconds": want.UnixMilli(),
		"microseconds": want.UnixMicro(),
		"nanoseconds":  want.UnixNano(),
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"type": "xai", "access_token": "numeric-access",
				"refresh_token": "numeric-refresh", "expires_at": expiresAt,
			})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := ParseGrokAuthJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(credentials) != 1 || !credentials[0].ExpiresAt.Equal(want) {
				t.Fatalf("expires=%v want=%v", credentials[0].ExpiresAt, want)
			}
		})
	}
}

func TestParseGrokAuthJSONSub2APIWrapper(t *testing.T) {
	raw := `{"accounts":[
		{"name":"wrapped-grok","platform":"grok","type":"oauth","priority":275,
		 "credentials":{"type":"xai","access_token":"wrapped-access","refresh_token":"wrapped-refresh","sub":"wrapped-user","expired":"2026-07-12T12:00:00Z"}},
		{"name":"other-provider","platform":"openai","type":"oauth",
		 "credentials":{"type":"xai","access_token":"wrong-access","refresh_token":"wrong-refresh","sub":"wrong-user","expired":"2026-07-12T12:00:00Z"}}
	]}`
	credentials, err := ParseGrokAuthJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 {
		t.Fatalf("credentials=%d %+v", len(credentials), credentials)
	}
	credential := credentials[0]
	if credential.UserID != "wrapped-user" || credential.Name != "wrapped-grok" ||
		credential.Priority == nil || *credential.Priority != 275 {
		t.Fatalf("wrapped credential=%+v", credential)
	}
}

func TestParseGrokAuthJSONDeduplicatesNewestRotation(t *testing.T) {
	raw := `[
		{"type":"xai","access_token":"old-access","refresh_token":"old-refresh","sub":"same-user","expired":"2026-07-12T10:00:00Z"},
		{"type":"xai","access_token":"new-access","refresh_token":"new-refresh","sub":"same-user","expired":"2026-07-12T12:00:00Z"}
	]`
	credentials, err := ParseGrokAuthJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 || credentials[0].AccessToken != "new-access" || credentials[0].RefreshToken != "new-refresh" {
		t.Fatalf("deduplicated=%+v", credentials)
	}
}

func TestParseCredentialBundleNestedZIP(t *testing.T) {
	nested := zipBytes(t, map[string][]byte{
		"second.json": []byte(`{"type":"xai","access_token":"second-access","refresh_token":"second-refresh","sub":"second-user","expired":"2026-07-12T12:00:00Z"}`),
	})
	outer := zipBytes(t, map[string][]byte{
		"old.json":                []byte(`{"type":"xai","access_token":"old-access","refresh_token":"old-refresh","sub":"same-user","expired":"2026-07-12T10:00:00Z"}`),
		"new.json":                []byte(`{"type":"xai","access_token":"new-access","refresh_token":"new-refresh","sub":"same-user","expired":"2026-07-12T12:00:00Z"}`),
		"nested.zip":              nested,
		"__MACOSX/._ignored.json": []byte("not-json"),
		"other-provider.json":     []byte(`{"type":"openai","access_token":"other","refresh_token":"other"}`),
		"raw-sso.json":            []byte(`{"ssoBasic":[{"token":"session-cookie"}]}`),
		"notes.txt":               []byte("ignored"),
	})
	credentials, err := ParseCredentialBundle("credentials.zip", outer, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 2 {
		t.Fatalf("credentials=%d %+v", len(credentials), credentials)
	}
	byUser := map[string]ImportedCredential{}
	for _, credential := range credentials {
		byUser[credential.UserID] = credential
	}
	if byUser["same-user"].AccessToken != "new-access" || byUser["second-user"].AccessToken != "second-access" {
		t.Fatalf("byUser=%+v", byUser)
	}
	if _, err := ParseCredentialBundle("credentials.zip", outer, 64); err == nil ||
		(!strings.Contains(err.Error(), "exceeds") && !strings.Contains(err.Error(), "too large")) {
		t.Fatalf("small bundle limit error=%v", err)
	}
}

func TestParseGrokAuthJSONExplainsRawSSO(t *testing.T) {
	_, err := ParseGrokAuthJSON([]byte(`{"ssoBasic":[{"token":"session-cookie"}]}`))
	if err == nil || !strings.Contains(err.Error(), "OAuth exchange") {
		t.Fatalf("error=%v", err)
	}
}

func syntheticJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "none"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func zipBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
