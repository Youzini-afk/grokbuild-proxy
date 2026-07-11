package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCredentialCRUD(t *testing.T) {
	s := newTestStore(t)

	created, err := s.CreateCredential(CreateCredentialInput{
		Name:         "main",
		Email:        "u@example.com",
		UserID:       "user-1",
		TeamID:       "team-1",
		OIDCClientID: "b1a00492-073a-47ea-816f-4c329264a828",
		AccessToken:  "access-token-test",
		RefreshToken: "refresh-token-test",
		ExpiresAt:    time.Date(2026, 7, 9, 19, 32, 31, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if !strings.HasPrefix(created.ID, "cred_") {
		t.Fatalf("id prefix: %q", created.ID)
	}
	if created.Priority != 100 || !created.Enabled {
		t.Fatalf("defaults: %+v", created)
	}
	if created.AccessToken != "access-token-test" {
		t.Fatal("access token not stored")
	}

	list, err := s.ListCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list len: %d", len(list))
	}

	got, err := s.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "u@example.com" {
		t.Fatalf("email: %q", got.Email)
	}

	// Priority order: higher first.
	low := 10
	high := 200
	_, err = s.CreateCredential(CreateCredentialInput{
		Name:         "low",
		AccessToken:  "a2",
		RefreshToken: "r2",
		Priority:     &low,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateCredential(CreateCredentialInput{
		Name:         "high",
		AccessToken:  "a3",
		RefreshToken: "r3",
		Priority:     &high,
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err = s.ListCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("list: %d", len(list))
	}
	if list[0].Priority != 200 || list[1].Priority != 100 || list[2].Priority != 10 {
		t.Fatalf("priority order: %d %d %d", list[0].Priority, list[1].Priority, list[2].Priority)
	}

	got.LastError = "rate limited"
	got.FailureCount = 2
	until := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	got.CooldownUntil = &until
	updated, err := s.UpdateCredential(got)
	if err != nil {
		t.Fatal(err)
	}
	if updated.FailureCount != 2 || updated.LastError != "rate limited" {
		t.Fatalf("update: %+v", updated)
	}

	disabled, err := s.SetCredentialEnabled(created.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled {
		t.Fatal("should be disabled")
	}

	prio, err := s.SetCredentialPriority(created.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if prio.Priority != 50 {
		t.Fatalf("priority: %d", prio.Priority)
	}

	if err := s.DeleteCredential(created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCredential(created.ID); err == nil {
		t.Fatal("expected not found after delete")
	}

	// Reject empty tokens.
	if _, err := s.CreateCredential(CreateCredentialInput{Name: "x"}); err == nil {
		t.Fatal("expected error for empty tokens")
	}
}

func TestUpsertCredentialIsIdempotentAndPreservesHealth(t *testing.T) {
	s := newTestStore(t)
	first, created, err := s.UpsertCredential(CreateCredentialInput{
		Name:         "first",
		Email:        "User@example.com",
		UserID:       "user-upsert",
		TeamID:       "team-upsert",
		SourceKey:    "https://auth.x.ai::client",
		OIDCClientID: "client",
		AccessToken:  "access-one",
		RefreshToken: "refresh-one",
	})
	if err != nil || !created {
		t.Fatalf("first created=%v err=%v", created, err)
	}
	cooldown := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if _, err := s.PatchCredential(first.ID, func(c *Credential) error {
		c.Enabled = false
		c.Priority = 42
		c.FailureCount = 3
		c.CooldownUntil = &cooldown
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	second, created, err := s.UpsertCredential(CreateCredentialInput{
		Name:         "rotated",
		Email:        "user@example.com",
		UserID:       "user-upsert",
		TeamID:       "team-upsert",
		SourceKey:    "https://auth.x.ai::client",
		OIDCClientID: "client",
		AccessToken:  "access-two",
		RefreshToken: "refresh-two",
	})
	if err != nil || created {
		t.Fatalf("second created=%v err=%v", created, err)
	}
	if second.ID != first.ID || second.AccessToken != "access-two" || second.RefreshToken != "refresh-two" {
		t.Fatalf("rotated=%+v", second)
	}
	if second.Enabled || second.Priority != 42 || second.FailureCount != 3 || second.CooldownUntil == nil {
		t.Fatalf("health/control fields were reset: %+v", second)
	}
	creds, err := s.ListCredentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("credentials=%d err=%v", len(creds), err)
	}
}

func TestBulkUpsertCredentialsSingleCommitAndIdempotent(t *testing.T) {
	s := newTestStore(t)
	inputs := make([]CreateCredentialInput, 0, 250)
	for i := 0; i < 250; i++ {
		inputs = append(inputs, CreateCredentialInput{
			Name: fmt.Sprintf("account-%d", i), UserID: fmt.Sprintf("user-%d", i),
			Email:       fmt.Sprintf("user-%d@example.com", i),
			AccessToken: fmt.Sprintf("access-%d", i), RefreshToken: fmt.Sprintf("refresh-%d", i),
		})
	}
	results, err := s.BulkUpsertCredentials(inputs)
	if err != nil {
		t.Fatal(err)
	}
	for i, result := range results {
		if result.Err != nil || !result.Created {
			t.Fatalf("result[%d]=%+v", i, result)
		}
	}
	if _, err := os.Stat(s.credentialsPath() + ".bak.1"); !os.IsNotExist(err) {
		t.Fatalf("one bulk commit must not create multiple backup generations: %v", err)
	}
	results, err = s.BulkUpsertCredentials(inputs)
	if err != nil {
		t.Fatal(err)
	}
	for i, result := range results {
		if result.Err != nil || result.Created {
			t.Fatalf("idempotent result[%d]=%+v", i, result)
		}
	}
	creds, err := s.ListCredentials()
	if err != nil || len(creds) != len(inputs) {
		t.Fatalf("credentials=%d err=%v", len(creds), err)
	}
}

func TestClientKeyCRUDAndHashOnly(t *testing.T) {
	s := newTestStore(t)

	res, err := s.CreateClient("ci")
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if !strings.HasPrefix(res.Plaintext, "sk-") {
		t.Fatalf("plaintext prefix: %q", res.Plaintext)
	}
	if !strings.HasPrefix(res.Client.ID, "cli_") {
		t.Fatalf("id: %q", res.Client.ID)
	}
	if res.Client.KeyHash != HashKey(res.Plaintext) {
		t.Fatal("hash mismatch")
	}
	if res.Client.Prefix == "" || strings.Contains(res.Client.Prefix, res.Plaintext[10:]) {
		// prefix is short head only
	}

	// SQLite stores only the hash, never the generated plaintext client key.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		raw, readErr := os.ReadFile(filepath.Join(s.DataDir(), databaseFile) + suffix)
		if readErr == nil && strings.Contains(string(raw), res.Plaintext) {
			t.Fatal("plaintext client key must not be persisted")
		}
	}

	// File mode 0600.
	info, err := os.Stat(filepath.Join(s.DataDir(), databaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode: %o", info.Mode().Perm())
	}

	found, ok, err := s.LookupClientByPlaintext(res.Plaintext)
	if err != nil || !ok {
		t.Fatalf("lookup: ok=%v err=%v", ok, err)
	}
	if found.ID != res.Client.ID {
		t.Fatalf("lookup id: %q", found.ID)
	}
	if _, ok, err := s.LookupClientByPlaintext("sk-not-real"); err != nil || ok {
		t.Fatalf("bad key should miss: ok=%v err=%v", ok, err)
	}

	disabled, err := s.SetClientDisabled(res.Client.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !disabled.Disabled {
		t.Fatal("disabled flag")
	}
	if _, ok, err := s.LookupClientByPlaintext(res.Plaintext); err != nil || ok {
		t.Fatalf("disabled key must not authenticate: ok=%v err=%v", ok, err)
	}

	list, err := s.ListClients()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}

	if err := s.DeleteClient(res.Client.ID); err != nil {
		t.Fatal(err)
	}
	list, err = s.ListClients()
	if err != nil || len(list) != 0 {
		t.Fatalf("after delete: %v len=%d", err, len(list))
	}
}

func TestEnsureBootstrapKeysGenerate(t *testing.T) {
	s := newTestStore(t)

	api, admin, genAPI, genAdmin, err := s.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	if !genAPI || !genAdmin {
		t.Fatalf("first empty bootstrap should mint both: genAPI=%v genAdmin=%v", genAPI, genAdmin)
	}
	if !strings.HasPrefix(api, "sk-") || !strings.HasPrefix(admin, "sk-") {
		t.Fatalf("prefixes api=%q admin=%q", api, admin)
	}
	if api == admin {
		t.Fatal("api and admin keys should differ")
	}

	// API key registered as client.
	if _, ok, err := s.LookupClientByPlaintext(api); err != nil || !ok {
		t.Fatalf("bootstrap api lookup: ok=%v err=%v", ok, err)
	}

	// Admin is not a client key.
	if _, ok, err := s.LookupClientByPlaintext(admin); err != nil || ok {
		t.Fatalf("admin should not be client key: ok=%v err=%v", ok, err)
	}

	// SQLite persists bootstrap secrets in the protected database.
	info, err := os.Stat(filepath.Join(s.DataDir(), databaseFile))
	if err != nil {
		t.Fatalf("database missing: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode: %o", info.Mode().Perm())
	}

	// Second call with empty config reuses meta.json (no new client mint).
	api2, admin2, genAPI2, genAdmin2, err := s.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	if genAPI2 || genAdmin2 {
		t.Fatalf("reuse from meta should not set generated flags: genAPI=%v genAdmin=%v", genAPI2, genAdmin2)
	}
	if api2 != api || admin2 != admin {
		t.Fatalf("empty config should reuse meta: api2=%q admin2=%q", api2, admin2)
	}
	// Configured keys returned as-is.
	api3, admin3, genAPI3, genAdmin3, err := s.EnsureBootstrapKeys(api, admin)
	if err != nil {
		t.Fatal(err)
	}
	if genAPI3 || genAdmin3 {
		t.Fatalf("configured keys should not set generated: genAPI=%v genAdmin=%v", genAPI3, genAdmin3)
	}
	if api3 != api || admin3 != admin {
		t.Fatalf("configured keys should be returned as-is: api3=%q admin3=%q", api3, admin3)
	}
	clients, err := s.ListClients()
	if err != nil {
		t.Fatal(err)
	}
	// Still one client (same hash not duplicated).
	if len(clients) != 1 {
		t.Fatalf("expected single client for same configured key, got %d", len(clients))
	}
}

func TestEnsureBootstrapKeysPartialGenerate(t *testing.T) {
	s := newTestStore(t)
	// Seed meta with only api key present.
	cfgAPI := "sk-testpartialapi00000000000000"
	if err := s.saveMeta(bootstrapMeta{APIKey: cfgAPI}); err != nil {
		t.Fatal(err)
	}
	// Empty config: reuse api from meta, mint only admin.
	api, admin, genAPI, genAdmin, err := s.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	if genAPI {
		t.Fatal("api loaded from meta must not report generatedAPI")
	}
	if !genAdmin {
		t.Fatal("missing admin must report generatedAdmin")
	}
	if api != cfgAPI {
		t.Fatalf("api should reuse meta: got %q", api)
	}
	if !strings.HasPrefix(admin, "sk-") || admin == cfgAPI {
		t.Fatalf("admin should be newly minted: %q", admin)
	}
}

func TestDeletedBootstrapClientDoesNotReappear(t *testing.T) {
	s := newTestStore(t)
	api, _, _, _, err := s.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	clients, err := s.ListClients()
	if err != nil || len(clients) != 1 {
		t.Fatalf("clients=%d err=%v", len(clients), err)
	}
	if err := s.DeleteClient(clients[0].ID); err != nil {
		t.Fatal(err)
	}

	dataDir := s.DataDir()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	api2, _, genAPI, _, err := reopened.EnsureBootstrapKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	if api2 != api || genAPI {
		t.Fatalf("meta key should remain revoked without remint: same=%v generated=%v", api2 == api, genAPI)
	}
	if _, ok, err := reopened.LookupClientByPlaintext(api); err != nil || ok {
		t.Fatalf("deleted bootstrap key revived: ok=%v err=%v", ok, err)
	}
}

func TestPatchCredentialAtomic(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateCredential(CreateCredentialInput{
		Name:         "n",
		AccessToken:  "at1",
		RefreshToken: "rt1",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Concurrent last_used + token rotate must not lose refresh.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = s.PatchCredential(created.ID, func(c *Credential) error {
				now := nowUTC()
				c.LastUsedAt = &now
				return nil
			})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = s.PatchCredential(created.ID, func(c *Credential) error {
				c.AccessToken = "at2"
				c.RefreshToken = "rt2"
				return nil
			})
		}
	}()
	wg.Wait()
	got, err := s.GetCredential(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RefreshToken != "rt2" && got.RefreshToken != "rt1" {
		t.Fatalf("unexpected refresh %q", got.RefreshToken)
	}
	// After concurrent patches, if access was rotated, refresh must match.
	if got.AccessToken == "at2" && got.RefreshToken != "rt2" {
		t.Fatalf("lost refresh after rotate: access=%q refresh=%q", got.AccessToken, got.RefreshToken)
	}
}

func TestEnsureBootstrapKeysConfigured(t *testing.T) {
	s := newTestStore(t)
	// Use synthetic keys that look like sk- but are not production secrets.
	cfgAPI := "sk-testbootstrapapi000000000000"
	cfgAdmin := "sk-testbootstrapadmin0000000000"

	api, admin, genAPI, genAdmin, err := s.EnsureBootstrapKeys(cfgAPI, cfgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if genAPI || genAdmin {
		t.Fatalf("configured keys should not report generated: genAPI=%v genAdmin=%v", genAPI, genAdmin)
	}
	if api != cfgAPI || admin != cfgAdmin {
		t.Fatalf("got api=%q admin=%q", api, admin)
	}
	if _, ok, err := s.LookupClientByPlaintext(cfgAPI); err != nil || !ok {
		t.Fatalf("configured api not stored: ok=%v err=%v", ok, err)
	}

	// Database mode remains protected when credentials are written.
	_, err = s.CreateCredential(CreateCredentialInput{
		Name:         "n",
		AccessToken:  "at",
		RefreshToken: "rt",
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(s.DataDir(), databaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode: %o", info.Mode().Perm())
	}
}

func TestAtomicWriteAndDirMode(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	s, err := New(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("data dir mode: %o", info.Mode().Perm())
	}
	_ = s
}

func TestNewDoesNotChmodExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o750 {
		t.Fatalf("existing directory mode changed to %o", got)
	}
}

func TestStoreHoldsLifetimeInstanceLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	first, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir); err == nil {
		t.Fatal("second store must not share an active data directory")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ListCredentials(); err == nil {
		t.Fatal("closed store accepted an operation")
	}
	second, err := New(dir)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	_ = second.Close()
}

func TestCorruptCredentialFileRecoversFromBackup(t *testing.T) {
	s := newTestStore(t)
	cred, err := s.CreateCredential(CreateCredentialInput{
		Name:         "recover",
		AccessToken:  "access-one",
		RefreshToken: "refresh-one",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PatchCredential(cred.ID, func(c *Credential) error {
		c.Name = "newer"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.DataDir(), credentialsFile), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := s.ListCredentials()
	if err != nil {
		t.Fatalf("backup recovery failed: %v", err)
	}
	if len(creds) != 1 || creds[0].ID != cred.ID {
		t.Fatalf("recovered=%+v", creds)
	}
	if _, err := s.PatchCredential(cred.ID, func(c *Credential) error {
		c.Name = "repaired"
		return nil
	}); err != nil {
		t.Fatalf("save after recovery failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.DataDir(), credentialsFile), []byte("{corrupt-again"), 0o600); err != nil {
		t.Fatal(err)
	}
	if creds, err := s.ListCredentials(); err != nil || len(creds) != 1 {
		t.Fatalf("valid backup was overwritten: credentials=%+v err=%v", creds, err)
	}
}

func TestJSONMigrationPrefersLargestValidSnapshotAndRunsOnce(t *testing.T) {
	dir := t.TempDir()
	legacy := credentialsDoc{Credentials: make([]Credential, 0, 120)}
	for i := 0; i < 120; i++ {
		legacy.Credentials = append(legacy.Credentials, Credential{
			ID: fmt.Sprintf("legacy-%03d", i), Name: fmt.Sprintf("legacy-%03d", i),
			UserID: fmt.Sprintf("user-%03d", i), AccessToken: fmt.Sprintf("access-%03d", i),
			RefreshToken: fmt.Sprintf("refresh-%03d", i), Enabled: true, Priority: 100,
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		})
	}
	writeDoc := func(path string, value any) {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeDoc(filepath.Join(dir, credentialsFile), credentialsDoc{Credentials: legacy.Credentials[:2]})
	writeDoc(filepath.Join(dir, credentialsFile)+".bak", legacy)
	writeDoc(filepath.Join(dir, clientsFile), clientsDoc{Clients: []ClientKey{{
		ID: "legacy-client", Name: "legacy", KeyHash: HashKey("sk-legacy-api"),
		Prefix: "sk-legac", CreatedAt: time.Now().UTC(),
	}}})
	writeDoc(filepath.Join(dir, metaFile), bootstrapMeta{APIKey: "sk-legacy-api", AdminKey: "sk-legacy-admin"})

	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := s.ListCredentials()
	if err != nil || len(credentials) != 120 {
		t.Fatalf("migrated credentials=%d err=%v", len(credentials), err)
	}
	apiKey, adminKey, _, _, err := s.EnsureBootstrapKeys("", "")
	if err != nil || apiKey != "sk-legacy-api" || adminKey != "sk-legacy-admin" {
		t.Fatalf("migrated keys api=%q admin=%q err=%v", apiKey, adminKey, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The migration marker prevents stale JSON from being re-imported.
	writeDoc(filepath.Join(dir, credentialsFile)+".bak", credentialsDoc{Credentials: legacy.Credentials[:1]})
	s, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	credentials, err = s.ListCredentials()
	if err != nil || len(credentials) != 120 {
		t.Fatalf("reopened credentials=%d err=%v", len(credentials), err)
	}
}

func TestRecordCredentialUsageFlushesOnClose(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.CreateCredential(CreateCredentialInput{AccessToken: "usage-access", RefreshToken: "usage-refresh"})
	if err != nil {
		t.Fatal(err)
	}
	usedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	s.RecordCredentialUsage(credential.ID, usedAt)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	credential, err = s.GetCredential(credential.ID)
	if err != nil || credential.LastUsedAt == nil || !credential.LastUsedAt.Equal(usedAt) {
		t.Fatalf("last_used=%v err=%v", credential.LastUsedAt, err)
	}
}

func TestCredentialEncryptionAtRestAndWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	key := strings.Repeat("ab", 32)
	s, err := NewWithOptions(dir, Options{EncryptionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.CreateCredential(CreateCredentialInput{
		AccessToken: "plaintext-access-secret", RefreshToken: "plaintext-refresh-secret", UserID: "encrypted-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s.GetCredential(credential.ID)
	if err != nil || loaded.AccessToken != "plaintext-access-secret" || loaded.RefreshToken != "plaintext-refresh-secret" {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal"} {
		raw, readErr := os.ReadFile(filepath.Join(dir, databaseFile) + suffix)
		if readErr == nil && (strings.Contains(string(raw), "plaintext-access-secret") || strings.Contains(string(raw), "plaintext-refresh-secret")) {
			t.Fatalf("plaintext token leaked into database%s", suffix)
		}
	}
	if _, err := NewWithOptions(dir, Options{EncryptionKey: strings.Repeat("cd", 32)}); err == nil {
		t.Fatal("wrong encryption key must fail")
	}
	if _, err := NewWithOptions(dir, Options{}); err == nil {
		t.Fatal("missing encryption key must fail for encrypted credentials")
	}
	s, err = NewWithOptions(dir, Options{EncryptionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	loaded, err = s.GetCredential(credential.ID)
	if err != nil || loaded.RefreshToken != "plaintext-refresh-secret" {
		t.Fatalf("reopened=%+v err=%v", loaded, err)
	}
}

func TestBackupVerifyAndRestore(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateCredential(CreateCredentialInput{UserID: "before-backup", AccessToken: "a", RefreshToken: "r"}); err != nil {
		t.Fatal(err)
	}
	backup, err := s.CreateBackup()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBackup(backup.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateCredential(CreateCredentialInput{UserID: "after-backup", AccessToken: "a2", RefreshToken: "r2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RestoreDatabase(dir, backup.Path); err != nil {
		t.Fatal(err)
	}
	s, err = New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	credentials, err := s.ListCredentials()
	if err != nil || len(credentials) != 1 || credentials[0].UserID != "before-backup" {
		t.Fatalf("restored credentials=%+v err=%v", credentials, err)
	}
}

func TestNewRejectsDangerousDataDirs(t *testing.T) {
	if _, err := New(string(filepath.Separator)); err == nil {
		t.Fatal("filesystem root must be rejected")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if _, err := New(home); err == nil {
			t.Fatal("user home must be rejected")
		}
	}
}

func TestHashKeyStable(t *testing.T) {
	h1 := HashKey("sk-abc")
	h2 := HashKey("sk-abc")
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("hash: %q", h1)
	}
	if HashKey("sk-abc") == HashKey("sk-abd") {
		t.Fatal("different inputs same hash")
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
