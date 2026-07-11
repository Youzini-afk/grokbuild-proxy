package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const databaseFile = "grokbuild.db"

const credentialColumns = `id,name,email,user_id,team_id,source_key,oidc_client_id,
	access_token,refresh_token,refresh_fingerprint,expires_at,enabled,priority,
	failure_count,cooldown_until,last_error,last_used_at,last_success_at,billing,
	created_at,updated_at`

func (s *Store) openSQLite() error {
	path := filepath.Join(s.dir, databaseFile)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("storage: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(0)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA temp_store=MEMORY",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return fmt.Errorf("storage: sqlite configure: %w", err)
		}
	}
	if err := createSQLiteSchema(db); err != nil {
		_ = db.Close()
		return err
	}
	s.db = db
	if err := s.migrateJSONToSQLite(); err != nil {
		s.db = nil
		_ = db.Close()
		return err
	}
	if err := s.normalizeCredentialEncryption(); err != nil {
		s.db = nil
		_ = db.Close()
		return err
	}
	secureSQLiteFiles(path)
	return nil
}

func (s *Store) normalizeCredentialEncryption() error {
	rawCredentials, err := listCredentialsQueryRaw(s.db, `SELECT `+credentialColumns+` FROM credentials`)
	if err != nil {
		return err
	}
	needsRewrite := false
	plainCredentials := make([]Credential, len(rawCredentials))
	for i, raw := range rawCredentials {
		plain, err := s.decryptCredential(raw)
		if err != nil {
			return err
		}
		plainCredentials[i] = plain
		if s.cipher != nil && ((raw.AccessToken != "" && !strings.HasPrefix(raw.AccessToken, encryptedTokenPrefix)) ||
			(raw.RefreshToken != "" && !strings.HasPrefix(raw.RefreshToken, encryptedTokenPrefix))) {
			needsRewrite = true
		}
	}
	if !needsRewrite {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for _, credential := range plainCredentials {
		if err := s.putCredentialTx(tx, credential); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_meta(key,value) VALUES('credential_encryption','aes-256-gcm-v1')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	if _, err := s.db.Exec(`VACUUM`); err != nil {
		return fmt.Errorf("storage: compact after credential encryption: %w", err)
	}
	return nil
}

func secureSQLiteFiles(path string) {
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(candidate); err == nil {
			_ = os.Chmod(candidate, fileMode)
		}
	}
}

func createSQLiteSchema(db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS credentials (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '',
			user_id TEXT NOT NULL DEFAULT '', team_id TEXT NOT NULL DEFAULT '',
			source_key TEXT NOT NULL DEFAULT '', oidc_client_id TEXT NOT NULL DEFAULT '',
			access_token TEXT NOT NULL DEFAULT '', refresh_token TEXT NOT NULL DEFAULT '',
			refresh_fingerprint TEXT NOT NULL DEFAULT '', expires_at TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 100,
			failure_count INTEGER NOT NULL DEFAULT 0, cooldown_until TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '', last_used_at TEXT NOT NULL DEFAULT '',
			last_success_at TEXT NOT NULL DEFAULT '', billing TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL, updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_schedule ON credentials(enabled, priority DESC, cooldown_until)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id, team_id)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_email ON credentials(email, oidc_client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_source ON credentials(source_key)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_refresh ON credentials(refresh_fingerprint)`,
		`CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', key_hash TEXT NOT NULL UNIQUE,
			prefix TEXT NOT NULL DEFAULT '', disabled INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL, stats TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS bootstrap_meta (
			id INTEGER PRIMARY KEY CHECK (id = 1), api_key TEXT NOT NULL DEFAULT '', admin_key TEXT NOT NULL DEFAULT ''
		)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("storage: create sqlite schema: %w", err)
		}
	}
	return nil
}

func (s *Store) migrateJSONToSQLite() error {
	var complete string
	err := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key='json_migration_complete'`).Scan(&complete)
	if err == nil && complete == "1" {
		return nil
	}
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("storage: read migration marker: %w", err)
	}

	credentials := bestCredentialSnapshot(s.credentialsPath(), backupGenerations)
	clients := bestClientSnapshot(s.clientsPath(), backupGenerations)
	meta := bestMetaSnapshot(s.metaPath(), backupGenerations)

	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("storage: begin json migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	for _, credential := range credentials.Credentials {
		if credential.ID == "" {
			credential.ID, err = newID("cred")
			if err != nil {
				return err
			}
		}
		if credential.CreatedAt.IsZero() {
			credential.CreatedAt = nowUTC()
		}
		if credential.UpdatedAt.IsZero() {
			credential.UpdatedAt = credential.CreatedAt
		}
		if err := s.putCredentialTx(tx, credential); err != nil {
			return fmt.Errorf("storage: migrate credential %s: %w", credential.ID, err)
		}
	}
	for _, client := range clients.Clients {
		if err := putClientTx(tx, client); err != nil {
			return fmt.Errorf("storage: migrate client %s: %w", client.ID, err)
		}
	}
	if meta.APIKey != "" || meta.AdminKey != "" {
		if _, err := tx.Exec(`INSERT INTO bootstrap_meta(id,api_key,admin_key) VALUES(1,?,?)
			ON CONFLICT(id) DO UPDATE SET api_key=excluded.api_key,admin_key=excluded.admin_key`, meta.APIKey, meta.AdminKey); err != nil {
			return fmt.Errorf("storage: migrate bootstrap metadata: %w", err)
		}
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&count); err != nil {
		return err
	}
	if count < len(credentials.Credentials) {
		return fmt.Errorf("storage: json migration count mismatch: source=%d database=%d", len(credentials.Credentials), count)
	}
	if _, err := tx.Exec(`INSERT INTO schema_meta(key,value) VALUES('schema_version','1')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_meta(key,value) VALUES('json_migration_complete','1')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storage: commit json migration: %w", err)
	}
	return nil
}

func bestCredentialSnapshot(path string, generations int) credentialsDoc {
	best := credentialsDoc{Credentials: []Credential{}}
	for _, candidate := range snapshotCandidates(path, generations) {
		var doc credentialsDoc
		if readRawJSON(candidate, &doc) == nil && len(doc.Credentials) > len(best.Credentials) {
			best = doc
		}
	}
	return best
}

func bestClientSnapshot(path string, generations int) clientsDoc {
	best := clientsDoc{Clients: []ClientKey{}}
	for _, candidate := range snapshotCandidates(path, generations) {
		var doc clientsDoc
		if readRawJSON(candidate, &doc) == nil && len(doc.Clients) > len(best.Clients) {
			best = doc
		}
	}
	return best
}

func bestMetaSnapshot(path string, generations int) bootstrapMeta {
	var best bootstrapMeta
	for _, candidate := range snapshotCandidates(path, generations) {
		var meta bootstrapMeta
		if readRawJSON(candidate, &meta) == nil && (meta.APIKey != "" || meta.AdminKey != "") {
			return meta
		}
	}
	return best
}

func snapshotCandidates(path string, generations int) []string {
	paths := []string{path, path + ".bak"}
	for i := 1; i < generations; i++ {
		paths = append(paths, fmt.Sprintf("%s.bak.%d", path, i))
	}
	return paths
}

func readRawJSON(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

func (s *Store) dbListCredentials() ([]Credential, error) {
	return s.cachedCredentials(), nil
}

func (s *Store) dbGetCredential(id string) (Credential, error) {
	credential, ok := s.cachedCredential(id)
	if !ok {
		return Credential{}, fmt.Errorf("storage: credential %q not found", id)
	}
	return credential, nil
}

func (s *Store) dbCreateCredential(in CreateCredentialInput) (Credential, error) {
	if in.AccessToken == "" && in.RefreshToken == "" {
		return Credential{}, fmt.Errorf("storage: access_token or refresh_token required")
	}
	var created Credential
	err := s.withLock(func() error {
		id, err := newID("cred")
		if err != nil {
			return err
		}
		now := nowUTC()
		enabled, priority := true, 100
		if in.Enabled != nil {
			enabled = *in.Enabled
		}
		if in.Priority != nil {
			priority = *in.Priority
		}
		created = Credential{ID: id, Enabled: enabled, Priority: priority, CreatedAt: now, UpdatedAt: now}
		applyCredentialInput(&created, in)
		if err := s.putCredentialDB(created); err != nil {
			return err
		}
		s.cacheCredential(created)
		return nil
	})
	return created, err
}

func (s *Store) dbBulkUpsertCredentials(inputs []CreateCredentialInput) ([]BulkUpsertResult, error) {
	results := make([]BulkUpsertResult, len(inputs))
	err := s.withLock(func() error {
		tx, err := s.db.BeginTx(context.Background(), nil)
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck
		credentials, err := s.listCredentialsQuery(tx, `SELECT `+credentialColumns+` FROM credentials`)
		if err != nil {
			return err
		}
		index := newCredentialIdentityIndex(credentials)
		now := nowUTC()
		for i, in := range inputs {
			if in.AccessToken == "" && in.RefreshToken == "" {
				results[i].Err = fmt.Errorf("storage: access_token or refresh_token required")
				continue
			}
			if existing := index.find(credentials, in); existing >= 0 {
				credential := credentials[existing]
				applyCredentialInput(&credential, in)
				credential.UpdatedAt = now
				if err := s.putCredentialTx(tx, credential); err != nil {
					return err
				}
				credentials[existing] = credential
				index.add(existing, credential)
				results[i].Credential = credential
				continue
			}
			id, err := newID("cred")
			if err != nil {
				return err
			}
			enabled, priority := true, 100
			if in.Enabled != nil {
				enabled = *in.Enabled
			}
			if in.Priority != nil {
				priority = *in.Priority
			}
			credential := Credential{ID: id, Enabled: enabled, Priority: priority, CreatedAt: now, UpdatedAt: now}
			applyCredentialInput(&credential, in)
			if err := s.putCredentialTx(tx, credential); err != nil {
				return err
			}
			credentials = append(credentials, credential)
			index.add(len(credentials)-1, credential)
			results[i] = BulkUpsertResult{Credential: credential, Created: true}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		s.replaceCredentialCache(credentials)
		return nil
	})
	return results, err
}

func (s *Store) dbUpdateCredential(c Credential) (Credential, error) {
	if c.ID == "" {
		return Credential{}, fmt.Errorf("storage: credential id required")
	}
	var updated Credential
	err := s.withLock(func() error {
		current, ok := s.cachedCredential(c.ID)
		if !ok {
			return fmt.Errorf("storage: credential %q not found", c.ID)
		}
		c.CreatedAt = current.CreatedAt
		c.UpdatedAt = nowUTC()
		if err := s.putCredentialDB(c); err != nil {
			return err
		}
		s.cacheCredential(c)
		updated = c
		return nil
	})
	return updated, err
}

func (s *Store) dbPatchCredential(id string, mutate func(*Credential) error) (Credential, error) {
	if id == "" || mutate == nil {
		return Credential{}, fmt.Errorf("storage: credential id and mutate func required")
	}
	var updated Credential
	err := s.withLock(func() error {
		current, ok := s.cachedCredential(id)
		if !ok {
			return fmt.Errorf("storage: credential %q not found", id)
		}
		if err := mutate(&current); err != nil {
			return err
		}
		current.ID = id
		current.UpdatedAt = nowUTC()
		if err := s.putCredentialDB(current); err != nil {
			return err
		}
		s.cacheCredential(current)
		updated = current
		return nil
	})
	return updated, err
}

func (s *Store) dbDeleteCredential(id string) error {
	return s.withLock(func() error {
		result, err := s.db.Exec(`DELETE FROM credentials WHERE id=?`, id)
		if err != nil {
			return err
		}
		rows, _ := result.RowsAffected()
		if rows == 0 {
			return fmt.Errorf("storage: credential %q not found", id)
		}
		s.removeCachedCredential(id)
		return nil
	})
}

type credentialScanner interface{ Scan(...any) error }
type credentialQueryer interface {
	Query(string, ...any) (*sql.Rows, error)
}

func listCredentialsQueryRaw(queryer credentialQueryer, query string, args ...any) ([]Credential, error) {
	rows, err := queryer.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Credential, 0)
	for rows.Next() {
		credential, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, credential)
	}
	return out, rows.Err()
}

func (s *Store) listCredentialsQuery(queryer credentialQueryer, query string, args ...any) ([]Credential, error) {
	credentials, err := listCredentialsQueryRaw(queryer, query, args...)
	if err != nil {
		return nil, err
	}
	return s.decryptCredentials(credentials)
}

func scanCredential(scanner credentialScanner) (Credential, error) {
	var c Credential
	var expires, cooldown, lastUsed, lastSuccess, billing, created, updated, fingerprint string
	var enabled int
	err := scanner.Scan(&c.ID, &c.Name, &c.Email, &c.UserID, &c.TeamID, &c.SourceKey, &c.OIDCClientID,
		&c.AccessToken, &c.RefreshToken, &fingerprint, &expires, &enabled, &c.Priority,
		&c.FailureCount, &cooldown, &c.LastError, &lastUsed, &lastSuccess, &billing, &created, &updated)
	if err != nil {
		return Credential{}, err
	}
	c.Enabled = enabled != 0
	c.ExpiresAt = parseDBTime(expires)
	c.CooldownUntil = parseDBTimePointer(cooldown)
	c.LastUsedAt = parseDBTimePointer(lastUsed)
	c.LastSuccessAt = parseDBTimePointer(lastSuccess)
	c.CreatedAt = parseDBTime(created)
	c.UpdatedAt = parseDBTime(updated)
	if billing != "" {
		_ = json.Unmarshal([]byte(billing), &c.Billing)
	}
	return c, nil
}

func (s *Store) putCredentialDB(c Credential) error {
	encrypted, err := s.encryptCredential(c)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(putCredentialSQL(), credentialArgs(encrypted, tokenFingerprint(c.RefreshToken))...)
	return err
}

func (s *Store) putCredentialTx(tx *sql.Tx, c Credential) error {
	encrypted, err := s.encryptCredential(c)
	if err != nil {
		return err
	}
	_, err = tx.Exec(putCredentialSQL(), credentialArgs(encrypted, tokenFingerprint(c.RefreshToken))...)
	return err
}

func putCredentialSQL() string {
	return `INSERT INTO credentials(` + credentialColumns + `) VALUES(` + strings.TrimRight(strings.Repeat("?,", 21), ",") + `)
	ON CONFLICT(id) DO UPDATE SET
	name=excluded.name,email=excluded.email,user_id=excluded.user_id,team_id=excluded.team_id,
	source_key=excluded.source_key,oidc_client_id=excluded.oidc_client_id,access_token=excluded.access_token,
	refresh_token=excluded.refresh_token,refresh_fingerprint=excluded.refresh_fingerprint,expires_at=excluded.expires_at,
	enabled=excluded.enabled,priority=excluded.priority,failure_count=excluded.failure_count,
	cooldown_until=excluded.cooldown_until,last_error=excluded.last_error,last_used_at=excluded.last_used_at,
	last_success_at=excluded.last_success_at,billing=excluded.billing,updated_at=excluded.updated_at`
}

func credentialArgs(c Credential, refreshFingerprint string) []any {
	billing := ""
	if len(c.Billing) > 0 {
		if raw, err := json.Marshal(c.Billing); err == nil {
			billing = string(raw)
		}
	}
	return []any{c.ID, c.Name, c.Email, c.UserID, c.TeamID, c.SourceKey, c.OIDCClientID,
		c.AccessToken, c.RefreshToken, refreshFingerprint, formatDBTime(c.ExpiresAt), boolInt(c.Enabled), c.Priority,
		c.FailureCount, formatDBTimePointer(c.CooldownUntil), c.LastError, formatDBTimePointer(c.LastUsedAt),
		formatDBTimePointer(c.LastSuccessAt), billing, formatDBTime(c.CreatedAt), formatDBTime(c.UpdatedAt)}
}

func tokenFingerprint(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func formatDBTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func formatDBTimePointer(value *time.Time) string {
	if value == nil {
		return ""
	}
	return formatDBTime(*value)
}

func parseDBTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}

func parseDBTimePointer(value string) *time.Time {
	parsed := parseDBTime(value)
	if parsed.IsZero() {
		return nil
	}
	return &parsed
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func putClientTx(tx *sql.Tx, client ClientKey) error {
	stats := ""
	if len(client.Stats) > 0 {
		raw, _ := json.Marshal(client.Stats)
		stats = string(raw)
	}
	_, err := tx.Exec(`INSERT INTO clients(id,name,key_hash,prefix,disabled,created_at,stats) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,key_hash=excluded.key_hash,prefix=excluded.prefix,
		disabled=excluded.disabled,created_at=excluded.created_at,stats=excluded.stats`,
		client.ID, client.Name, client.KeyHash, client.Prefix, boolInt(client.Disabled), formatDBTime(client.CreatedAt), stats)
	return err
}

func (s *Store) dbLoadClients() (clientsDoc, error) {
	rows, err := s.db.Query(`SELECT id,name,key_hash,prefix,disabled,created_at,stats FROM clients ORDER BY created_at,id`)
	if err != nil {
		return clientsDoc{}, err
	}
	defer rows.Close()
	doc := clientsDoc{Clients: []ClientKey{}}
	for rows.Next() {
		var client ClientKey
		var disabled int
		var created, stats string
		if err := rows.Scan(&client.ID, &client.Name, &client.KeyHash, &client.Prefix, &disabled, &created, &stats); err != nil {
			return clientsDoc{}, err
		}
		client.Disabled = disabled != 0
		client.CreatedAt = parseDBTime(created)
		if stats != "" {
			_ = json.Unmarshal([]byte(stats), &client.Stats)
		}
		doc.Clients = append(doc.Clients, client)
	}
	return doc, rows.Err()
}

func (s *Store) dbSaveClients(doc clientsDoc) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`DELETE FROM clients`); err != nil {
		return err
	}
	for _, client := range doc.Clients {
		if err := putClientTx(tx, client); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.replaceClientCache(doc.Clients)
	return nil
}

func (s *Store) dbLoadMeta() (bootstrapMeta, error) {
	var meta bootstrapMeta
	err := s.db.QueryRow(`SELECT api_key,admin_key FROM bootstrap_meta WHERE id=1`).Scan(&meta.APIKey, &meta.AdminKey)
	if err == sql.ErrNoRows {
		return bootstrapMeta{}, nil
	}
	return meta, err
}

func (s *Store) dbSaveMeta(meta bootstrapMeta) error {
	_, err := s.db.Exec(`INSERT INTO bootstrap_meta(id,api_key,admin_key) VALUES(1,?,?)
		ON CONFLICT(id) DO UPDATE SET api_key=excluded.api_key,admin_key=excluded.admin_key`, meta.APIKey, meta.AdminKey)
	return err
}

// ExportCredentialsJSON returns a portable JSON snapshot for rollback or
// migration to another deployment. Secrets are intentionally included.
func (s *Store) ExportCredentialsJSON() ([]byte, error) {
	credentials, err := s.ListCredentials()
	if err != nil {
		return nil, err
	}
	type portableCredential struct {
		Key          string `json:"key"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    string `json:"expires_at,omitempty"`
		Email        string `json:"email,omitempty"`
		UserID       string `json:"user_id,omitempty"`
		TeamID       string `json:"team_id,omitempty"`
		OIDCClientID string `json:"oidc_client_id,omitempty"`
	}
	portable := make([]portableCredential, 0, len(credentials))
	for _, credential := range credentials {
		portable = append(portable, portableCredential{
			Key: credential.AccessToken, RefreshToken: credential.RefreshToken,
			ExpiresAt: formatDBTime(credential.ExpiresAt), Email: credential.Email,
			UserID: credential.UserID, TeamID: credential.TeamID, OIDCClientID: credential.OIDCClientID,
		})
	}
	raw, err := json.MarshalIndent(map[string]any{"credentials": portable}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
