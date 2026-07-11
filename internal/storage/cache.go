package storage

import (
	"context"
	"fmt"
	"sort"
	"time"
)

const runtimeFlushInterval = 30 * time.Second

func (s *Store) reloadCaches() error {
	credentials, err := listCredentialsQuery(s.db, `SELECT `+credentialColumns+` FROM credentials ORDER BY priority DESC,id`)
	if err != nil {
		return fmt.Errorf("storage: load credential cache: %w", err)
	}
	clients, err := s.dbLoadClients()
	if err != nil {
		return fmt.Errorf("storage: load client cache: %w", err)
	}
	s.replaceCredentialCache(credentials)
	s.replaceClientCache(clients.Clients)
	return nil
}

// CredentialSnapshot returns an immutable process-local snapshot. The slice is
// replaced, never mutated, so readers can use it without holding the cache lock.
func (s *Store) CredentialSnapshot() (uint64, []Credential) {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.credentialVersion, s.credentialCache
}

func (s *Store) cachedCredentials() []Credential {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return append([]Credential(nil), s.credentialCache...)
}

func (s *Store) cachedCredential(id string) (Credential, bool) {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	credential, ok := s.credentialByID[id]
	return credential, ok
}

func (s *Store) replaceCredentialCache(credentials []Credential) {
	next := append([]Credential(nil), credentials...)
	sort.SliceStable(next, func(i, j int) bool {
		if next[i].Priority != next[j].Priority {
			return next[i].Priority > next[j].Priority
		}
		return next[i].ID < next[j].ID
	})
	byID := make(map[string]Credential, len(next))
	for _, credential := range next {
		byID[credential.ID] = credential
	}
	s.cacheMu.Lock()
	s.credentialCache = next
	s.credentialByID = byID
	s.credentialVersion++
	s.cacheMu.Unlock()
}

func (s *Store) cacheCredential(credential Credential) {
	current := s.cachedCredentials()
	found := false
	for i := range current {
		if current[i].ID == credential.ID {
			current[i] = credential
			found = true
			break
		}
	}
	if !found {
		current = append(current, credential)
	}
	s.replaceCredentialCache(current)
}

func (s *Store) removeCachedCredential(id string) {
	current := s.cachedCredentials()
	next := make([]Credential, 0, len(current))
	for _, credential := range current {
		if credential.ID != id {
			next = append(next, credential)
		}
	}
	s.replaceCredentialCache(next)
}

func (s *Store) replaceClientCache(clients []ClientKey) {
	next := append([]ClientKey(nil), clients...)
	byHash := make(map[string]ClientKey, len(next))
	for _, client := range next {
		byHash[client.KeyHash] = client
	}
	s.cacheMu.Lock()
	s.clientCache = next
	s.clientByHash = byHash
	s.cacheMu.Unlock()
}

func (s *Store) cachedClients() []ClientKey {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return append([]ClientKey(nil), s.clientCache...)
}

func (s *Store) cachedClientByHash(hash string) (ClientKey, bool) {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	client, ok := s.clientByHash[hash]
	return client, ok
}

// RecordCredentialUsage coalesces high-frequency last_used updates. Token
// rotation and failure state remain synchronously durable; usage telemetry does
// not block the request path.
func (s *Store) RecordCredentialUsage(id string, usedAt time.Time) {
	if s == nil || id == "" {
		return
	}
	usedAt = usedAt.UTC().Truncate(time.Second)
	s.runtimeMu.Lock()
	if s.pendingUsage == nil {
		s.pendingUsage = make(map[string]time.Time)
	}
	if previous := s.pendingUsage[id]; usedAt.After(previous) {
		s.pendingUsage[id] = usedAt
	}
	s.runtimeMu.Unlock()
}

func (s *Store) startRuntimeFlusher() {
	s.runtimeMu.Lock()
	if s.runtimeStop != nil {
		s.runtimeMu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	s.runtimeStop, s.runtimeDone = stop, done
	s.runtimeMu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(runtimeFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = s.flushRuntimeUsage()
			case <-stop:
				return
			}
		}
	}()
}

func (s *Store) stopRuntimeFlusher() {
	if s == nil {
		return
	}
	s.runtimeMu.Lock()
	stop, done := s.runtimeStop, s.runtimeDone
	if stop != nil {
		close(stop)
		s.runtimeStop = nil
		s.runtimeDone = nil
	}
	s.runtimeMu.Unlock()
	if done != nil {
		<-done
	}
	_ = s.flushRuntimeUsage()
}

func (s *Store) flushRuntimeUsage() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.runtimeMu.Lock()
	pending := s.pendingUsage
	s.pendingUsage = make(map[string]time.Time)
	s.runtimeMu.Unlock()
	if len(pending) == 0 {
		return nil
	}
	err := s.withLock(func() error {
		tx, err := s.db.BeginTx(context.Background(), nil)
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck
		for id, usedAt := range pending {
			if _, err := tx.Exec(`UPDATE credentials SET last_used_at=?,updated_at=? WHERE id=?`, formatDBTime(usedAt), formatDBTime(usedAt), id); err != nil {
				return err
			}
		}
		return tx.Commit()
	})
	if err != nil {
		s.runtimeMu.Lock()
		for id, usedAt := range pending {
			if usedAt.After(s.pendingUsage[id]) {
				s.pendingUsage[id] = usedAt
			}
		}
		s.runtimeMu.Unlock()
		return err
	}
	// Refresh only the telemetry fields without changing the scheduling version.
	s.cacheMu.Lock()
	next := append([]Credential(nil), s.credentialCache...)
	byID := make(map[string]Credential, len(s.credentialByID))
	for i, credential := range next {
		if usedAt, ok := pending[credential.ID]; ok {
			value := usedAt
			credential.LastUsedAt = &value
			credential.UpdatedAt = usedAt
			next[i] = credential
		}
		byID[credential.ID] = credential
	}
	s.credentialCache = next
	s.credentialByID = byID
	s.cacheMu.Unlock()
	return nil
}
