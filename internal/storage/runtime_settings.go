package storage

import (
	"database/sql"
	"fmt"
)

const runtimeSettingsKey = "runtime_settings_v1"

// LoadRuntimeSettingsJSON returns the persisted runtime-settings document.
func (s *Store) LoadRuntimeSettingsJSON() ([]byte, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	var value string
	err := s.db.QueryRow(`SELECT value FROM schema_meta WHERE key=?`, runtimeSettingsKey).Scan(&value)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("storage: load runtime settings: %w", err)
	}
	return []byte(value), nil
}

// SaveRuntimeSettingsJSON atomically persists the validated settings document.
func (s *Store) SaveRuntimeSettingsJSON(raw []byte) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("storage: database unavailable")
	}
	return s.withLock(func() error {
		_, err := s.db.Exec(`INSERT INTO schema_meta(key,value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, runtimeSettingsKey, string(raw))
		if err != nil {
			return fmt.Errorf("storage: save runtime settings: %w", err)
		}
		return nil
	})
}

// DeleteRuntimeSettings removes the override so configured defaults apply.
func (s *Store) DeleteRuntimeSettings() error {
	if s == nil || s.db == nil {
		return fmt.Errorf("storage: database unavailable")
	}
	return s.withLock(func() error {
		_, err := s.db.Exec(`DELETE FROM schema_meta WHERE key=?`, runtimeSettingsKey)
		if err != nil {
			return fmt.Errorf("storage: delete runtime settings: %w", err)
		}
		return nil
	})
}
