package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const backupRetention = 10

type BackupInfo struct {
	Path      string    `json:"path"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateBackup creates a transactionally consistent SQLite snapshot and
// retains the newest backupRetention generations.
func (s *Store) CreateBackup() (BackupInfo, error) {
	if s == nil || s.db == nil {
		return BackupInfo{}, fmt.Errorf("storage: database unavailable")
	}
	if err := s.flushRuntimeUsage(); err != nil {
		return BackupInfo{}, err
	}
	dir := filepath.Join(s.dir, "backups")
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return BackupInfo{}, err
	}
	name := "grokbuild-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".db"
	path := filepath.Join(dir, name)
	err := s.withLock(func() error {
		if _, err := s.db.Exec(`VACUUM INTO ?`, path); err != nil {
			return fmt.Errorf("storage: create sqlite backup: %w", err)
		}
		return nil
	})
	if err != nil {
		return BackupInfo{}, err
	}
	_ = os.Chmod(path, fileMode)
	info, err := inspectBackup(path)
	if err != nil {
		return BackupInfo{}, err
	}
	if err := os.WriteFile(path+".sha256", []byte(info.SHA256+"  "+name+"\n"), fileMode); err != nil {
		return BackupInfo{}, err
	}
	pruneBackups(dir, backupRetention)
	return info, nil
}

func inspectBackup(path string) (BackupInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return BackupInfo{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		_ = file.Close()
		return BackupInfo{}, err
	}
	_ = file.Close()
	stat, err := os.Stat(path)
	if err != nil {
		return BackupInfo{}, err
	}
	return BackupInfo{
		Path: path, Name: filepath.Base(path), Size: stat.Size(),
		SHA256: hex.EncodeToString(hash.Sum(nil)), CreatedAt: stat.ModTime().UTC(),
	}, nil
}

// VerifyBackup checks both SHA-256 (when a sidecar exists) and SQLite integrity.
func VerifyBackup(path string) (BackupInfo, error) {
	path, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return BackupInfo{}, err
	}
	info, err := inspectBackup(path)
	if err != nil {
		return BackupInfo{}, err
	}
	if raw, readErr := os.ReadFile(path + ".sha256"); readErr == nil {
		expected := strings.Fields(string(raw))
		if len(expected) > 0 && !strings.EqualFold(expected[0], info.SHA256) {
			return BackupInfo{}, fmt.Errorf("storage: backup checksum mismatch")
		}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		return BackupInfo{}, err
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return BackupInfo{}, err
	}
	if !strings.EqualFold(integrity, "ok") {
		return BackupInfo{}, fmt.Errorf("storage: backup integrity check failed: %s", integrity)
	}
	return info, nil
}

// RestoreDatabase restores a verified backup while holding the data-directory
// lifetime lock. The previous database is retained as a pre-restore snapshot.
func RestoreDatabase(dataDir, backupPath string) error {
	backup, err := VerifyBackup(backupPath)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(filepath.Clean(dataDir))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(abs, dirMode); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(abs, ".instance.lock"), os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockFile(lock, true); err != nil {
		return fmt.Errorf("storage: stop the running service before restore: %w", err)
	}
	defer unlockFile(lock) //nolint:errcheck
	target := filepath.Join(abs, databaseFile)
	previous := ""
	if _, err := os.Stat(target); err == nil {
		previous = target + ".pre-restore-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(target, previous); err != nil {
			return err
		}
	}
	restored := false
	defer func() {
		if !restored && previous != "" {
			_ = os.Rename(previous, target)
		}
	}()
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(target + suffix)
	}
	source, err := os.Open(backup.Path)
	if err != nil {
		return err
	}
	defer source.Close()
	tmp, err := os.CreateTemp(abs, ".restore-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	_ = tmp.Chmod(fileMode)
	if _, err := io.Copy(tmp, source); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	restored = true
	return nil
}

func pruneBackups(dir string, keep int) {
	entries, _ := filepath.Glob(filepath.Join(dir, "grokbuild-*.db"))
	sort.Sort(sort.Reverse(sort.StringSlice(entries)))
	if len(entries) <= keep {
		return
	}
	for _, path := range entries[keep:] {
		_ = os.Remove(path)
		_ = os.Remove(path + ".sha256")
	}
}
