package auth

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

const (
	maxCredentialBundleFiles = 20_000
	maxCredentialBundleDepth = 3
)

// ParseCredentialBundle auto-detects an uploaded JSON or ZIP credential
// bundle. ZIP files are parsed in memory and never extracted to disk. Nested
// ZIPs are supported to accommodate common sub2api export batches.
func ParseCredentialBundle(filename string, data []byte, maxUncompressed int64) ([]ImportedCredential, error) {
	if maxUncompressed <= 0 {
		maxUncompressed = 128 << 20
	}
	if int64(len(data)) > maxUncompressed {
		return nil, fmt.Errorf("import credential bundle: uploaded file too large")
	}
	extension := strings.ToLower(path.Ext(strings.TrimSpace(filename)))
	switch extension {
	case ".json":
		return ParseGrokAuthJSON(data)
	case ".zip":
		state := &credentialBundleState{maxBytes: maxUncompressed}
		credentials, err := state.parseZIP(data, 1, path.Base(filename))
		if err != nil {
			return nil, err
		}
		credentials = DeduplicateImportedCredentials(credentials)
		if len(credentials) == 0 {
			return nil, fmt.Errorf("import credential bundle: no supported Grok/CPA/sub2api credentials found")
		}
		return credentials, nil
	default:
		return nil, fmt.Errorf("import credential bundle: file must be .json or .zip")
	}
}

type credentialBundleState struct {
	files    int
	jsonSize int64
	maxBytes int64
}

func (s *credentialBundleState) parseZIP(data []byte, depth int, archiveName string) ([]ImportedCredential, error) {
	if depth > maxCredentialBundleDepth {
		return nil, fmt.Errorf("import credential bundle: nested ZIP depth exceeds %d", maxCredentialBundleDepth)
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("import credential bundle: invalid ZIP %q: %w", path.Base(archiveName), err)
	}
	if len(reader.File) > maxCredentialBundleFiles-s.files {
		return nil, fmt.Errorf("import credential bundle: file count exceeds %d", maxCredentialBundleFiles)
	}
	entries := append([]*zip.File(nil), reader.File...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	out := make([]ImportedCredential, 0)
	for _, entry := range entries {
		if entry.FileInfo().IsDir() || ignoredArchiveMetadata(entry.Name) {
			continue
		}
		extension := strings.ToLower(path.Ext(entry.Name))
		if extension != ".json" && extension != ".zip" {
			continue
		}
		s.files++
		if s.files > maxCredentialBundleFiles {
			return nil, fmt.Errorf("import credential bundle: file count exceeds %d", maxCredentialBundleFiles)
		}
		limit := s.maxBytes
		if extension == ".json" {
			limit = s.maxBytes - s.jsonSize
			if limit <= 0 || entry.UncompressedSize64 > uint64(limit) {
				return nil, fmt.Errorf("import credential bundle: uncompressed JSON exceeds %d bytes", s.maxBytes)
			}
		} else if entry.UncompressedSize64 > uint64(s.maxBytes) {
			return nil, fmt.Errorf("import credential bundle: nested ZIP is too large")
		}
		raw, readErr := readZIPEntry(entry, limit)
		if readErr != nil {
			return nil, fmt.Errorf("import credential bundle: read %q: %w", path.Base(entry.Name), readErr)
		}
		if extension == ".zip" {
			parsed, parseErr := s.parseZIP(raw, depth+1, entry.Name)
			if parseErr != nil {
				return nil, parseErr
			}
			out = append(out, parsed...)
			continue
		}
		s.jsonSize += int64(len(raw))
		parsed, parseErr := ParseGrokAuthJSON(raw)
		if parseErr != nil {
			if errors.Is(parseErr, ErrNoSupportedCredential) || errors.Is(parseErr, ErrRawSSORequiresExchange) {
				continue
			}
			return nil, fmt.Errorf("import credential bundle: parse %q: %w", path.Base(entry.Name), parseErr)
		}
		out = append(out, parsed...)
	}
	return out, nil
}

func readZIPEntry(entry *zip.File, limit int64) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("entry exceeds allowed size")
	}
	return raw, nil
}

func ignoredArchiveMetadata(name string) bool {
	clean := strings.ReplaceAll(name, "\\", "/")
	base := path.Base(clean)
	return strings.HasPrefix(clean, "__MACOSX/") || strings.HasPrefix(base, "._")
}
