package osv

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// settingsFileName is the consent document, stored beside the other opt-in
// module settings in the data directory.
const settingsFileName = "osv-settings.json"

// Settings is the stored consent for the OSV online lookup. It is on by
// default: a missing file means on, which keeps the behaviour of versions that
// predate the toggle. The zero value is usable and reads DataDir on first use,
// so a Matcher can be wired with either NewSettings or a literal.
type Settings struct {
	// DataDir holds osv-settings.json. It is the directory the EPSS feed, the
	// malware index and the other opt-in modules also store their consent in.
	DataDir string

	mu      sync.RWMutex
	loaded  bool
	enabled bool
}

// NewSettings returns settings rooted at dataDir. It reads no file: the first
// Enabled call does, so construction never fails.
func NewSettings(dataDir string) *Settings {
	return &Settings{DataDir: dataDir}
}

// Enabled reports whether the online lookup is on. A nil Settings means on.
func (s *Settings) Enabled() bool {
	if s == nil {
		return true
	}

	s.mu.RLock()
	loaded, enabled := s.loaded, s.enabled
	s.mu.RUnlock()
	if loaded {
		return enabled
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		s.enabled = s.read()
		s.loaded = true
	}
	return s.enabled
}

// SetEnabled stores the user's answer. Only the UI calls this; the CLI only
// reads. Turning the lookup off affects the next scan, never a running one.
func (s *Settings) SetEnabled(enabled bool) error {
	if s == nil {
		return errors.New("osv: settings are required")
	}
	if s.DataDir == "" {
		return errors.New("osv: data directory is required")
	}
	if err := os.MkdirAll(s.DataDir, 0o700); err != nil {
		return fmt.Errorf("osv: create data directory: %w", err)
	}
	data, err := json.Marshal(settingsFile{Enabled: enabled})
	if err != nil {
		return fmt.Errorf("osv: encode settings: %w", err)
	}
	path := filepath.Join(s.DataDir, settingsFileName)
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("osv: store settings: %w", err)
	}

	s.mu.Lock()
	s.enabled = enabled
	s.loaded = true
	s.mu.Unlock()
	return nil
}

// settingsFile is the on-disk consent document.
type settingsFile struct {
	Enabled bool `json:"enabled"`
}

// read returns the stored setting. A missing file means on, so the behaviour of
// versions that predate the toggle is unchanged. A file that exists but cannot
// be read or parsed means off: the user wrote a preference, and a damaged file
// must not quietly turn a lookup they turned off back on.
func (s *Settings) read() bool {
	if s.DataDir == "" {
		return true
	}
	data, err := os.ReadFile(filepath.Join(s.DataDir, settingsFileName))
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	var stored settingsFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return false
	}
	return stored.Enabled
}

// writeFileAtomic writes data through a temporary file in the same directory
// and renames it into place, so a reader never sees half a document.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
