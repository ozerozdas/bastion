package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	trivydb "github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// DBState is the vulnerability DB's state as the API reports it.
type DBState string

// The states a Manager reports. Ready is derived from Trivy's metadata file,
// never remembered, so a DB removed from disk shows up as missing again.
const (
	DBMissing     DBState = "missing"
	DBDownloading DBState = "downloading"
	DBReady       DBState = "ready"
	DBFailed      DBState = "failed"
)

// Download triggers recorded on a DBStatus.
const (
	triggerUser = "user"
	triggerScan = "scan"
)

// metadataFile is Trivy's DB metadata, next to the DB itself in db.Dir.
const metadataFile = "metadata.json"

// DBStatus is a snapshot of the vulnerability DB.
type DBStatus struct {
	// State is one of the DBState constants.
	State DBState
	// UpdatedAt is the DB's build date from Trivy's metadata. It is set only
	// when State is ready and the metadata carries it.
	UpdatedAt *time.Time
	// Error explains a failed download. It is set only when State is failed.
	Error string
	// Trigger is the trigger of the download in flight, or of the last one
	// ("user" or "scan"). It is empty before the first download.
	Trigger string
}

// Manager owns the vulnerability DB under one cache directory.
//
// Downloads are single-flight: a scan-triggered download and a user-triggered
// one never run at the same time, and every waiter observes the same attempt.
// The updater therefore runs outside the lock, while waiters block on a channel
// that the attempt closes when it finishes.
type Manager struct {
	cacheDir string
	// dbDir is where Trivy keeps the DB inside the cache directory.
	dbDir   string
	updater func(ctx context.Context, cacheDir string) error

	// bgCtx scopes user-triggered downloads: Close cancels them.
	bgCtx  context.Context
	cancel context.CancelFunc

	mu          sync.Mutex
	downloading bool
	// done is closed when the attempt in flight finishes. It is replaced by
	// every attempt, so a waiter takes the channel of the attempt it saw.
	done chan struct{}
	// failed is the last attempt's error; nil after a successful attempt.
	failed error
	// trigger is the trigger of the attempt in flight or of the last one.
	trigger string
}

// NewManager returns a manager for the vulnerability DB under cacheDir.
func NewManager(cacheDir string) *Manager {
	return newManagerWithUpdater(cacheDir, defaultUpdater)
}

// newManagerWithUpdater is NewManager with a caller-supplied updater, so tests
// drive the state machine without touching the network.
func newManagerWithUpdater(cacheDir string, updater func(ctx context.Context, cacheDir string) error) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		cacheDir: cacheDir,
		dbDir:    trivydb.Dir(cacheDir),
		updater:  updater,
		bgCtx:    ctx,
		cancel:   cancel,
	}
}

// Close cancels a user-triggered download. It does not wait for the updater: a
// download interrupted this way reports as failed.
func (m *Manager) Close() { m.cancel() }

// Status reports the DB state without blocking. The metadata file is read on
// every call, so a Status never holds a lock across a download.
func (m *Manager) Status() DBStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

// statusLocked derives the state. Downloading wins over the file on disk: an
// update may already have replaced it while the attempt is still running.
func (m *Manager) statusLocked() DBStatus {
	if m.downloading {
		return DBStatus{State: DBDownloading, Trigger: m.trigger}
	}
	if meta, ok := m.readMetadata(); ok {
		status := DBStatus{State: DBReady}
		if !meta.UpdatedAt.IsZero() {
			updated := meta.UpdatedAt
			status.UpdatedAt = &updated
		}
		return status
	}
	if m.failed != nil {
		return DBStatus{State: DBFailed, Error: m.failed.Error(), Trigger: m.trigger}
	}
	return DBStatus{State: DBMissing}
}

// EnsureReady returns once the vulnerability DB is on disk, downloading it
// first when needed. A scan calls it before running Trivy, which would
// otherwise download the DB itself without anyone observing progress.
//
// While another download is in flight, EnsureReady waits for it instead of
// starting a second one, and returns ctx.Err() if ctx ends first.
func (m *Manager) EnsureReady(ctx context.Context) error {
	if m.cacheDir == "" {
		return errors.New("trivy: cache dir is required")
	}
	for {
		m.mu.Lock()
		if m.downloading {
			done := m.done
			m.mu.Unlock()
			select {
			case <-done:
				// Re-evaluate: the attempt may have failed, or another caller
				// may have started the next one.
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if _, ok := m.readMetadata(); ok {
			m.mu.Unlock()
			return nil
		}
		// Nobody is downloading and the DB is not on disk. This caller runs the
		// attempt itself, inside the same single-flight state so a concurrent
		// StartDownload joins it instead of starting another.
		m.beginLocked(triggerScan)
		done := m.done
		m.mu.Unlock()

		m.finishDownload(ctx, done)

		m.mu.Lock()
		err := m.failed
		m.mu.Unlock()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("trivy: ensure vulnerability DB: %w", err)
		}
		return nil
	}
}

// StartDownload starts a user-triggered download in the background and returns
// the state it started in. It is idempotent: while an attempt is in flight,
// whatever its trigger, it returns that attempt's state and starts nothing.
func (m *Manager) StartDownload() DBStatus {
	m.mu.Lock()
	if m.downloading {
		status := m.statusLocked()
		m.mu.Unlock()
		return status
	}
	m.beginLocked(triggerUser)
	// Still holding the lock, so the goroutine cannot have finished and the
	// state is downloading.
	status := m.statusLocked()
	done := m.done
	ctx := m.bgCtx
	m.mu.Unlock()

	go m.finishDownload(ctx, done)
	return status
}

// beginLocked starts an attempt. The caller must hold m.mu.
func (m *Manager) beginLocked(trigger string) {
	m.downloading = true
	m.done = make(chan struct{})
	m.failed = nil
	m.trigger = trigger
}

// finishDownload runs the updater and publishes the outcome to every waiter.
// It never holds the lock while the updater runs.
func (m *Manager) finishDownload(ctx context.Context, done chan struct{}) {
	err := m.updater(ctx, m.cacheDir)

	m.mu.Lock()
	m.downloading = false
	m.failed = err
	close(done)
	m.mu.Unlock()
}

// defaultUpdater downloads the vulnerability DB into db.Dir(cacheDir).
//
// No WithDBRepository is passed, so Trivy's default repositories apply. The
// library's operation.DownloadDB is deliberately not used: with a nil
// repository list it silently downloads nothing.
func defaultUpdater(ctx context.Context, cacheDir string) error {
	if cacheDir == "" {
		return errors.New("trivy: cache dir is required")
	}
	dbDir := trivydb.Dir(cacheDir)
	if err := os.MkdirAll(dbDir, 0o750); err != nil {
		return fmt.Errorf("trivy: create db dir %q: %w", dbDir, err)
	}
	if err := trivydb.NewClient(dbDir, true).Download(ctx, dbDir, ftypes.RegistryOptions{}); err != nil {
		return fmt.Errorf("download vulnerability DB: %w", err)
	}
	return nil
}

// dbMetadata is the part of Trivy's metadata.json bastion reports. It is
// decoded here so the file's shape is the only contract this package depends
// on, and a file Trivy changes keeps being read as long as UpdatedAt stays.
type dbMetadata struct {
	UpdatedAt time.Time `json:"UpdatedAt"`
}

// readMetadata reads Trivy's metadata file. ok is false when the DB is not on
// disk or the metadata cannot be decoded, which both mean "not ready".
func (m *Manager) readMetadata() (dbMetadata, bool) {
	data, err := os.ReadFile(filepath.Join(m.dbDir, metadataFile))
	if err != nil {
		return dbMetadata{}, false
	}
	var meta dbMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return dbMetadata{}, false
	}
	return meta, true
}
