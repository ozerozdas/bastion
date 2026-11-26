// Package servelock is the handshake between `bastion serve` and `bastion mcp`.
//
// `bastion serve` holds an exclusive OS file lock on <data-dir>/serve.lock for
// its lifetime. `bastion mcp` only checks whether that lock is held: the MCP
// process must not start a scan manager of its own, because a second manager
// would recover (fail) the scans serve owns and race its Trivy downloads.
//
// The lock is advisory and process-scoped: the OS releases it when serve exits,
// including after a crash, so a stale lock file never reports a dead server.
package servelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileName is the lock file inside the data directory.
const FileName = "serve.lock"

// acquireWait bounds how long Acquire retries a held lock before failing.
const (
	acquireWait  = 3 * time.Second
	acquireRetry = 100 * time.Millisecond
)

// errLocked marks the "another process holds the lock" case, so Held can tell
// it apart from a real file-system error.
var errLocked = errors.New("serve lock is held")

// Acquire takes the serve lock in dir for the caller's lifetime and returns a
// function that releases it. It fails when another process already holds it.
// The data directory is created when it does not exist yet, exactly like
// store.Open does before it opens the database.
func Acquire(dir string) (release func(), err error) {
	if dir == "" {
		return nil, errors.New("servelock: directory is required")
	}
	file, err := openLockFile(dir)
	if err != nil {
		return nil, err
	}
	// A previous serve may still be shutting down, or a `bastion mcp` Held
	// probe may hold its shared lock for an instant: wait briefly before
	// reporting a running server.
	deadline := time.Now().Add(acquireWait)
	err = tryLock(file)
	for errors.Is(err, errLocked) && time.Now().Before(deadline) {
		time.Sleep(acquireRetry)
		err = tryLock(file)
	}
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("servelock: %s: %w", lockPath(dir), err)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			_ = unlock(file)
			_ = file.Close()
		})
	}, nil
}

// Held reports whether some process currently holds the serve lock in dir. It
// probes with a shared lock, so two concurrent probes never conflict with each
// other; only serve's exclusive lock makes it report true. A missing directory
// or lock file means no server is running (and nothing is created here: the
// check must stay read-only).
func Held(dir string) bool {
	if dir == "" {
		return false
	}
	file, err := os.OpenFile(lockPath(dir), os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()

	err = trySharedLock(file)
	if err == nil {
		_ = unlock(file)
		return false
	}
	return errors.Is(err, errLocked)
}

// lockPath is the lock file inside dir.
func lockPath(dir string) string {
	return filepath.Join(dir, FileName)
}

// openLockFile creates the data directory when needed and opens (creating) the
// lock file. Locking never writes content, so the file stays empty.
func openLockFile(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("servelock: create %s: %w", dir, err)
	}
	file, err := os.OpenFile(lockPath(dir), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("servelock: open %s: %w", lockPath(dir), err)
	}
	return file, nil
}
