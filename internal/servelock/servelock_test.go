package servelock_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/servelock"
)

// TestAcquireMakesHeldTrue proves serve's lock is visible to the check mcp
// runs, and that releasing it makes the check report no server.
func TestAcquireMakesHeldTrue(t *testing.T) {
	dir := t.TempDir()

	if servelock.Held(dir) {
		t.Fatal("Held reports a running serve before anything acquired the lock")
	}

	release, err := servelock.Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if !servelock.Held(dir) {
		t.Error("Held reports no serve while the lock is held")
	}

	release()
	if servelock.Held(dir) {
		t.Error("Held reports a serve after the lock was released")
	}
}

// TestAcquireRejectsASecondHolder: one data directory has at most one serve.
func TestAcquireRejectsASecondHolder(t *testing.T) {
	dir := t.TempDir()

	release, err := servelock.Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()

	if _, err := servelock.Acquire(dir); err == nil {
		t.Fatal("Acquire succeeded twice for the same directory")
	} else if !strings.Contains(err.Error(), servelock.FileName) {
		t.Errorf("error = %v, want it to name %s", err, servelock.FileName)
	}
}

// TestAcquireWaitsForAShuttingDownHolder: a serve that releases the lock
// shortly (graceful shutdown) does not make the next start fail.
func TestAcquireWaitsForAShuttingDownHolder(t *testing.T) {
	dir := t.TempDir()

	release, err := servelock.Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		release()
	}()

	second, err := servelock.Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire while the holder shuts down: %v", err)
	}
	second()
}

// TestHeldProbesDoNotBlockEachOther: Held takes a shared lock, so concurrent
// probes of a server-less directory all report false and leave the lock free
// for serve to acquire afterwards.
func TestHeldProbesDoNotBlockEachOther(t *testing.T) {
	dir := t.TempDir()
	// Create the lock file; Held on a missing file returns false trivially.
	release, err := servelock.Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	release()

	start := make(chan struct{})
	results := make(chan bool, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			<-start
			results <- servelock.Held(dir)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	for held := range results {
		if held {
			t.Error("a concurrent Held probe reports a running serve")
		}
	}

	release, err = servelock.Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire after concurrent Held probes: %v", err)
	}
	release()
}

// TestHeldWithoutADataDirectoryIsFalse: a read-only check must not create the
// data directory, and a missing one cannot have a running serve.
func TestHeldWithoutADataDirectoryIsFalse(t *testing.T) {
	dir := t.TempDir() + "/absent"

	if servelock.Held(dir) {
		t.Fatal("Held reports a serve for a directory that does not exist")
	}
}
