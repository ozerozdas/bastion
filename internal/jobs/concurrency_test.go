package jobs_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
)

// TestConcurrencyLimit proves the pool never runs more scans than configured,
// even when more are queued.
func TestConcurrencyLimit(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/concurrency")
	src, sourcesByKind := pathSource()

	var mu sync.Mutex
	active, maxActive, started := 0, 0, 0
	release := make(chan struct{})
	sc := &fakeScanner{
		name:  "fake",
		kinds: []sources.TargetKind{sources.KindPath},
		scan: func(ctx context.Context, _ *sources.Workspace, _ scanners.Options) (*scanners.RawResult, error) {
			mu.Lock()
			active++
			started++
			if active > maxActive {
				maxActive = active
			}
			mu.Unlock()
			defer func() {
				mu.Lock()
				active--
				mu.Unlock()
			}()

			select {
			case <-release:
				return rawResult("fake"), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}

	m := newManager(t, jobs.Config{
		DB:          db,
		Sources:     sourcesByKind,
		Scanners:    []scanners.Scanner{sc},
		Normalizers: map[string]findings.Normalizer{"fake": &fakeNormalizer{}},
		Concurrency: 2,
	})

	ctx := context.Background()
	var ids []int64
	for i := range 4 {
		id, err := m.Enqueue(ctx, asset.ID, "api")
		if err != nil {
			t.Fatalf("Enqueue #%d: %v", i, err)
		}
		ids = append(ids, id)
	}

	waitFor(t, "two scans to start", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return started == 2
	})
	// No third scan may start while both workers are busy.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	got := started
	mu.Unlock()
	if got != 2 {
		t.Fatalf("scans started = %d while the pool is full, want 2", got)
	}

	close(release)
	for _, id := range ids {
		waitForStatus(t, db, id, store.ScanStatusSucceeded)
	}

	mu.Lock()
	defer mu.Unlock()
	if maxActive != 2 {
		t.Errorf("max in-flight scans = %d, want 2", maxActive)
	}
	if got, want := int(src.cleanup.Load()), len(ids); got != want {
		t.Errorf("workspace cleanups = %d, want %d", got, want)
	}
}

// TestSerializedScanner proves two scans using a scanner that reports
// Serialized run one at a time, while the pool has spare workers.
func TestSerializedScanner(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/serialized")

	var calls sync.WaitGroup
	calls.Add(2)
	firstEntered := make(chan struct{})
	secondEntered := make(chan struct{})
	release := make(chan struct{})

	sc := &fakeScanner{
		name:       "trivy-like",
		kinds:      []sources.TargetKind{sources.KindPath},
		serialized: true,
		scan: func(_ context.Context, _ *sources.Workspace, _ scanners.Options) (*scanners.RawResult, error) {
			calls.Done()
			select {
			case <-firstEntered:
				close(secondEntered)
			default:
				close(firstEntered)
				<-release
			}
			return rawResult("trivy-like"), nil
		},
	}

	m := newManager(t, jobs.Config{
		DB:          db,
		Sources:     map[sources.TargetKind]sources.Source{sources.KindPath: &fakeSource{kind: sources.KindPath}},
		Scanners:    []scanners.Scanner{sc},
		Normalizers: map[string]findings.Normalizer{"trivy-like": &fakeNormalizer{}},
		Concurrency: 2,
	})

	ctx := context.Background()
	first, err := m.Enqueue(ctx, asset.ID, "api")
	if err != nil {
		t.Fatalf("Enqueue first: %v", err)
	}
	second, err := m.Enqueue(ctx, asset.ID, "api")
	if err != nil {
		t.Fatalf("Enqueue second: %v", err)
	}

	select {
	case <-firstEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("first scan never entered the serialized scanner")
	}
	select {
	case <-secondEntered:
		t.Fatal("second scan entered the serialized scanner while the first was still running")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	waitForStatus(t, db, first, store.ScanStatusSucceeded)
	waitForStatus(t, db, second, store.ScanStatusSucceeded)
	select {
	case <-secondEntered:
	default:
		t.Fatal("second scan never ran after the first finished")
	}
	calls.Wait()
}
