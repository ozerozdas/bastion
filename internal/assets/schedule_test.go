package assets

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// fixedNow is the clock every scheduled-scan test runs at.
var fixedNow = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

// scheduleAssetSeq keeps test asset refs unique within one run.
var scheduleAssetSeq atomic.Int64

// openScheduleDB opens a throwaway database with the real migrations.
func openScheduleDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "bastion.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// createScheduledAsset inserts an asset with a schedule and returns its id.
func createScheduledAsset(t *testing.T, db *sql.DB, schedule string) int64 {
	t.Helper()
	queries := sqlcdb.New(db)
	asset, err := queries.CreateAsset(t.Context(), sqlcdb.CreateAssetParams{
		Kind:         "path",
		DisplayName:  schedule,
		Ref:          "/tmp/" + schedule + "-" + t.Name() + "-" + strconv.FormatInt(scheduleAssetSeq.Add(1), 10),
		MetadataJSON: "{}",
		CreatedAt:    store.FormatTimestamp(fixedNow),
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if _, err := queries.SetAssetScanSchedule(t.Context(), sqlcdb.SetAssetScanScheduleParams{
		ScanSchedule: schedule,
		ID:           asset.ID,
	}); err != nil {
		t.Fatalf("set schedule: %v", err)
	}
	return asset.ID
}

// addScan inserts one scan of any status. A nil started/finished leaves the
// column NULL, which is what a queued scan or an interrupted one looks like.
func addScan(t *testing.T, db *sql.DB, assetID int64, status string, started, finished *time.Time) int64 {
	t.Helper()
	queries := sqlcdb.New(db)
	scan, err := queries.CreateScan(t.Context(), sqlcdb.CreateScanParams{
		AssetID:   assetID,
		Status:    status,
		Trigger:   ScanTriggerUI,
		StartedAt: nullTimestamp(started),
	})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if status != "queued" && status != "running" {
		if err := queries.FinishScan(t.Context(), sqlcdb.FinishScanParams{
			Status:     status,
			FinishedAt: nullTimestamp(finished),
			ID:         scan.ID,
		}); err != nil {
			t.Fatalf("finish scan: %v", err)
		}
	}
	return scan.ID
}

func nullTimestamp(value *time.Time) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: store.FormatTimestamp(*value), Valid: true}
}

// newScheduleTestService builds the assets service on the fixed clock and a
// scheduler whose enqueue is recorded instead of reaching a scan manager.
func newScheduleTestService(t *testing.T) (*Service, *Scheduler, *[]int64) {
	t.Helper()
	db := openScheduleDB(t)
	service, err := NewService(db, WithClock(func() time.Time { return fixedNow }))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	scheduler, err := NewScheduler(service)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	var queued []int64
	scheduler.enqueue = func(_ context.Context, ids []int64) ([]QueuedScan, error) {
		queued = append(queued, ids...)
		return nil, nil
	}
	return service, scheduler, &queued
}

// TestScheduleDue is the due rule with a pinned clock: no scan and an exactly
// reached interval are due, a failed scan is the latest scan, and off never is.
func TestScheduleDue(t *testing.T) {
	ago := func(d time.Duration) *time.Time {
		at := fixedNow.Add(-d)
		return &at
	}
	cases := []struct {
		name     string
		schedule string
		last     *time.Time
		want     bool
	}{
		{name: "never scanned daily", schedule: ScheduleDaily, last: nil, want: true},
		{name: "never scanned weekly", schedule: ScheduleWeekly, last: nil, want: true},
		{name: "daily not yet due", schedule: ScheduleDaily, last: ago(24*time.Hour - time.Second), want: false},
		{name: "daily exactly due", schedule: ScheduleDaily, last: ago(24 * time.Hour), want: true},
		{name: "daily overdue", schedule: ScheduleDaily, last: ago(48 * time.Hour), want: true},
		{name: "weekly not yet due", schedule: ScheduleWeekly, last: ago(7*24*time.Hour - time.Second), want: false},
		{name: "weekly exactly due", schedule: ScheduleWeekly, last: ago(7 * 24 * time.Hour), want: true},
		{name: "weekly overdue", schedule: ScheduleWeekly, last: ago(8 * 24 * time.Hour), want: true},
		{name: "off is never due", schedule: ScheduleOff, last: nil, want: false},
		{name: "unknown schedule is never due", schedule: "hourly", last: nil, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scheduleDue(tc.schedule, tc.last, fixedNow); got != tc.want {
				t.Errorf("scheduleDue(%q, %v) = %v, want %v", tc.schedule, tc.last, got, tc.want)
			}
		})
	}
}

// TestSchedulerEnqueuesDueAssets drives one check against real rows: schedules,
// archived assets, off, active scans and a failed latest scan all take effect.
func TestSchedulerEnqueuesDueAssets(t *testing.T) {
	service, scheduler, queued := newScheduleTestService(t)
	db := service.db
	ctx := t.Context()

	neverScanned := createScheduledAsset(t, db, ScheduleDaily)

	notDue := createScheduledAsset(t, db, ScheduleDaily)
	addScan(t, db, notDue, "succeeded", timePtr(fixedNow.Add(-23*time.Hour)), timePtr(fixedNow.Add(-23*time.Hour)))

	exactlyDueDaily := createScheduledAsset(t, db, ScheduleDaily)
	addScan(t, db, exactlyDueDaily, "succeeded", timePtr(fixedNow.Add(-24*time.Hour)), timePtr(fixedNow.Add(-24*time.Hour)))

	weeklyNotDue := createScheduledAsset(t, db, ScheduleWeekly)
	addScan(t, db, weeklyNotDue, "succeeded", timePtr(fixedNow.Add(-6*24*time.Hour)), timePtr(fixedNow.Add(-6*24*time.Hour)))

	exactlyDueWeekly := createScheduledAsset(t, db, ScheduleWeekly)
	addScan(t, db, exactlyDueWeekly, "succeeded", timePtr(fixedNow.Add(-7*24*time.Hour)), timePtr(fixedNow.Add(-7*24*time.Hour)))

	off := createScheduledAsset(t, db, ScheduleOff)
	archived := createScheduledAsset(t, db, ScheduleDaily)
	if _, err := sqlcdb.New(db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ArchivedAt: sql.NullString{String: store.FormatTimestamp(fixedNow), Valid: true},
		ID:         archived,
	}); err != nil {
		t.Fatalf("archive asset: %v", err)
	}

	active := createScheduledAsset(t, db, ScheduleDaily)
	addScan(t, db, active, "queued", nil, nil)

	failedNotDue := createScheduledAsset(t, db, ScheduleDaily)
	addScan(t, db, failedNotDue, "failed", timePtr(fixedNow.Add(-23*time.Hour)), timePtr(fixedNow.Add(-23*time.Hour)))

	failedDue := createScheduledAsset(t, db, ScheduleDaily)
	addScan(t, db, failedDue, "failed", timePtr(fixedNow.Add(-24*time.Hour)), timePtr(fixedNow.Add(-24*time.Hour)))

	timestampless := createScheduledAsset(t, db, ScheduleDaily)
	addScan(t, db, timestampless, "canceled", nil, nil)

	scheduler.runOnce(ctx)

	want := map[int64]bool{
		neverScanned:     true,
		exactlyDueDaily:  true,
		exactlyDueWeekly: true,
		failedDue:        true,
		timestampless:    true,
	}
	got := make(map[int64]bool, len(*queued))
	for _, id := range *queued {
		got[id] = true
	}
	for id, due := range want {
		if due && !got[id] {
			t.Errorf("asset %d was due but was not queued", id)
		}
	}
	for _, id := range []int64{notDue, weeklyNotDue, off, archived, active, failedNotDue} {
		if got[id] {
			t.Errorf("asset %d was queued but was not due", id)
		}
	}
	if len(*queued) != len(want) {
		t.Errorf("queued = %v, want exactly %d assets", *queued, len(want))
	}
}

// TestSchedulerContinuesAfterEnqueueFailure: one asset's enqueue failure is
// logged and the remaining due assets are still queued.
func TestSchedulerContinuesAfterEnqueueFailure(t *testing.T) {
	service, scheduler, _ := newScheduleTestService(t)
	db := service.db

	first := createScheduledAsset(t, db, ScheduleDaily)
	second := createScheduledAsset(t, db, ScheduleDaily)

	var calls []int64
	scheduler.enqueue = func(_ context.Context, ids []int64) ([]QueuedScan, error) {
		calls = append(calls, ids...)
		if ids[0] == first {
			return nil, errors.New("enqueue failed")
		}
		return nil, nil
	}

	scheduler.runOnce(t.Context())

	if len(calls) != 2 || calls[0] != first || calls[1] != second {
		t.Fatalf("enqueue calls = %v, want [%d %d]", calls, first, second)
	}
}

// TestSchedulerCloseStopsLoop: the startup check runs, and Close stops the
// ticker so nothing is queued afterwards.
func TestSchedulerCloseStopsLoop(t *testing.T) {
	service, scheduler, _ := newScheduleTestService(t)
	createScheduledAsset(t, service.db, ScheduleDaily)

	var count atomic.Int64
	scheduler.enqueue = func(context.Context, []int64) ([]QueuedScan, error) {
		count.Add(1)
		return nil, nil
	}
	scheduler.interval = 10 * time.Millisecond

	scheduler.Start()
	deadline := time.Now().Add(2 * time.Second)
	for count.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if count.Load() == 0 {
		t.Fatal("startup check did not enqueue the due asset")
	}

	scheduler.Close()
	stoppedAt := count.Load()
	time.Sleep(100 * time.Millisecond)
	if after := count.Load(); after != stoppedAt {
		t.Errorf("enqueue count after Close = %d, want %d", after, stoppedAt)
	}
}

func timePtr(value time.Time) *time.Time { return &value }
