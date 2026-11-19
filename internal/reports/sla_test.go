package reports_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
)

// slaAt is a UTC timestamp on a seeded SLA day.
func slaAt(year int, month time.Month, day, hour int) time.Time {
	return time.Date(year, month, day, hour, 0, 0, 0, time.UTC)
}

// TestSLAReportAgesFixesAndScopes is the #190 report contract with a pinned
// clock: overdue aging against the stored thresholds, unknown severity
// excluded, ignored findings excluded, fixed detection, the fix window,
// mean time to fix and asset scoping.
func TestSLAReportAgesFixesAndScopes(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	now := slaAt(2026, time.November, 20, 12)
	service, err := reports.NewService(db, reports.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/sla-alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/sla-beta", "Beta")

	// May 1: the first sightings. highFixed disappears after this scan and is
	// fixed by the next succeeded scan (August 20).
	critOld := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-1", findings.SeverityCritical)
	lowOld := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-2", findings.SeverityLow)
	highFixed := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-3", findings.SeverityHigh)
	// Unknown severity is aged too but has no threshold, so it never counts.
	unknownSev := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-4", findings.SeverityUnknown)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.May, 1, 10),
		critOld, lowOld, highFixed, unknownSev)

	// August 20: highFixed is gone (fixed now); mediumFixed appears and is
	// fixed by the November 10 scan.
	mediumFixed := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-5", findings.SeverityMedium)
	ignoredHigh := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-6", findings.SeverityHigh)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.August, 20, 10),
		critOld, lowOld, unknownSev, mediumFixed, ignoredHigh)

	// November 10: the latest succeeded scan. mediumRecent first appears here,
	// so it is 10 days old and inside the medium threshold.
	mediumRecent := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-7", findings.SeverityMedium)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.November, 10, 10),
		critOld, lowOld, unknownSev, mediumRecent, ignoredHigh)
	if err := store.SetFindingState(ctx, db, alpha.ID, ignoredHigh.Fingerprint,
		store.FindingStateIgnored, "accepted upstream", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	betaHigh := newFinding(beta.ID, findings.TypeVulnerability, "CVE-SLA-8", findings.SeverityHigh)
	seedScan(t, db, beta.ID, store.ScanStatusSucceeded, slaAt(2026, time.October, 1, 10), betaHigh)

	thresholds, err := service.SLAThresholds(ctx)
	if err != nil {
		t.Fatalf("SLAThresholds: %v", err)
	}
	wantThresholds := reports.SLAThresholds{Critical: 7, High: 30, Medium: 90, Low: 180}
	if thresholds != wantThresholds {
		t.Fatalf("thresholds = %+v, want %+v", thresholds, wantThresholds)
	}

	report, err := service.SLA(ctx, 0, reports.DefaultSLAWindowDays)
	if err != nil {
		t.Fatalf("SLA: %v", err)
	}

	// Alpha has four open findings (the ignored high is excluded, the fixed
	// ones are gone); beta has one.
	if report.OpenCount != 5 {
		t.Errorf("open_count = %d, want 5", report.OpenCount)
	}
	if report.OverdueCount != 3 || len(report.Overdue) != 3 {
		t.Fatalf("overdue = %+v, want three entries", report.Overdue)
	}

	// Most overdue first: the 203-day critical (196 over), the 203-day low
	// (23 over), then beta's 50-day high (20 over).
	wantOverdue := []struct {
		rule          string
		ageDays       int
		thresholdDays int
		overdueDays   int
	}{
		{rule: "CVE-SLA-1", ageDays: 203, thresholdDays: 7, overdueDays: 196},
		{rule: "CVE-SLA-2", ageDays: 203, thresholdDays: 180, overdueDays: 23},
		{rule: "CVE-SLA-8", ageDays: 50, thresholdDays: 30, overdueDays: 20},
	}
	for i, want := range wantOverdue {
		got := report.Overdue[i]
		if got.Finding.RuleID != want.rule || got.AgeDays != want.ageDays ||
			got.ThresholdDays != want.thresholdDays || got.OverdueDays != want.overdueDays {
			t.Errorf("overdue[%d] = %+v, want %+v", i, got, want)
		}
	}
	// The unknown-severity finding shares the May 1 first sighting but is
	// never overdue; the ignored high stays out of the report entirely.
	for _, item := range report.Overdue {
		if item.Finding.RuleID == "CVE-SLA-4" || item.Finding.RuleID == "CVE-SLA-6" {
			t.Errorf("overdue contains %q, want unknown and ignored findings excluded", item.Finding.RuleID)
		}
	}

	// The default 90-day window starts on August 22, so only the November 10
	// fix counts; its mean age is the 82 days from August 20.
	if report.FixedInWindow != 1 {
		t.Errorf("fixed_in_window = %d, want 1", report.FixedInWindow)
	}
	if report.MeanTimeToFixDays == nil || *report.MeanTimeToFixDays != 82 {
		t.Errorf("mean_time_to_fix_days = %v, want 82", report.MeanTimeToFixDays)
	}

	// A 100-day window also includes the August 20 fix (111 days old), so the
	// mean is (111+82)/2.
	wide, err := service.SLA(ctx, 0, 100)
	if err != nil {
		t.Fatalf("SLA(100 days): %v", err)
	}
	if wide.FixedInWindow != 2 {
		t.Errorf("wide fixed_in_window = %d, want 2", wide.FixedInWindow)
	}
	if wide.MeanTimeToFixDays == nil || *wide.MeanTimeToFixDays != 96.5 {
		t.Errorf("wide mean_time_to_fix_days = %v, want 96.5", wide.MeanTimeToFixDays)
	}

	// A 5-day window ends before both fixes: nothing fixed, no mean.
	narrow, err := service.SLA(ctx, 0, 5)
	if err != nil {
		t.Fatalf("SLA(5 days): %v", err)
	}
	if narrow.FixedInWindow != 0 || narrow.MeanTimeToFixDays != nil {
		t.Errorf("narrow fix stats = %d/%v, want 0/nil", narrow.FixedInWindow, narrow.MeanTimeToFixDays)
	}

	// Asset scoping narrows every number.
	scoped, err := service.SLA(ctx, alpha.ID, reports.DefaultSLAWindowDays)
	if err != nil {
		t.Fatalf("SLA(alpha): %v", err)
	}
	if scoped.OpenCount != 4 || scoped.OverdueCount != 2 || scoped.FixedInWindow != 1 {
		t.Errorf("scoped report = %+v, want open 4, overdue 2, fixed 1", scoped)
	}
	for _, item := range scoped.Overdue {
		if item.Finding.AssetID != alpha.ID {
			t.Errorf("scoped overdue contains asset %d, want only alpha", item.Finding.AssetID)
		}
	}

	betaReport, err := service.SLA(ctx, beta.ID, reports.DefaultSLAWindowDays)
	if err != nil {
		t.Fatalf("SLA(beta): %v", err)
	}
	if betaReport.OpenCount != 1 || betaReport.OverdueCount != 1 || betaReport.FixedInWindow != 0 {
		t.Errorf("beta report = %+v, want open 1, overdue 1, fixed 0", betaReport)
	}

	for _, days := range []int{-1, 0, 366} {
		if _, err := service.SLA(ctx, 0, days); !errors.Is(err, reports.ErrInvalid) {
			t.Errorf("SLA(days=%d) error = %v, want ErrInvalid", days, err)
		}
	}
	if _, err := service.SLA(ctx, -1, 90); !errors.Is(err, reports.ErrInvalid) {
		t.Errorf("SLA(asset=-1) error = %v, want ErrInvalid", err)
	}
}

// TestSLAFixedFindingsRespectsIgnoreScope checks that a fingerprint hidden by
// a live finding_states decision is not a fix, while an expired decision no
// longer hides it.
func TestSLAFixedFindingsRespectsIgnoreScope(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	now := slaAt(2026, time.November, 20, 12)
	service, err := reports.NewService(db, reports.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/sla-ignore", "Alpha")

	liveIgnored := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-IGN-1", findings.SeverityHigh)
	expiredIgnored := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-IGN-2", findings.SeverityHigh)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.May, 1, 10),
		liveIgnored, expiredIgnored)
	// Both fingerprints disappear from the August scan: both look fixed.
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.August, 20, 10))

	if err := store.SetFindingState(ctx, db, alpha.ID, liveIgnored.Fingerprint,
		store.FindingStateIgnored, "not deployed", nil); err != nil {
		t.Fatalf("SetFindingState(live): %v", err)
	}
	expired := slaAt(2026, time.July, 1, 0)
	if err := store.SetFindingState(ctx, db, alpha.ID, expiredIgnored.Fingerprint,
		store.FindingStateIgnored, "temporary", &expired); err != nil {
		t.Fatalf("SetFindingState(expired): %v", err)
	}

	// The 100-day window starts on August 12, so the August 20 fix counts.
	report, err := service.SLA(ctx, 0, 100)
	if err != nil {
		t.Fatalf("SLA: %v", err)
	}
	if report.FixedInWindow != 1 {
		t.Fatalf("fixed_in_window = %d, want 1 (the live ignore is not a fix)", report.FixedInWindow)
	}
	// May 1 to August 20 is 111 days.
	if report.MeanTimeToFixDays == nil || *report.MeanTimeToFixDays != 111 {
		t.Errorf("mean_time_to_fix_days = %v, want 111", report.MeanTimeToFixDays)
	}
}

// TestSLAFixedFindingsIgnoresOldFixes bounds the fixed side to the window: a
// fingerprint fixed long before the window is not counted, and one fixed
// inside it still is.
func TestSLAFixedFindingsIgnoresOldFixes(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	now := slaAt(2026, time.November, 20, 12)
	service, err := reports.NewService(db, reports.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/sla-window", "Alpha")

	oldFixed := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-OLD", findings.SeverityHigh)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.January, 1, 10), oldFixed)
	// February 1: oldFixed is gone, fixed 323 days before now.
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.February, 1, 10))

	recentFixed := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-SLA-NEW", findings.SeverityHigh)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.September, 1, 10), recentFixed)
	// September 10: recentFixed is gone, fixed inside the 90-day window
	// (which starts on August 22).
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.September, 10, 10))

	report, err := service.SLA(ctx, 0, reports.DefaultSLAWindowDays)
	if err != nil {
		t.Fatalf("SLA: %v", err)
	}
	if report.FixedInWindow != 1 {
		t.Fatalf("fixed_in_window = %d, want only the September fix", report.FixedInWindow)
	}
	if report.MeanTimeToFixDays == nil || *report.MeanTimeToFixDays != 9 {
		t.Errorf("mean_time_to_fix_days = %v, want 9", report.MeanTimeToFixDays)
	}
}

// TestSetSLAThresholdsValidatesAndPersists covers the service half of the
// settings contract: bad values write nothing, good ones survive a re-read.
func TestSetSLAThresholdsValidatesAndPersists(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	bad := []reports.SLAThresholds{
		{Critical: 0, High: 30, Medium: 90, Low: 180},
		{Critical: 7, High: 30, Medium: 90, Low: 3651},
	}
	for _, thresholds := range bad {
		if _, err := service.SetSLAThresholds(ctx, thresholds); !errors.Is(err, reports.ErrInvalid) {
			t.Errorf("SetSLAThresholds(%+v) error = %v, want ErrInvalid", thresholds, err)
		}
	}
	stored, err := service.SLAThresholds(ctx)
	if err != nil {
		t.Fatalf("SLAThresholds: %v", err)
	}
	if stored != (reports.SLAThresholds{Critical: 7, High: 30, Medium: 90, Low: 180}) {
		t.Fatalf("thresholds after rejected writes = %+v, want the seeded defaults", stored)
	}

	want := reports.SLAThresholds{Critical: 3, High: 14, Medium: 45, Low: 120}
	if _, err := service.SetSLAThresholds(ctx, want); err != nil {
		t.Fatalf("SetSLAThresholds: %v", err)
	}
	stored, err = service.SLAThresholds(ctx)
	if err != nil {
		t.Fatalf("SLAThresholds after write: %v", err)
	}
	if stored != want {
		t.Fatalf("thresholds = %+v, want %+v", stored, want)
	}
}

// TestSLACapsOverdueList seeds more overdue findings than the response cap and
// checks that the list stops at 500 while open_count stays exact.
func TestSLACapsOverdueList(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	now := slaAt(2026, time.November, 20, 12)
	service, err := reports.NewService(db, reports.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/sla-cap", "Alpha")

	const total = reports.MaxSLAOverdue + 1
	list := make([]findings.Finding, 0, total)
	for i := 0; i < total; i++ {
		list = append(list, newFinding(alpha.ID, findings.TypeVulnerability,
			fmt.Sprintf("CVE-SLA-CAP-%03d", i), findings.SeverityCritical))
	}
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.May, 1, 10), list...)
	// The latest scan still has every finding: all are open, all are overdue.
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, slaAt(2026, time.November, 10, 10), list...)

	report, err := service.SLA(ctx, 0, reports.DefaultSLAWindowDays)
	if err != nil {
		t.Fatalf("SLA: %v", err)
	}
	if report.OpenCount != total {
		t.Errorf("open_count = %d, want %d", report.OpenCount, total)
	}
	if len(report.Overdue) != reports.MaxSLAOverdue {
		t.Errorf("overdue entries = %d, want the %d cap", len(report.Overdue), reports.MaxSLAOverdue)
	}
	if report.OverdueCount != reports.MaxSLAOverdue {
		t.Errorf("overdue_count = %d, want %d", report.OverdueCount, reports.MaxSLAOverdue)
	}
	if !report.OverdueTruncated {
		t.Error("overdue_truncated = false, want true")
	}
}
