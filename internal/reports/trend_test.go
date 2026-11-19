package reports_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// trendDay is a UTC timestamp on a seeded November day; the hour orders the
// scans of one day.
func trendDay(day, hour int) time.Time {
	return time.Date(2026, 11, day, hour, 0, 0, 0, time.UTC)
}

// TestTrendKeepsLastScanPerDay seeds two scans on one day, an ignore decision,
// a failed newer scan and an archived asset, then asserts the points, the
// window and the scoping.
func TestTrendKeepsLastScanPerDay(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	clock := trendDay(10, 23)
	service, err := reports.NewService(db, reports.WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/trend-alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/trend-beta", "Beta")
	archived := seedAsset(t, db, findings.AssetKindPath, "/tmp/trend-archived", "Archived")

	// Alpha day 8: one low and one unknown finding.
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, trendDay(8, 10),
		newFinding(alpha.ID, findings.TypeVulnerability, "CVE-TREND-1", findings.SeverityLow),
		newFinding(alpha.ID, findings.TypeVulnerability, "CVE-TREND-2", findings.SeverityUnknown))

	// Alpha day 10: an earlier scan must lose to the later one.
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, trendDay(10, 9),
		newFinding(alpha.ID, findings.TypeVulnerability, "CVE-TREND-3", findings.SeverityCritical),
		newFinding(alpha.ID, findings.TypeVulnerability, "CVE-TREND-4", findings.SeverityHigh))

	critical := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-TREND-5", findings.SeverityCritical)
	medium := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-TREND-6", findings.SeverityMedium)
	ignored := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-TREND-7", findings.SeverityHigh)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, trendDay(10, 11), critical, medium, ignored)
	if err := store.SetFindingState(ctx, db, alpha.ID, ignored.Fingerprint,
		store.FindingStateIgnored, "accepted upstream", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	// A failed scan later on the same day must not win the day.
	seedScan(t, db, alpha.ID, store.ScanStatusFailed, trendDay(10, 12),
		newFinding(alpha.ID, findings.TypeSecret, "private-key", findings.SeverityCritical))

	seedScan(t, db, beta.ID, store.ScanStatusSucceeded, trendDay(9, 10),
		newFinding(beta.ID, findings.TypeVulnerability, "CVE-TREND-8", findings.SeverityCritical))

	seedScan(t, db, archived.ID, store.ScanStatusSucceeded, trendDay(10, 10),
		newFinding(archived.ID, findings.TypeVulnerability, "CVE-TREND-9", findings.SeverityCritical))
	if _, err := sqlcdb.New(db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ID:         archived.ID,
		ArchivedAt: sql.NullString{String: trendDay(10, 13).Format(time.RFC3339), Valid: true},
	}); err != nil {
		t.Fatalf("ArchiveAsset: %v", err)
	}

	series, err := service.Trend(ctx, 0, 3)
	if err != nil {
		t.Fatalf("Trend: %v", err)
	}
	if len(series) != 2 {
		t.Fatalf("series = %+v, want alpha and beta only", series)
	}
	if series[0].AssetID != alpha.ID || series[0].DisplayName != "Alpha" ||
		series[1].AssetID != beta.ID || series[1].DisplayName != "Beta" {
		t.Errorf("series order = %+v, want Alpha then Beta", series)
	}

	wantAlpha := []reports.TrendPoint{
		{Date: "2026-11-08", Low: 1, Unknown: 1},
		{Date: "2026-11-10", Critical: 1, Medium: 1},
	}
	if !slices.Equal(series[0].Points, wantAlpha) {
		t.Errorf("alpha points = %+v, want %+v", series[0].Points, wantAlpha)
	}
	wantBeta := []reports.TrendPoint{{Date: "2026-11-09", Critical: 1}}
	if !slices.Equal(series[1].Points, wantBeta) {
		t.Errorf("beta points = %+v, want %+v", series[1].Points, wantBeta)
	}

	// A two-day window starts at 11-09, so alpha's 11-08 point is gone.
	narrow, err := service.Trend(ctx, 0, 2)
	if err != nil {
		t.Fatalf("Trend(2 days): %v", err)
	}
	if len(narrow) != 2 || len(narrow[0].Points) != 1 || narrow[0].Points[0].Date != "2026-11-10" {
		t.Errorf("narrow trend = %+v, want only the 11-10 alpha point", narrow)
	}

	scoped, err := service.Trend(ctx, alpha.ID, 3)
	if err != nil {
		t.Fatalf("Trend(alpha): %v", err)
	}
	if len(scoped) != 1 || scoped[0].AssetID != alpha.ID {
		t.Errorf("scoped trend = %+v, want only alpha", scoped)
	}

	for _, days := range []int{-1, 0, 366} {
		if _, err := service.Trend(ctx, 0, days); !errors.Is(err, reports.ErrInvalid) {
			t.Errorf("Trend(days=%d) error = %v, want ErrInvalid", days, err)
		}
	}
	if _, err := service.Trend(ctx, -1, 90); !errors.Is(err, reports.ErrInvalid) {
		t.Errorf("Trend(asset=-1) error = %v, want ErrInvalid", err)
	}
}
