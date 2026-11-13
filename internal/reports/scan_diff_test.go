package reports_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
)

// diffFixture seeds one asset with three scans: a succeeded first scan, a
// failed scan in between, and a succeeded second scan. The second scan drops
// the critical finding, keeps the medium one and adds a high and a low one.
type diffFixture struct {
	service *reports.Service
	db      *sql.DB
	asset   findings.Asset
	first   int64
	failed  int64
	second  int64

	critical  findings.Finding
	medium    findings.Finding
	newHigh   findings.Finding
	newLow    findings.Finding
	failedHit findings.Finding
}

func newDiffFixture(t *testing.T) diffFixture {
	t.Helper()

	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}
	asset := seedAsset(t, db, findings.AssetKindPath, "/tmp/diff", "Diff")

	f := diffFixture{service: service, db: db, asset: asset}
	f.critical = newFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical)
	f.medium = newFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityMedium)
	f.newHigh = newFinding(asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh)
	f.newLow = newFinding(asset.ID, findings.TypeLicense, "MIT", findings.SeverityLow)
	f.failedHit = newFinding(asset.ID, findings.TypeSecret, "private-key", findings.SeverityCritical)

	f.first = seedScan(t, db, asset.ID, store.ScanStatusSucceeded, at(9), f.critical, f.medium)
	f.failed = seedScan(t, db, asset.ID, store.ScanStatusFailed, at(10), f.failedHit)
	f.second = seedScan(t, db, asset.ID, store.ScanStatusSucceeded, at(11), f.medium, f.newLow, f.newHigh)
	return f
}

// fingerprints reads a diff group's fingerprints in order.
func fingerprints(list []reports.Finding) []string {
	out := make([]string, 0, len(list))
	for _, finding := range list {
		out = append(out, finding.Fingerprint)
	}
	return out
}

// TestScanDiffDefaultAgainst covers the default baseline: the newest succeeded
// scan older than the current one, skipping the failed scan in between.
func TestScanDiffDefaultAgainst(t *testing.T) {
	f := newDiffFixture(t)

	diff, err := f.service.ScanDiff(context.Background(), f.second, 0)
	if err != nil {
		t.Fatalf("ScanDiff: %v", err)
	}
	if diff.ScanID != f.second {
		t.Errorf("ScanID = %d, want %d", diff.ScanID, f.second)
	}
	if diff.AgainstScanID == nil || *diff.AgainstScanID != f.first {
		t.Fatalf("AgainstScanID = %v, want %d (the failed scan must not be the baseline)", diff.AgainstScanID, f.first)
	}

	// Most severe first: the new high finding precedes the new low one.
	if got, want := fingerprints(diff.New), []string{f.newHigh.Fingerprint, f.newLow.Fingerprint}; !slices.Equal(got, want) {
		t.Errorf("New = %v, want %v", got, want)
	}
	if got, want := fingerprints(diff.Fixed), []string{f.critical.Fingerprint}; !slices.Equal(got, want) {
		t.Errorf("Fixed = %v, want %v", got, want)
	}
	if got, want := fingerprints(diff.Persisting), []string{f.medium.Fingerprint}; !slices.Equal(got, want) {
		t.Errorf("Persisting = %v, want %v", got, want)
	}

	wantCounts := reports.ScanDiffCounts{
		New:        reports.SeverityTotals{High: 1, Low: 1},
		Fixed:      reports.SeverityTotals{Critical: 1},
		Persisting: reports.SeverityTotals{Medium: 1},
	}
	if diff.Counts != wantCounts {
		t.Errorf("Counts = %+v, want %+v", diff.Counts, wantCounts)
	}
}

// TestScanDiffExplicitAgainst compares against the scan named in the query.
func TestScanDiffExplicitAgainst(t *testing.T) {
	f := newDiffFixture(t)

	diff, err := f.service.ScanDiff(context.Background(), f.second, f.first)
	if err != nil {
		t.Fatalf("ScanDiff: %v", err)
	}
	if diff.AgainstScanID == nil || *diff.AgainstScanID != f.first {
		t.Fatalf("AgainstScanID = %v, want %d", diff.AgainstScanID, f.first)
	}
	if got, want := fingerprints(diff.Fixed), []string{f.critical.Fingerprint}; !slices.Equal(got, want) {
		t.Errorf("Fixed = %v, want %v", got, want)
	}

	// The reverse direction reports the newer findings as fixed.
	reversed, err := f.service.ScanDiff(context.Background(), f.first, f.second)
	if err != nil {
		t.Fatalf("ScanDiff(reversed): %v", err)
	}
	if got, want := fingerprints(reversed.New), []string{f.critical.Fingerprint}; !slices.Equal(got, want) {
		t.Errorf("reversed New = %v, want %v", got, want)
	}
	if got, want := fingerprints(reversed.Fixed), []string{f.newHigh.Fingerprint, f.newLow.Fingerprint}; !slices.Equal(got, want) {
		t.Errorf("reversed Fixed = %v, want %v", got, want)
	}
}

// TestScanDiffFirstScan reports every finding as new when there is no earlier
// succeeded scan to compare with.
func TestScanDiffFirstScan(t *testing.T) {
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}
	asset := seedAsset(t, db, findings.AssetKindPath, "/tmp/first", "First")
	critical := newFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical)
	high := newFinding(asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh)
	scanID := seedScan(t, db, asset.ID, store.ScanStatusSucceeded, at(9), high, critical)

	diff, err := service.ScanDiff(context.Background(), scanID, 0)
	if err != nil {
		t.Fatalf("ScanDiff: %v", err)
	}
	if diff.AgainstScanID != nil {
		t.Fatalf("AgainstScanID = %v, want nil", *diff.AgainstScanID)
	}
	if got, want := fingerprints(diff.New), []string{critical.Fingerprint, high.Fingerprint}; !slices.Equal(got, want) {
		t.Errorf("New = %v, want %v", got, want)
	}
	if len(diff.Fixed) != 0 || len(diff.Persisting) != 0 {
		t.Errorf("Fixed/Persisting = %v/%v, want empty", diff.Fixed, diff.Persisting)
	}
	wantCounts := reports.ScanDiffCounts{New: reports.SeverityTotals{Critical: 1, High: 1}}
	if diff.Counts != wantCounts {
		t.Errorf("Counts = %+v, want %+v", diff.Counts, wantCounts)
	}
}

// TestScanDiffRejects covers every refusal: unknown ids, a scan against itself,
// scans of different assets and scans that did not succeed.
func TestScanDiffRejects(t *testing.T) {
	f := newDiffFixture(t)
	other := seedAsset(t, f.db, findings.AssetKindRepo, "octo/other", "Other")
	otherScan := seedScan(t, f.db, other.ID, store.ScanStatusSucceeded, at(9),
		newFinding(other.ID, findings.TypeVulnerability, "CVE-2026-0009", findings.SeverityHigh))

	cases := []struct {
		name      string
		scanID    int64
		againstID int64
		want      error
	}{
		{name: "unknown scan", scanID: 999_999, want: reports.ErrNotFound},
		{name: "unknown against", scanID: f.second, againstID: 999_999, want: reports.ErrNotFound},
		{name: "against itself", scanID: f.second, againstID: f.second, want: reports.ErrInvalid},
		{name: "negative against", scanID: f.second, againstID: -1, want: reports.ErrInvalid},
		{name: "different assets", scanID: f.second, againstID: otherScan, want: reports.ErrInvalid},
		{name: "current scan failed", scanID: f.failed, want: reports.ErrConflict},
		{name: "against scan failed", scanID: f.second, againstID: f.failed, want: reports.ErrConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.service.ScanDiff(context.Background(), tc.scanID, tc.againstID)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ScanDiff(%d, %d) error = %v, want %v", tc.scanID, tc.againstID, err, tc.want)
			}
		})
	}
}
