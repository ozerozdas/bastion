package reports_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// TestNormalizeCVEID covers the accepted advisory formats and the canonical
// form the report echoes back.
func TestNormalizeCVEID(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "cve", value: "CVE-2021-44228", want: "CVE-2021-44228"},
		{name: "lower-case cve is upper-cased", value: "cve-2021-44228", want: "CVE-2021-44228"},
		{name: "surrounding space is trimmed", value: " CVE-2021-44228 ", want: "CVE-2021-44228"},
		{name: "four-digit sequence", value: "CVE-2026-1000", want: "CVE-2026-1000"},
		{name: "long sequence", value: "CVE-2024-1234567", want: "CVE-2024-1234567"},
		{name: "ghsa", value: "GHSA-1234-5678-9012", want: "GHSA-1234-5678-9012"},
		{name: "lower-case ghsa", value: "ghsa-abcd-efgh-ijkl", want: "ghsa-abcd-efgh-ijkl"},
		{name: "empty", value: "", wantErr: true},
		{name: "not an advisory", value: "log4j", wantErr: true},
		{name: "short cve year", value: "CVE-21-1234", wantErr: true},
		{name: "short cve sequence", value: "CVE-2021-123", wantErr: true},
		{name: "short ghsa", value: "GHSA-1234-5678", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := reports.NormalizeCVEID(tc.value)
			if tc.wantErr {
				if !errors.Is(err, reports.ErrInvalid) {
					t.Fatalf("NormalizeCVEID(%q) error = %v, want ErrInvalid", tc.value, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeCVEID(%q): %v", tc.value, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeCVEID(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// TestCVEInsightsMatchesLatestOpenFindings seeds two live assets, an archived
// one, a superseded scan and an ignored finding, then asserts the matches,
// their first_seen scan and the asset scoping.
func TestCVEInsightsMatchesLatestOpenFindings(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db, reports.WithEPSS(fakeEPSS{
		"CVE-2021-44228": {Score: 0.99999, Percentile: 1.0},
	}))
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/cve-alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindImage, "registry/beta:latest", "Beta")
	archived := seedAsset(t, db, findings.AssetKindPath, "/tmp/cve-archived", "Archived")
	gamma := seedAsset(t, db, findings.AssetKindPath, "/tmp/cve-gamma", "Gamma")

	log4j := func() findings.Finding {
		finding := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2021-44228", findings.SeverityCritical)
		finding.PackageName = "log4j-core"
		finding.PackageVersion = "2.14.0"
		finding.FixedVersion = "2.17.0"
		finding.Fingerprint = findings.Fingerprint(alpha.ID, finding)
		return finding
	}
	firstSeenScan := seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(9), log4j())

	open := log4j()
	ignored := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2021-44228", findings.SeverityHigh)
	ignored.PackageName = "log4j-ignored"
	unrelated := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2020-1111", findings.SeverityHigh)
	latestScan := seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(11), open, ignored, unrelated)
	if err := store.SetFindingState(ctx, db, alpha.ID, ignored.Fingerprint,
		store.FindingStateIgnored, "accepted upstream", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	// The match is case-insensitive: a scanner that stored a lower-case rule id
	// still lands in the report.
	betaFinding := newFinding(beta.ID, findings.TypeVulnerability, "cve-2021-44228", findings.SeverityHigh)
	betaFinding.PackageName = "log4j-core"
	seedScan(t, db, beta.ID, store.ScanStatusSucceeded, at(10), betaFinding)

	archivedFinding := newFinding(archived.ID, findings.TypeVulnerability, "CVE-2021-44228", findings.SeverityCritical)
	seedScan(t, db, archived.ID, store.ScanStatusSucceeded, at(8), archivedFinding)
	if _, err := sqlcdb.New(db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ID:         archived.ID,
		ArchivedAt: sql.NullString{String: at(12).Format(time.RFC3339), Valid: true},
	}); err != nil {
		t.Fatalf("ArchiveAsset: %v", err)
	}

	ghsa := newFinding(gamma.ID, findings.TypeVulnerability, "GHSA-1234-5678-9012", findings.SeverityMedium)
	seedScan(t, db, gamma.ID, store.ScanStatusSucceeded, at(7), ghsa)

	insights, err := service.CVEInsights(ctx, "cve-2021-44228", 0)
	if err != nil {
		t.Fatalf("CVEInsights: %v", err)
	}
	if insights.CVE != "CVE-2021-44228" {
		t.Errorf("cve = %q, want the upper-cased id", insights.CVE)
	}
	if insights.EPSS == nil || insights.EPSS.Score != 0.99999 || insights.EPSS.Percentile != 1.0 {
		t.Fatalf("epss = %+v, want the seeded score", insights.EPSS)
	}
	if len(insights.Assets) != 2 {
		t.Fatalf("assets = %+v, want alpha and beta only", insights.Assets)
	}
	first := insights.Assets[0]
	if first.AssetID != alpha.ID || first.DisplayName != "Alpha" || first.Kind != string(findings.AssetKindPath) {
		t.Errorf("first asset = %+v, want Alpha", first)
	}
	if first.Severity != string(findings.SeverityCritical) || first.PackageName != "log4j-core" ||
		first.PackageVersion != "2.14.0" || first.FixedVersion != "2.17.0" {
		t.Errorf("first asset = %+v, want the open log4j finding", first)
	}
	if first.FirstSeen == nil || !first.FirstSeen.Equal(at(9)) {
		t.Errorf("alpha first_seen = %v, want %v (the first scan)", first.FirstSeen, at(9))
	}
	if latestScan <= firstSeenScan {
		t.Fatalf("test setup: scans out of order (%d, %d)", latestScan, firstSeenScan)
	}
	second := insights.Assets[1]
	if second.AssetID != beta.ID || second.FirstSeen == nil || !second.FirstSeen.Equal(at(10)) {
		t.Errorf("beta asset = %+v, want first_seen %v", second, at(10))
	}

	scoped, err := service.CVEInsights(ctx, "CVE-2021-44228", alpha.ID)
	if err != nil {
		t.Fatalf("CVEInsights(alpha): %v", err)
	}
	if len(scoped.Assets) != 1 || scoped.Assets[0].AssetID != alpha.ID {
		t.Errorf("scoped assets = %+v, want only alpha", scoped.Assets)
	}

	unknown, err := service.CVEInsights(ctx, "CVE-2019-0000", 0)
	if err != nil {
		t.Fatalf("CVEInsights(unknown): %v", err)
	}
	if len(unknown.Assets) != 0 || unknown.Assets == nil {
		t.Errorf("unknown assets = %+v, want an empty list", unknown.Assets)
	}
	if unknown.EPSS != nil {
		t.Errorf("unknown epss = %+v, want nil", unknown.EPSS)
	}

	byGHSA, err := service.CVEInsights(ctx, "ghsa-1234-5678-9012", 0)
	if err != nil {
		t.Fatalf("CVEInsights(ghsa): %v", err)
	}
	if len(byGHSA.Assets) != 1 || byGHSA.Assets[0].AssetID != gamma.ID {
		t.Errorf("ghsa assets = %+v, want gamma", byGHSA.Assets)
	}
	if byGHSA.EPSS != nil {
		t.Errorf("ghsa epss = %+v, want nil (the feed scores CVEs)", byGHSA.EPSS)
	}

	if _, err := service.CVEInsights(ctx, "not-an-advisory", 0); !errors.Is(err, reports.ErrInvalid) {
		t.Errorf("bad id error = %v, want ErrInvalid", err)
	}
	if _, err := service.CVEInsights(ctx, "CVE-2021-44228", -1); !errors.Is(err, reports.ErrInvalid) {
		t.Errorf("negative asset error = %v, want ErrInvalid", err)
	}
}
