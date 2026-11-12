package store_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

func TestLoadScanReportReadsBackSucceededScan(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createTestAsset(ctx, t, queries)
	scan := createTestScan(ctx, t, queries, asset.ID)

	critical := testFinding(asset.ID, findings.TypeSecret, "aws-access-key", findings.SeverityCritical)
	critical.References = []string{"https://example.test/aws", "https://example.test/keys"}
	cvss := 9.8
	critical.CVSS = &cvss
	medium := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityMedium)

	res := store.ScanResult{
		Status:     store.ScanStatusSucceeded,
		TargetRef:  "sha-abc123",
		FinishedAt: timeAt(10),
		ScannerRuns: []store.ScannerRun{
			{
				Scanner:        "gitleaks",
				ScannerVersion: "8.30.1",
				Status:         "succeeded",
				DurationMS:     durationMS(42),
			},
			{
				Scanner:        "trivy",
				ScannerVersion: "0.76.2",
				DBVersion:      "2026-11-11",
				Status:         "succeeded",
				RawPath:        "/tmp/trivy.json",
			},
		},
		Packages: []findings.Package{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", PURL: "pkg:npm/left-pad@1.3.0", Path: "package-lock.json"},
			{Ecosystem: "go", Name: "example", Version: "1.0.0", Direct: boolPtr(true)},
		},
		Findings: []findings.Finding{medium, critical},
	}
	if err := store.SaveScanResult(ctx, db, scan.ID, res); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}

	report, err := store.LoadScanReport(ctx, db, scan.ID)
	if err != nil {
		t.Fatalf("LoadScanReport: %v", err)
	}
	if report.ScanID != scan.ID {
		t.Errorf("ScanID = %d, want %d", report.ScanID, scan.ID)
	}
	if report.Status != store.ScanStatusSucceeded {
		t.Errorf("Status = %q, want %q", report.Status, store.ScanStatusSucceeded)
	}
	if report.Error != "" {
		t.Errorf("Error = %q, want empty for a succeeded scan", report.Error)
	}
	if report.TargetRef != "sha-abc123" {
		t.Errorf("TargetRef = %q, want sha-abc123", report.TargetRef)
	}

	if len(report.ScannerRuns) != 2 {
		t.Fatalf("ScannerRuns = %d, want 2", len(report.ScannerRuns))
	}
	first := report.ScannerRuns[0]
	if first.Scanner != "gitleaks" || first.ScannerVersion != "8.30.1" || first.Status != "succeeded" {
		t.Errorf("first scanner run = %+v, want gitleaks 8.30.1 succeeded", first)
	}
	if first.DurationMS == nil || *first.DurationMS != 42 {
		t.Errorf("gitleaks DurationMS = %v, want 42", first.DurationMS)
	}
	if first.DBVersion != "" || first.RawPath != "" || first.Error != "" {
		t.Errorf("gitleaks optional fields = %+v, want empty", first)
	}
	second := report.ScannerRuns[1]
	if second.Scanner != "trivy" || second.DBVersion != "2026-11-11" {
		t.Errorf("second scanner run = %+v, want trivy with its DB version", second)
	}
	if second.DurationMS != nil {
		t.Errorf("trivy DurationMS = %v, want nil for an unset duration", *second.DurationMS)
	}
	if second.RawPath != "/tmp/trivy.json" {
		t.Errorf("trivy RawPath = %q, want /tmp/trivy.json", second.RawPath)
	}

	// ListPackagesByScan orders by ecosystem, so go precedes npm.
	if len(report.Packages) != 2 {
		t.Fatalf("Packages = %d, want 2", len(report.Packages))
	}
	if got := report.Packages[0]; got.Ecosystem != "go" || got.Name != "example" || got.Version != "1.0.0" {
		t.Errorf("package[0] = %+v, want go/example@1.0.0", got)
	}
	if report.Packages[0].Direct == nil || !*report.Packages[0].Direct {
		t.Errorf("package[0].Direct = %v, want true", report.Packages[0].Direct)
	}
	if got := report.Packages[1]; got.Ecosystem != "npm" || got.PURL != "pkg:npm/left-pad@1.3.0" || got.Path != "package-lock.json" {
		t.Errorf("package[1] = %+v, want the npm package with purl and path", got)
	}
	if report.Packages[1].Direct != nil {
		t.Errorf("package[1].Direct = %v, want nil when the scanner did not report it", *report.Packages[1].Direct)
	}

	// Findings are most severe first, so the critical secret leads.
	if len(report.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2", len(report.Findings))
	}
	got := report.Findings[0]
	if got.Title != critical.Title || got.Severity != findings.SeverityCritical {
		t.Errorf("finding[0] = %+v, want the critical secret", got)
	}
	if got.Type != findings.TypeSecret || got.RuleID != "aws-access-key" || got.Scanner != "trivy" {
		t.Errorf("finding[0] identity = %+v, want the stored secret fields", got)
	}
	if !slices.Equal(got.References, critical.References) {
		t.Errorf("finding[0].References = %v, want %v", got.References, critical.References)
	}
	if got.CVSS == nil || *got.CVSS != cvss {
		t.Errorf("finding[0].CVSS = %v, want %v", got.CVSS, cvss)
	}
	if got.Fingerprint != critical.Fingerprint || got.Occurrences != 1 {
		t.Errorf("finding[0] fingerprint/occurrences = %q/%d, want %q/1", got.Fingerprint, got.Occurrences, critical.Fingerprint)
	}
	if report.Findings[1].Title != medium.Title {
		t.Errorf("finding[1] = %+v, want the medium vulnerability", report.Findings[1])
	}

	// Nothing is ignored, so Open holds every finding in the same order.
	if len(report.Open) != len(report.Findings) {
		t.Fatalf("Open = %d, want all %d findings", len(report.Open), len(report.Findings))
	}
	for i, f := range report.Open {
		if f.Fingerprint != report.Findings[i].Fingerprint {
			t.Errorf("Open[%d] = %s, want %s", i, f.Fingerprint, report.Findings[i].Fingerprint)
		}
	}
}

func TestLoadScanReportExcludesIgnoredFromOpen(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createTestAsset(ctx, t, queries)
	scan := createTestScan(ctx, t, queries, asset.ID)

	ignored := testFinding(asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh)
	open := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityHigh)
	if err := store.SaveScanResult(ctx, db, scan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{ignored, open},
	}); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}
	if err := store.SetFindingState(ctx, db, asset.ID, ignored.Fingerprint, store.FindingStateIgnored, "test key"); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	report, err := store.LoadScanReport(ctx, db, scan.ID)
	if err != nil {
		t.Fatalf("LoadScanReport: %v", err)
	}
	// Ignored findings stay part of what the scan produced.
	if len(report.Findings) != 2 {
		t.Fatalf("Findings = %d, want both findings", len(report.Findings))
	}
	if len(report.Open) != 1 {
		t.Fatalf("Open = %d, want only the unignored finding", len(report.Open))
	}
	if report.Open[0].Fingerprint != open.Fingerprint {
		t.Fatalf("Open[0] = %q, want %q", report.Open[0].Fingerprint, open.Fingerprint)
	}

	// Clearing the decision brings the finding back to Open.
	if err := store.ClearFindingState(ctx, db, asset.ID, ignored.Fingerprint); err != nil {
		t.Fatalf("ClearFindingState: %v", err)
	}
	report, err = store.LoadScanReport(ctx, db, scan.ID)
	if err != nil {
		t.Fatalf("LoadScanReport after clear: %v", err)
	}
	if len(report.Open) != 2 {
		t.Fatalf("Open after clear = %d, want both findings", len(report.Open))
	}
}

func TestLoadScanReportEmptyReferences(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createTestAsset(ctx, t, queries)
	scan := createTestScan(ctx, t, queries, asset.ID)

	// No References set: the column stores [] and the report must not invent
	// a reference list.
	finding := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0003", findings.SeverityLow)
	if err := store.SaveScanResult(ctx, db, scan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{finding},
	}); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}

	report, err := store.LoadScanReport(ctx, db, scan.ID)
	if err != nil {
		t.Fatalf("LoadScanReport: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(report.Findings))
	}
	if refs := report.Findings[0].References; len(refs) != 0 {
		t.Fatalf("References = %v, want empty", refs)
	}
}

func TestLoadScanReportMissingScan(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)

	_, err := store.LoadScanReport(ctx, db, 999)
	if err == nil {
		t.Fatal("LoadScanReport on a missing scan succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("LoadScanReport error = %v, want the does-not-exist message", err)
	}
}
