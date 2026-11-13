package jobs_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// fakeAdvisories is an AdvisoryMatcher with a fixed answer. It records whether
// it was handed the inventory.
type fakeAdvisories struct {
	items []findings.Finding
	err   error
	pkgs  []findings.Package
}

func (f *fakeAdvisories) Name() string    { return "osv" }
func (f *fakeAdvisories) Version() string { return "test" }

func (f *fakeAdvisories) Match(_ context.Context, pkgs []findings.Package, asset findings.Asset) ([]findings.Finding, error) {
	f.pkgs = pkgs
	if f.err != nil {
		return nil, f.err
	}
	out := make([]findings.Finding, len(f.items))
	copy(out, f.items)
	for i := range out {
		out[i].AssetID = asset.ID
		out[i].Fingerprint = findings.Fingerprint(asset.ID, out[i])
	}
	return out, nil
}

// TestAdvisoriesEnrichScan proves the matcher receives the packages the
// scanners extracted and that its findings land in the stored scan.
func TestAdvisoriesEnrichScan(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/osv")

	pkg := findings.Package{Ecosystem: "npm", Name: "-harseurl", Version: "0.0.1", Path: "package-lock.json"}
	adv := &fakeAdvisories{items: []findings.Finding{{
		Type:           findings.TypeMalware,
		RuleID:         "MAL-2022-7",
		Severity:       findings.SeverityCritical,
		Title:          "Malicious code in -harseurl (npm)",
		PackageName:    "-harseurl",
		PackageVersion: "0.0.1",
		Ecosystem:      "npm",
		Location:       "package-lock.json",
		Scanner:        "osv",
	}}}

	m := newManager(t, jobs.Config{
		DB:          db,
		Sources:     map[sources.TargetKind]sources.Source{sources.KindPath: &fakeSource{kind: sources.KindPath}},
		Scanners:    []scanners.Scanner{&fakeScanner{name: "good", kinds: []sources.TargetKind{sources.KindPath}}},
		Normalizers: map[string]findings.Normalizer{"good": &fakeNormalizer{pkgs: []findings.Package{pkg}}},
		Advisories:  adv,
		Concurrency: 1,
	})

	scanID, err := m.Enqueue(context.Background(), asset.ID, "api")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	waitForStatus(t, db, scanID, store.ScanStatusSucceeded)

	if len(adv.pkgs) != 1 || adv.pkgs[0] != pkg {
		t.Fatalf("matcher inventory = %+v, want the normalizer's package", adv.pkgs)
	}
	rows, err := sqlcdb.New(db).ListFindingsByScan(context.Background(), sqlcdb.ListFindingsByScanParams{ScanID: scanID})
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if len(rows) != 1 || rows[0].Scanner != "osv" || rows[0].RuleID.String != "MAL-2022-7" {
		t.Fatalf("persisted findings = %+v, want the OSV malware finding", rows)
	}
	if statuses := scannerRunStatuses(t, db, scanID); statuses["osv"] != "succeeded" {
		t.Errorf("scanner run statuses = %v, want osv succeeded", statuses)
	}
}

// TestAdvisoryFailureDoesNotFailScan proves a network failure is recorded
// against the osv run while the scan and its other findings stand.
func TestAdvisoryFailureDoesNotFailScan(t *testing.T) {
	db := openTestDB(t)
	asset := createAsset(t, db, "path", "/tmp/osv-down")

	pkg := findings.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Path: "package-lock.json"}
	finding := findings.Finding{
		Type:     findings.TypeVulnerability,
		RuleID:   "CVE-2026-0001",
		Severity: findings.SeverityHigh,
		Title:    "example vulnerability",
		Location: "package.json",
	}

	m := newManager(t, jobs.Config{
		DB:          db,
		Sources:     map[sources.TargetKind]sources.Source{sources.KindPath: &fakeSource{kind: sources.KindPath}},
		Scanners:    []scanners.Scanner{&fakeScanner{name: "good", kinds: []sources.TargetKind{sources.KindPath}}},
		Normalizers: map[string]findings.Normalizer{"good": &fakeNormalizer{items: []findings.Finding{finding}, pkgs: []findings.Package{pkg}}},
		Advisories:  &fakeAdvisories{err: errors.New("api.osv.dev: status 500")},
		Concurrency: 1,
	})

	scanID, err := m.Enqueue(context.Background(), asset.ID, "api")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	waitForStatus(t, db, scanID, store.ScanStatusSucceeded)

	rows, err := sqlcdb.New(db).ListFindingsByScan(context.Background(), sqlcdb.ListFindingsByScanParams{ScanID: scanID})
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if len(rows) != 1 || rows[0].RuleID.String != "CVE-2026-0001" {
		t.Fatalf("persisted findings = %+v, want the scanner's finding", rows)
	}
	if statuses := scannerRunStatuses(t, db, scanID); statuses["osv"] != "failed" {
		t.Errorf("scanner run statuses = %v, want osv failed", statuses)
	}
}
