package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
)

// fakeScanner is a Scanner + Normalizer pair for pipeline tests: it returns
// pre-built findings and never touches a scanner library.
type fakeScanner struct {
	name     string
	err      error
	findings []findings.Finding
}

func (f *fakeScanner) Name() string                     { return f.name }
func (f *fakeScanner) Version() string                  { return "test" }
func (f *fakeScanner) Supports(sources.TargetKind) bool { return true }

func (f *fakeScanner) Scan(context.Context, *sources.Workspace, scanners.Options) (*scanners.RawResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &scanners.RawResult{Scanner: f.name}, nil
}

func (f *fakeScanner) Normalize(*scanners.RawResult, findings.Asset) ([]findings.Finding, []findings.Package, error) {
	return f.findings, []findings.Package{}, nil
}

func testFinding(ruleID string) findings.Finding {
	f := findings.Finding{
		AssetID:  1,
		Type:     findings.TypeSecret,
		RuleID:   ruleID,
		Severity: findings.SeverityHigh,
		Location: "config/credentials:1",
		Scanner:  "good",
	}
	f.Fingerprint = findings.Fingerprint(f.AssetID, f)
	return f
}

func TestScanTargetPartialFailure(t *testing.T) {
	good := &fakeScanner{name: "good", findings: []findings.Finding{testFinding("aws-access-token")}}
	bad := &fakeScanner{name: "bad", err: errors.New("vuln db download failed")}

	out, err := scanTarget(context.Background(), sources.KindPath,
		[]scanners.Scanner{good, bad}, &sources.Workspace{Dir: "/tmp/ws"},
		findings.Asset{ID: 1, Kind: findings.AssetKindPath}, scanners.Options{})

	if err == nil {
		t.Fatal("scanTarget returned no error although a scanner failed")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Fatalf("error %q does not name the failed scanner", err)
	}
	if strings.Contains(err.Error(), "good") {
		t.Fatalf("error %q names a scanner that succeeded", err)
	}

	// The other scanner's findings are still part of the output.
	if len(out.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(out.Findings), out.Findings)
	}
	if out.Findings[0].Occurrences != 1 {
		t.Fatalf("occurrences = %d, want 1", out.Findings[0].Occurrences)
	}

	if len(out.ScannerRuns) != 2 {
		t.Fatalf("got %d scanner runs, want 2: %+v", len(out.ScannerRuns), out.ScannerRuns)
	}
	runs := map[string]scannerRun{}
	for _, run := range out.ScannerRuns {
		runs[run.Scanner] = run
	}
	if run := runs["good"]; run.Status != "succeeded" || run.Error != "" {
		t.Fatalf("good run = %+v, want succeeded without error", run)
	}
	if run := runs["bad"]; run.Status != "failed" || !strings.Contains(run.Error, "vuln db download failed") {
		t.Fatalf("bad run = %+v, want failed with the scanner error", run)
	}
}

func TestScanTargetMergesDuplicateFingerprints(t *testing.T) {
	// The same rule fires twice (two Dockerfile stages); one scan, one finding.
	dup := testFinding("DS-0001")
	good := &fakeScanner{name: "good", findings: []findings.Finding{dup, dup}}

	out, err := scanTarget(context.Background(), sources.KindPath,
		[]scanners.Scanner{good}, &sources.Workspace{Dir: "/tmp/ws"},
		findings.Asset{ID: 1, Kind: findings.AssetKindPath}, scanners.Options{})
	if err != nil {
		t.Fatalf("scanTarget: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(out.Findings))
	}
	if out.Findings[0].Occurrences != 2 {
		t.Fatalf("occurrences = %d, want 2", out.Findings[0].Occurrences)
	}
}
