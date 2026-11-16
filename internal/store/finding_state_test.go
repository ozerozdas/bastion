package store_test

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// createAssetAt resolves a distinct path asset per ref, so a test can compare
// two assets that carry the same fingerprint string.
func createAssetAt(ctx context.Context, t *testing.T, queries *sqlcdb.Queries, ref string) sqlcdb.Asset {
	t.Helper()

	asset, err := queries.GetOrCreateAsset(ctx, sqlcdb.GetOrCreateAssetParams{
		Kind:         "path",
		DisplayName:  ref,
		Ref:          ref,
		MetadataJSON: "{}",
		CreatedAt:    "2026-11-11T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(%q): %v", ref, err)
	}
	return asset
}

func TestFindingStateHidesOnlyItsOwnAsset(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createAssetAt(ctx, t, queries, "/tmp/alpha")
	other := createAssetAt(ctx, t, queries, "/tmp/beta")

	finding := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityHigh)

	first := createTestScan(ctx, t, queries, asset.ID)
	if err := store.SaveScanResult(ctx, db, first.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{finding},
	}); err != nil {
		t.Fatalf("SaveScanResult(first scan): %v", err)
	}

	if err := store.SetFindingState(ctx, db, asset.ID, finding.Fingerprint, store.FindingStateIgnored, "  accepted upstream  ", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	// The next scan rediscovers the same fingerprint; the decision hides it
	// without touching the stored findings row.
	second := createTestScan(ctx, t, queries, asset.ID)
	if err := store.SaveScanResult(ctx, db, second.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{finding},
	}); err != nil {
		t.Fatalf("SaveScanResult(second scan): %v", err)
	}

	rows, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: second.ID})
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("findings = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.Status != store.FindingStateIgnored {
		t.Fatalf("status = %q, want ignored", got.Status)
	}
	if !got.State.Valid || got.State.String != store.FindingStateIgnored {
		t.Fatalf("state = %+v, want ignored", got.State)
	}
	if !got.Reason.Valid || got.Reason.String != "accepted upstream" {
		t.Fatalf("reason = %+v, want the trimmed reason", got.Reason)
	}

	ignored, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{
		ScanID: second.ID,
		Status: store.FindingStateIgnored,
	})
	if err != nil {
		t.Fatalf("ListFindingsByScan(status ignored): %v", err)
	}
	if len(ignored) != 1 {
		t.Fatalf("ignored findings = %d, want 1", len(ignored))
	}
	open, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{
		ScanID: second.ID,
		Status: "open",
	})
	if err != nil {
		t.Fatalf("ListFindingsByScan(status open): %v", err)
	}
	if len(open) != 0 {
		t.Fatalf("open findings = %d, want 0", len(open))
	}

	// The same fingerprint string on another asset is unaffected.
	mirror := testFinding(other.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityHigh)
	mirror.Fingerprint = finding.Fingerprint
	otherScan := createTestScan(ctx, t, queries, other.ID)
	if err := store.SaveScanResult(ctx, db, otherScan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{mirror},
	}); err != nil {
		t.Fatalf("SaveScanResult(other asset): %v", err)
	}

	otherRows, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: otherScan.ID})
	if err != nil {
		t.Fatalf("ListFindingsByScan(other asset): %v", err)
	}
	if len(otherRows) != 1 || otherRows[0].Status != "open" || otherRows[0].State.Valid {
		t.Fatalf("other asset finding = %+v, want one open finding without state", otherRows)
	}

	if _, err := queries.GetFindingState(ctx, sqlcdb.GetFindingStateParams{
		AssetID:     other.ID,
		Fingerprint: finding.Fingerprint,
	}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetFindingState(other asset) error = %v, want sql.ErrNoRows", err)
	}

	states, err := queries.ListFindingStatesByAsset(ctx, asset.ID)
	if err != nil {
		t.Fatalf("ListFindingStatesByAsset: %v", err)
	}
	if len(states) != 1 || states[0].Fingerprint != finding.Fingerprint {
		t.Fatalf("states = %+v, want the ignored fingerprint", states)
	}

	// Latest findings compute the same effective status.
	latest, err := queries.ListLatestFindings(ctx, sqlcdb.ListLatestFindingsParams{AssetID: asset.ID})
	if err != nil {
		t.Fatalf("ListLatestFindings: %v", err)
	}
	if len(latest) != 1 || latest[0].ScanID != second.ID || latest[0].Status != store.FindingStateIgnored {
		t.Fatalf("latest findings of the ignored asset = %+v, want the ignored finding of scan %d", latest, second.ID)
	}
	latestOther, err := queries.ListLatestFindings(ctx, sqlcdb.ListLatestFindingsParams{AssetID: other.ID})
	if err != nil {
		t.Fatalf("ListLatestFindings(other asset): %v", err)
	}
	if len(latestOther) != 1 || latestOther[0].Status != "open" {
		t.Fatalf("latest findings of the other asset = %+v, want one open finding", latestOther)
	}
}

func TestSetFindingStateReplacesDecision(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createAssetAt(ctx, t, queries, "/tmp/alpha")
	finding := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityHigh)
	scan := createTestScan(ctx, t, queries, asset.ID)
	if err := store.SaveScanResult(ctx, db, scan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{finding},
	}); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}

	if err := store.SetFindingState(ctx, db, asset.ID, finding.Fingerprint, store.FindingStateIgnored, "first", nil); err != nil {
		t.Fatalf("SetFindingState(ignored): %v", err)
	}
	if err := store.SetFindingState(ctx, db, asset.ID, finding.Fingerprint, store.FindingStateFalsePositive, "scanner false match", nil); err != nil {
		t.Fatalf("SetFindingState(false_positive): %v", err)
	}

	states, err := queries.ListFindingStatesByAsset(ctx, asset.ID)
	if err != nil {
		t.Fatalf("ListFindingStatesByAsset: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("states = %d, want the replaced decision", len(states))
	}
	if states[0].State != store.FindingStateFalsePositive || !states[0].Reason.Valid || states[0].Reason.String != "scanner false match" {
		t.Fatalf("state = %+v, want false_positive with the new reason", states[0])
	}

	// Every state hides the finding, so the effective status stays ignored;
	// the state tells the UI which decision it was.
	rows, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if len(rows) != 1 || rows[0].Status != store.FindingStateIgnored {
		t.Fatalf("findings = %+v, want one finding with effective status ignored", rows)
	}
	if !rows[0].State.Valid || rows[0].State.String != store.FindingStateFalsePositive {
		t.Fatalf("row state = %+v, want false_positive", rows[0].State)
	}

	// Asset B has never seen a decision; a random asset keeps its own rows.
	other := createAssetAt(ctx, t, queries, "/tmp/beta")
	if _, err := queries.GetFindingState(ctx, sqlcdb.GetFindingStateParams{
		AssetID:     other.ID,
		Fingerprint: finding.Fingerprint,
	}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetFindingState(other asset) error = %v, want sql.ErrNoRows", err)
	}
}

func TestSetFindingStateValidatesInput(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createAssetAt(ctx, t, queries, "/tmp/alpha")
	const fingerprint = "abc123"

	cases := []struct {
		name        string
		fingerprint string
		state       string
		reason      string
		want        string
	}{
		{
			name:        "empty reason",
			fingerprint: fingerprint,
			state:       store.FindingStateIgnored,
			reason:      "",
			want:        "a reason is required",
		},
		{
			name:        "whitespace reason",
			fingerprint: fingerprint,
			state:       store.FindingStateAcceptedRisk,
			reason:      " \t\n ",
			want:        "a reason is required",
		},
		{
			name:        "unknown state",
			fingerprint: fingerprint,
			state:       "muted",
			reason:      "looks noisy",
			want:        `state "muted" is not one of`,
		},
		{
			name:        "empty state",
			fingerprint: fingerprint,
			state:       "",
			reason:      "looks noisy",
			want:        `state "" is not one of`,
		},
		{
			name:        "blank fingerprint",
			fingerprint: "   ",
			state:       store.FindingStateIgnored,
			reason:      "looks noisy",
			want:        "fingerprint is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := store.SetFindingState(ctx, db, asset.ID, tc.fingerprint, tc.state, tc.reason, nil)
			if err == nil {
				t.Fatalf("SetFindingState(%q, %q, %q) succeeded, want an error", tc.fingerprint, tc.state, tc.reason)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}

	states, err := queries.ListFindingStatesByAsset(ctx, asset.ID)
	if err != nil {
		t.Fatalf("ListFindingStatesByAsset: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("states = %+v, want none after rejected input", states)
	}
}

func TestSetFindingStatesIsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createAssetAt(ctx, t, queries, "/tmp/alpha")
	other := createAssetAt(ctx, t, queries, "/tmp/beta")

	first := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityHigh)
	second := testFinding(asset.ID, findings.TypeSecret, "aws-key", findings.SeverityMedium)
	elsewhere := testFinding(other.ID, findings.TypeVulnerability, "CVE-2026-0002", findings.SeverityLow)

	// The two findings live in different scans: a decision may name any
	// finding the asset has, not only the ones of its latest scan.
	firstScan := createTestScan(ctx, t, queries, asset.ID)
	if err := store.SaveScanResult(ctx, db, firstScan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{first},
	}); err != nil {
		t.Fatalf("SaveScanResult(first): %v", err)
	}
	secondScan := createTestScan(ctx, t, queries, asset.ID)
	if err := store.SaveScanResult(ctx, db, secondScan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{second},
	}); err != nil {
		t.Fatalf("SaveScanResult(second): %v", err)
	}
	otherScan := createTestScan(ctx, t, queries, other.ID)
	if err := store.SaveScanResult(ctx, db, otherScan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{elsewhere},
	}); err != nil {
		t.Fatalf("SaveScanResult(other): %v", err)
	}

	// A fingerprint that belongs to another asset is unknown for this one, so
	// the whole batch is rejected and the known fingerprint is not written.
	err := store.SetFindingStates(ctx, db, asset.ID,
		[]string{first.Fingerprint, elsewhere.Fingerprint}, store.FindingStateIgnored, "accepted upstream", nil)
	var unknown *store.UnknownFingerprintsError
	if !errors.As(err, &unknown) {
		t.Fatalf("SetFindingStates with an unknown fingerprint = %v, want *UnknownFingerprintsError", err)
	}
	if unknown.AssetID != asset.ID {
		t.Errorf("unknown error asset = %d, want %d", unknown.AssetID, asset.ID)
	}
	if len(unknown.Fingerprints) != 1 || unknown.Fingerprints[0] != elsewhere.Fingerprint {
		t.Errorf("unknown fingerprints = %v, want only %q", unknown.Fingerprints, elsewhere.Fingerprint)
	}
	states, err := queries.ListFindingStatesByAsset(ctx, asset.ID)
	if err != nil {
		t.Fatalf("ListFindingStatesByAsset: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("states = %+v, want none after the rejected batch", states)
	}

	// The valid batch lands as one decision, deduplicated, with a trimmed
	// shared reason.
	if err := store.SetFindingStates(ctx, db, asset.ID,
		[]string{first.Fingerprint, second.Fingerprint, first.Fingerprint},
		store.FindingStateAcceptedRisk, "  shared reason  ", nil); err != nil {
		t.Fatalf("SetFindingStates: %v", err)
	}
	states, err = queries.ListFindingStatesByAsset(ctx, asset.ID)
	if err != nil {
		t.Fatalf("ListFindingStatesByAsset: %v", err)
	}
	if len(states) != 2 {
		t.Fatalf("states = %+v, want one per fingerprint", states)
	}
	for _, state := range states {
		if state.State != store.FindingStateAcceptedRisk {
			t.Errorf("state of %q = %q, want accepted_risk", state.Fingerprint, state.State)
		}
		if !state.Reason.Valid || state.Reason.String != "shared reason" {
			t.Errorf("reason of %q = %+v, want the trimmed reason", state.Fingerprint, state.Reason)
		}
	}

	// The other asset's finding is still open: a batch never leaks across
	// assets.
	otherStates, err := queries.ListFindingStatesByAsset(ctx, other.ID)
	if err != nil {
		t.Fatalf("ListFindingStatesByAsset(other): %v", err)
	}
	if len(otherStates) != 0 {
		t.Fatalf("other asset states = %+v, want none", otherStates)
	}
}

func TestSetFindingStatesValidatesInput(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createAssetAt(ctx, t, queries, "/tmp/alpha")

	tooMany := make([]string, store.MaxFindingStateBatch+1)
	for i := range tooMany {
		tooMany[i] = "fp-" + strconv.Itoa(i)
	}

	cases := []struct {
		name         string
		fingerprints []string
		state        string
		reason       string
		want         string
	}{
		{
			name:         "no fingerprints",
			fingerprints: nil,
			state:        store.FindingStateIgnored,
			reason:       "looks noisy",
			want:         "at least one fingerprint",
		},
		{
			name:         "over the cap",
			fingerprints: tooMany,
			state:        store.FindingStateIgnored,
			reason:       "looks noisy",
			want:         "at most 5000",
		},
		{
			name:         "blank fingerprint",
			fingerprints: []string{"abc123", "   "},
			state:        store.FindingStateIgnored,
			reason:       "looks noisy",
			want:         "fingerprint is required",
		},
		{
			name:         "unknown state",
			fingerprints: []string{"abc123"},
			state:        "muted",
			reason:       "looks noisy",
			want:         `state "muted" is not one of`,
		},
		{
			name:         "blank reason",
			fingerprints: []string{"abc123"},
			state:        store.FindingStateIgnored,
			reason:       "  ",
			want:         "a reason is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := store.SetFindingStates(ctx, db, asset.ID, tc.fingerprints, tc.state, tc.reason, nil)
			if err == nil {
				t.Fatalf("SetFindingStates(%d fingerprints, %q) succeeded, want an error", len(tc.fingerprints), tc.state)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}

	states, err := queries.ListFindingStatesByAsset(ctx, asset.ID)
	if err != nil {
		t.Fatalf("ListFindingStatesByAsset: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("states = %+v, want none after rejected input", states)
	}
}

func TestListLatestFindingsUsesLatestSucceededScan(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createAssetAt(ctx, t, queries, "/tmp/alpha")
	other := createAssetAt(ctx, t, queries, "/tmp/beta")

	older := createTestScan(ctx, t, queries, asset.ID)
	olderFinding := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical)
	if err := store.SaveScanResult(ctx, db, older.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{olderFinding},
	}); err != nil {
		t.Fatalf("SaveScanResult(older succeeded scan): %v", err)
	}

	// A newer failed scan persisted partial results; it must not shadow the
	// last successful report.
	newerFailed := createTestScan(ctx, t, queries, asset.ID)
	failedFinding := testFinding(asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityLow)
	if err := store.SaveScanResult(ctx, db, newerFailed.ID, store.ScanResult{
		Status:   store.ScanStatusFailed,
		Error:    "trivy: db unavailable",
		Findings: []findings.Finding{failedFinding},
	}); err != nil {
		t.Fatalf("SaveScanResult(failed scan): %v", err)
	}

	// A canceled scan must be skipped too.
	newestCanceled := createTestScan(ctx, t, queries, asset.ID)
	if err := store.SaveScanResult(ctx, db, newestCanceled.ID, store.ScanResult{
		Status:   store.ScanStatusCanceled,
		Findings: []findings.Finding{failedFinding},
	}); err != nil {
		t.Fatalf("SaveScanResult(canceled scan): %v", err)
	}

	otherScan := createTestScan(ctx, t, queries, other.ID)
	otherFinding := testFinding(other.ID, findings.TypeSecret, "aws-access-key", findings.SeverityMedium)
	if err := store.SaveScanResult(ctx, db, otherScan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{otherFinding},
	}); err != nil {
		t.Fatalf("SaveScanResult(other asset): %v", err)
	}

	all, err := queries.ListLatestFindings(ctx, sqlcdb.ListLatestFindingsParams{})
	if err != nil {
		t.Fatalf("ListLatestFindings: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("latest findings = %d, want 2", len(all))
	}
	if all[0].ScanID != older.ID || all[0].Fingerprint != olderFinding.Fingerprint {
		t.Fatalf("first latest finding = %+v, want the critical finding of the older succeeded scan %d", all[0], older.ID)
	}
	if all[1].ScanID != otherScan.ID || all[1].Severity != string(findings.SeverityMedium) {
		t.Fatalf("second latest finding = %+v, want the medium finding of the other asset", all[1])
	}

	byAsset, err := queries.ListLatestFindings(ctx, sqlcdb.ListLatestFindingsParams{AssetID: asset.ID})
	if err != nil {
		t.Fatalf("ListLatestFindings(asset): %v", err)
	}
	if len(byAsset) != 1 || byAsset[0].ScanID != older.ID {
		t.Fatalf("latest findings of the asset = %+v, want only the succeeded scan", byAsset)
	}

	byType, err := queries.ListLatestFindings(ctx, sqlcdb.ListLatestFindingsParams{
		Type: string(findings.TypeVulnerability),
	})
	if err != nil {
		t.Fatalf("ListLatestFindings(type): %v", err)
	}
	if len(byType) != 1 || byType[0].ScanID != older.ID {
		t.Fatalf("latest vulnerability findings = %+v, want the critical CVE", byType)
	}

	bySeverity, err := queries.ListLatestFindings(ctx, sqlcdb.ListLatestFindingsParams{
		Severity: string(findings.SeverityMedium),
	})
	if err != nil {
		t.Fatalf("ListLatestFindings(severity): %v", err)
	}
	if len(bySeverity) != 1 || bySeverity[0].ScanID != otherScan.ID {
		t.Fatalf("latest medium findings = %+v, want the other asset's secret", bySeverity)
	}
}

func TestClearFindingStateReopens(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createAssetAt(ctx, t, queries, "/tmp/alpha")
	finding := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityHigh)
	scan := createTestScan(ctx, t, queries, asset.ID)
	if err := store.SaveScanResult(ctx, db, scan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{finding},
	}); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}

	if err := store.SetFindingState(ctx, db, asset.ID, finding.Fingerprint, store.FindingStateIgnored, "accepted upstream", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}
	before, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if len(before) != 1 || before[0].Status != store.FindingStateIgnored {
		t.Fatalf("findings before clear = %+v, want ignored", before)
	}

	if err := store.ClearFindingState(ctx, db, asset.ID, finding.Fingerprint); err != nil {
		t.Fatalf("ClearFindingState: %v", err)
	}

	after, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("ListFindingsByScan(after clear): %v", err)
	}
	if len(after) != 1 || after[0].Status != "open" {
		t.Fatalf("findings after clear = %+v, want open", after)
	}
	if after[0].State.Valid || after[0].Reason.Valid {
		t.Fatalf("state/reason after clear = %+v/%+v, want NULL", after[0].State, after[0].Reason)
	}

	// Clearing again is idempotent, and the latest findings agree.
	if err := store.ClearFindingState(ctx, db, asset.ID, finding.Fingerprint); err != nil {
		t.Fatalf("ClearFindingState(second time): %v", err)
	}
	latest, err := queries.ListLatestFindings(ctx, sqlcdb.ListLatestFindingsParams{AssetID: asset.ID})
	if err != nil {
		t.Fatalf("ListLatestFindings: %v", err)
	}
	if len(latest) != 1 || latest[0].Status != "open" {
		t.Fatalf("latest findings after clear = %+v, want open", latest)
	}

	if err := store.ClearFindingState(ctx, db, asset.ID, "  "); err == nil {
		t.Fatal("ClearFindingState with a blank fingerprint succeeded, want an error")
	}
}

// TestFindingStateExpiryReopensFinding pins the clock: the same decision is
// ignored before its expiry and open again from it on (#32). The read queries
// take now as an argument, so no wall clock is involved.
func TestFindingStateExpiryReopensFinding(t *testing.T) {
	ctx := context.Background()
	db, _ := openTestDB(t)
	queries := sqlcdb.New(db)

	asset := createAssetAt(ctx, t, queries, "/tmp/expiry")
	finding := testFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0003", findings.SeverityHigh)

	scan := createTestScan(ctx, t, queries, asset.ID)
	if err := store.SaveScanResult(ctx, db, scan.ID, store.ScanResult{
		Status:   store.ScanStatusSucceeded,
		Findings: []findings.Finding{finding},
	}); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}

	expiresAt := time.Date(2026, 12, 1, 23, 59, 59, 0, time.UTC)
	if err := store.SetFindingState(ctx, db, asset.ID, finding.Fingerprint,
		store.FindingStateAcceptedRisk, "temporary acceptance", &expiresAt); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	statusAt := func(now time.Time) (string, int64) {
		t.Helper()
		rows, err := queries.ListFindingsByScan(ctx, sqlcdb.ListFindingsByScanParams{
			ScanID: scan.ID,
			Now:    store.FormatTimestamp(now),
		})
		if err != nil {
			t.Fatalf("ListFindingsByScan(now %s): %v", now, err)
		}
		if len(rows) != 1 {
			t.Fatalf("findings at %s = %d, want 1", now, len(rows))
		}
		return rows[0].Status, rows[0].Expired
	}

	if status, expired := statusAt(expiresAt.Add(-time.Hour)); status != "ignored" || expired != 0 {
		t.Fatalf("before expiry: status = %q, expired = %d; want ignored, 0", status, expired)
	}
	if status, expired := statusAt(expiresAt); status != "open" || expired != 1 {
		t.Fatalf("at expiry: status = %q, expired = %d; want open, 1", status, expired)
	}
	if status, expired := statusAt(expiresAt.Add(time.Hour)); status != "open" || expired != 1 {
		t.Fatalf("after expiry: status = %q, expired = %d; want open, 1", status, expired)
	}
}
