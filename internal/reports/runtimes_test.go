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

// eolFinding builds an end-of-life finding the way the eol scanner does: rule
// "eol", the end-of-life date in the description when there is one.
func eolFinding(assetID int64, name, version, ecosystem, fixed, description string) findings.Finding {
	finding := findings.Finding{
		AssetID:        assetID,
		Type:           findings.TypeOutdated,
		RuleID:         "eol",
		Severity:       findings.SeverityHigh,
		Title:          "outdated runtime " + name,
		PackageName:    name,
		PackageVersion: version,
		FixedVersion:   fixed,
		Ecosystem:      ecosystem,
		Description:    description,
		Scanner:        "endoflife.date",
		Occurrences:    1,
	}
	finding.Fingerprint = findings.Fingerprint(assetID, finding)
	return finding
}

// TestRuntimesGroupsByNameAndVersion seeds a superseded scan, a duplicate
// runtime on two assets, an ignore decision, a non-EOL outdated row and an
// archived asset, then asserts the grouping, the date parsing and the scoping.
func TestRuntimesGroupsByNameAndVersion(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/runtime-alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/runtime-beta", "Beta")
	archived := seedAsset(t, db, findings.AssetKindPath, "/tmp/runtime-archived", "Archived")

	// The older alpha scan's runtime is superseded by the newer scan.
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(9),
		eolFinding(alpha.ID, "go", "1.20", "go", "1.22",
			"Go 1.20 stopped receiving security updates on 2024-02-06."))

	python := eolFinding(alpha.ID, "python", "3.8", "python", "3.13",
		"Python 3.8 stopped receiving security updates on 2024-10-07.")
	node := eolFinding(alpha.ID, "node", "18", "node", "20",
		"Node.js 18 stopped receiving security updates.")
	ruby := eolFinding(alpha.ID, "ruby", "3.0", "ruby", "",
		"Ruby 3.0 stopped receiving security updates on 2024-03-31.")
	notEOL := newFinding(alpha.ID, findings.TypeOutdated, "outdated", findings.SeverityLow)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(10), python, node, ruby, notEOL)
	if err := store.SetFindingState(ctx, db, alpha.ID, ruby.Fingerprint,
		store.FindingStateIgnored, "not deployed", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	// Beta runs the same runtime: one group, two assets.
	seedScan(t, db, beta.ID, store.ScanStatusSucceeded, at(11),
		eolFinding(beta.ID, "python", "3.8", "python", "3.13",
			"Python 3.8 stopped receiving security updates on 2024-10-07."))

	seedScan(t, db, archived.ID, store.ScanStatusSucceeded, at(10),
		eolFinding(archived.ID, "python", "3.8", "python", "3.13",
			"Python 3.8 stopped receiving security updates on 2024-10-07."))
	if _, err := sqlcdb.New(db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ID:         archived.ID,
		ArchivedAt: sql.NullString{String: at(12).Format(time.RFC3339), Valid: true},
	}); err != nil {
		t.Fatalf("ArchiveAsset: %v", err)
	}

	runtimes, err := service.Runtimes(ctx, 0)
	if err != nil {
		t.Fatalf("Runtimes: %v", err)
	}
	if len(runtimes) != 2 {
		t.Fatalf("runtimes = %+v, want node and python", runtimes)
	}

	nodeRuntime := runtimes[0]
	if nodeRuntime.Name != "node" || nodeRuntime.Version != "18" || nodeRuntime.Ecosystem != "node" {
		t.Errorf("first runtime = %+v, want node 18", nodeRuntime)
	}
	if nodeRuntime.EOLDate != "" || nodeRuntime.FixedVersion != "20" {
		t.Errorf("node dates = %q/%q, want no EOL date and 20", nodeRuntime.EOLDate, nodeRuntime.FixedVersion)
	}
	if len(nodeRuntime.Assets) != 1 || nodeRuntime.Assets[0].AssetID != alpha.ID {
		t.Errorf("node assets = %+v, want alpha", nodeRuntime.Assets)
	}

	pythonRuntime := runtimes[1]
	if pythonRuntime.Name != "python" || pythonRuntime.Version != "3.8" || pythonRuntime.Ecosystem != "python" {
		t.Errorf("second runtime = %+v, want python 3.8", pythonRuntime)
	}
	if pythonRuntime.EOLDate != "2024-10-07" || pythonRuntime.FixedVersion != "3.13" {
		t.Errorf("python dates = %q/%q, want 2024-10-07 and 3.13", pythonRuntime.EOLDate, pythonRuntime.FixedVersion)
	}
	wantAssets := []reports.RuntimeAsset{
		{AssetID: alpha.ID, DisplayName: "Alpha"},
		{AssetID: beta.ID, DisplayName: "Beta"},
	}
	if !slices.Equal(pythonRuntime.Assets, wantAssets) {
		t.Errorf("python assets = %+v, want %+v", pythonRuntime.Assets, wantAssets)
	}

	scoped, err := service.Runtimes(ctx, alpha.ID)
	if err != nil {
		t.Fatalf("Runtimes(alpha): %v", err)
	}
	if len(scoped) != 2 || len(scoped[1].Assets) != 1 || scoped[1].Assets[0].AssetID != alpha.ID {
		t.Errorf("scoped runtimes = %+v, want alpha only", scoped)
	}

	if _, err := service.Runtimes(ctx, -1); !errors.Is(err, reports.ErrInvalid) {
		t.Errorf("Runtimes(-1) error = %v, want ErrInvalid", err)
	}
}
