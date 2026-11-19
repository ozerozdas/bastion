package reports_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/licencepolicy"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// licenseFinding builds a licence finding for a package.
func licenseFinding(assetID int64, licence, pkg, version string) findings.Finding {
	finding := findings.Finding{
		AssetID:        assetID,
		Type:           findings.TypeLicense,
		RuleID:         licence,
		Severity:       findings.SeverityHigh,
		Title:          licence + " license",
		PackageName:    pkg,
		PackageVersion: version,
		Ecosystem:      "npm",
		Scanner:        "trivy",
		Occurrences:    1,
	}
	finding.Fingerprint = findings.Fingerprint(assetID, finding)
	return finding
}

// TestLicensesResolvesPolicyAndIncludesAllow seeds a global deny and allow, a
// per-asset allow override, an ignored finding and an archived asset, then
// asserts the policy join, the allow inclusion, the grouping and the order.
func TestLicensesResolvesPolicyAndIncludesAllow(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	service, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}
	policies, err := licencepolicy.NewService(db)
	if err != nil {
		t.Fatalf("licencepolicy.NewService: %v", err)
	}

	if _, err := policies.Replace(ctx, nil, licencepolicy.Policy{
		Allow: []string{"Apache-2.0"},
		Deny:  []string{"GPL-3.0"},
	}); err != nil {
		t.Fatalf("Replace(global): %v", err)
	}

	alpha := seedAsset(t, db, findings.AssetKindPath, "/tmp/licenses-alpha", "Alpha")
	beta := seedAsset(t, db, findings.AssetKindRepo, "octo/licenses-beta", "Beta")
	archived := seedAsset(t, db, findings.AssetKindPath, "/tmp/licenses-archived", "Archived")

	// Alpha allows GPL, overriding the global deny for its own findings.
	alphaID := alpha.ID
	if _, err := policies.Replace(ctx, &alphaID, licencepolicy.Policy{
		Allow: []string{"GPL-3.0"},
	}); err != nil {
		t.Fatalf("Replace(alpha): %v", err)
	}

	// The older alpha scan is superseded: old-gpl must not appear.
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(9),
		licenseFinding(alpha.ID, "GPL-3.0", "old-gpl", "0.1.0"))

	alphaGPL := licenseFinding(alpha.ID, "GPL-3.0", "alpha-gpl", "1.0.0")
	alphaMIT := licenseFinding(alpha.ID, "MIT", "alpha-mit", "0.1.0")
	ignored := licenseFinding(alpha.ID, "BSD-3-Clause", "alpha-bsd", "1.0.0")
	vulnerability := newFinding(alpha.ID, findings.TypeVulnerability, "CVE-2026-9100", findings.SeverityCritical)
	seedScan(t, db, alpha.ID, store.ScanStatusSucceeded, at(10),
		alphaGPL, alphaMIT, ignored, vulnerability)
	if err := store.SetFindingState(ctx, db, alpha.ID, ignored.Fingerprint,
		store.FindingStateIgnored, "known package", nil); err != nil {
		t.Fatalf("SetFindingState: %v", err)
	}

	betaGPL := licenseFinding(beta.ID, "GPL-3.0", "beta-gpl", "2.0.0")
	betaApache1 := licenseFinding(beta.ID, "Apache-2.0", "beta-web", "1.0.0")
	betaApache2 := licenseFinding(beta.ID, "Apache-2.0", "beta-http", "1.1.0")
	seedScan(t, db, beta.ID, store.ScanStatusSucceeded, at(10), betaGPL, betaApache1, betaApache2)

	seedScan(t, db, archived.ID, store.ScanStatusSucceeded, at(10),
		licenseFinding(archived.ID, "GPL-3.0", "archived-gpl", "1.0.0"))
	if _, err := sqlcdb.New(db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ID:         archived.ID,
		ArchivedAt: sql.NullString{String: at(11).Format(time.RFC3339), Valid: true},
	}); err != nil {
		t.Fatalf("ArchiveAsset: %v", err)
	}

	report, err := service.Licenses(ctx, 0)
	if err != nil {
		t.Fatalf("Licenses: %v", err)
	}
	if len(report.Licenses) != 4 {
		t.Fatalf("licenses = %+v, want four entries", report.Licenses)
	}

	// Deny first, then by package count descending, then by licence name.
	want := []struct {
		license  string
		policy   string
		packages int
		assets   int
		pkg      string
	}{
		{license: "GPL-3.0", policy: reports.LicensePolicyDeny, packages: 1, assets: 1, pkg: "beta-gpl"},
		{license: "Apache-2.0", policy: reports.LicensePolicyAllow, packages: 2, assets: 1},
		{license: "GPL-3.0", policy: reports.LicensePolicyAllow, packages: 1, assets: 1, pkg: "alpha-gpl"},
		{license: "MIT", policy: reports.LicensePolicyNone, packages: 1, assets: 1, pkg: "alpha-mit"},
	}
	for i, expected := range want {
		entry := report.Licenses[i]
		if entry.License != expected.license || entry.Policy != expected.policy ||
			entry.Packages != expected.packages || entry.Assets != expected.assets {
			t.Errorf("licenses[%d] = %+v, want %+v", i, entry, expected)
		}
		if expected.pkg != "" {
			if len(entry.Items) != 1 || entry.Items[0].PackageName != expected.pkg {
				t.Errorf("licenses[%d] items = %+v, want %q", i, entry.Items, expected.pkg)
			}
		}
	}

	// The ignored BSD finding and the archived asset's GPL are absent.
	for _, entry := range report.Licenses {
		if entry.License == "BSD-3-Clause" {
			t.Errorf("licenses contains the ignored BSD finding: %+v", entry)
		}
		for _, item := range entry.Items {
			if item.AssetID == archived.ID {
				t.Errorf("licenses contains the archived asset: %+v", item)
			}
		}
	}

	scoped, err := service.Licenses(ctx, alpha.ID)
	if err != nil {
		t.Fatalf("Licenses(alpha): %v", err)
	}
	if len(scoped.Licenses) != 2 {
		t.Fatalf("scoped licenses = %+v, want alpha's two entries", scoped.Licenses)
	}
	for _, entry := range scoped.Licenses {
		for _, item := range entry.Items {
			if item.AssetID != alpha.ID {
				t.Errorf("scoped licenses contain asset %d, want only alpha", item.AssetID)
			}
		}
	}

	if _, err := service.Licenses(ctx, -1); !errors.Is(err, reports.ErrInvalid) {
		t.Errorf("Licenses(-1) error = %v, want ErrInvalid", err)
	}
}
