//go:build integration

package osv

import (
	"context"
	"os"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
)

// TestMatchLiveOSV checks the matcher against api.osv.dev. It needs the
// network, so it is opt-in:
//
//	BASTION_OSV_INTEGRATION=1 go test -tags integration ./internal/scanners/osv -run TestMatchLiveOSV -v
//
// -harseurl@0.0.1 is a real npm package with the MAL-2022-7 malicious-package
// advisory (verified with POST /v1/query and GET /v1/vulns/MAL-2022-7).
func TestMatchLiveOSV(t *testing.T) {
	if os.Getenv("BASTION_OSV_INTEGRATION") != "1" {
		t.Skip("set BASTION_OSV_INTEGRATION=1 to run the live OSV API test")
	}

	m := New("integration-test")
	fs, err := m.Match(context.Background(), []findings.Package{{
		Ecosystem: "npm",
		Name:      "-harseurl",
		Version:   "0.0.1",
		Path:      "package-lock.json",
	}}, findings.Asset{ID: 1, Kind: findings.AssetKindPath, DisplayName: "osv-integration"})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}

	var malware []findings.Finding
	for _, f := range fs {
		if f.RuleID == "MAL-2022-7" {
			malware = append(malware, f)
		}
	}
	if len(malware) != 1 {
		t.Fatalf("got %d MAL-2022-7 findings, want 1: %+v", len(malware), fs)
	}
	f := malware[0]
	if f.Type != findings.TypeMalware || f.Severity != findings.SeverityCritical {
		t.Errorf("type/severity = %s/%s, want malware/critical", f.Type, f.Severity)
	}
	if f.PackageName != "-harseurl" || f.PackageVersion != "0.0.1" || f.Ecosystem != "npm" {
		t.Errorf("package = %s@%s (%s)", f.PackageName, f.PackageVersion, f.Ecosystem)
	}
	if f.Title == "" || f.Title == "Malicious package -harseurl" {
		t.Errorf("title = %q, want the advisory summary", f.Title)
	}
}
