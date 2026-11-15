package trivy

import (
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
)

// TestNormalizeECRImageReport pins the image path for an ECR-like report: the
// registry reference and the layer digest are never a finding location, and
// the same report produces the same fingerprints (they use the asset id and
// package, not a layer).
func TestNormalizeECRImageReport(t *testing.T) {
	const (
		ref   = "143709573002.dkr.ecr.eu-central-1.amazonaws.com/t2n-api@sha256:aaaa"
		layer = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	input := `{
		"SchemaVersion": 2,
		"ArtifactType": "container_image",
		"Results": [{
			"Target": "` + ref + ` (debian 12.5)",
			"Class": "os-pkgs",
			"Type": "debian",
			"Packages": [{"Name": "openssl", "Version": "3.0.11-1"}],
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2024-9999",
				"PkgName": "openssl",
				"InstalledVersion": "3.0.11-1",
				"FixedVersion": "3.0.13-1",
				"Severity": "HIGH",
				"LayerDigest": "` + layer + `"
			}]
		}]
	}`

	asset := findings.Asset{ID: 42, Kind: findings.AssetKindImage, Ref: ref}
	first, pkgs, err := New().Normalize(&scanners.RawResult{Raw: []byte(input)}, asset)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	second, _, err := New().Normalize(&scanners.RawResult{Raw: []byte(input)}, asset)
	if err != nil {
		t.Fatalf("Normalize again: %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("findings = %d/%d, want 1/1", len(first), len(second))
	}
	if first[0].Fingerprint != second[0].Fingerprint {
		t.Errorf("fingerprint changed between identical scans: %q vs %q",
			first[0].Fingerprint, second[0].Fingerprint)
	}
	if first[0].Location != "openssl" {
		t.Errorf("location = %q, want openssl", first[0].Location)
	}
	if strings.Contains(first[0].Location, "sha256:") || first[0].Location == ref {
		t.Errorf("location = %q, want neither the layer nor the registry ref", first[0].Location)
	}
	if len(pkgs) != 1 || pkgs[0].Path != "" {
		t.Errorf("packages = %+v, want one image package with no path", pkgs)
	}
}
