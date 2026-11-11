// Package findings holds bastion's normalized data model, fingerprinting and
// scan diffing (PROJECT_SPEC.md §5).
//
// Scanner adapters translate their native output into these types; everything
// downstream (store, reports, API) works only with these types.
package findings

import (
	"slices"
	"strings"

	"github.com/ozerozdas/bastion/internal/scanners"
)

// Type is the kind of finding.
type Type string

// Finding types from PROJECT_SPEC.md §5.
const (
	TypeVulnerability Type = "vulnerability"
	TypeSecret        Type = "secret"
	TypeOutdated      Type = "outdated"
	TypeMisconfig     Type = "misconfig"
	TypeLicense       Type = "license"
	TypeMalware       Type = "malware"
	TypeSAST          Type = "sast"
)

// Severity is the normalized severity scale. Scanner-specific levels are
// mapped onto it; unknown input becomes SeverityUnknown rather than being
// dropped or upgraded.
type Severity string

// Severity levels from PROJECT_SPEC.md §5.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityUnknown  Severity = "unknown"
)

// AssetKind is the kind of artifact a finding belongs to.
type AssetKind string

// Asset kinds from PROJECT_SPEC.md §5.
const (
	AssetKindRepo  AssetKind = "repo"
	AssetKindImage AssetKind = "image"
	AssetKindPath  AssetKind = "path"
)

// Asset is the scanned artifact a finding belongs to.
type Asset struct {
	ID          int64     `json:"id"`
	Kind        AssetKind `json:"kind"`
	DisplayName string    `json:"display_name"`
	Ref         string    `json:"ref"`
}

// Finding is one normalized finding. Every field maps to a §5 findings column
// except LayerDigest, which is display-only provenance.
type Finding struct {
	AssetID  int64    `json:"asset_id"`
	Type     Type     `json:"type"`
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`

	PackageName    string `json:"package_name,omitempty"`
	PackageVersion string `json:"package_version,omitempty"`
	FixedVersion   string `json:"fixed_version,omitempty"`
	Ecosystem      string `json:"ecosystem,omitempty"`

	// Location is "file", "file:line" or, for image findings, the package path
	// inside the image. It is never a layer digest.
	Location string   `json:"location,omitempty"`
	CVSS     *float64 `json:"cvss,omitempty"`

	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`

	Scanner string `json:"scanner"`
	// Match is the redacted secret (first 4 chars plus "****"); raw secrets are
	// never stored. Empty for non-secret findings.
	Match string `json:"match,omitempty"`
	// SecretHMAC is hex(HMAC-SHA256(local_key, secret)) for secret findings.
	// It identifies a secret across scans without persisting it.
	SecretHMAC string `json:"secret_hmac,omitempty"`
	// LayerDigest records which image layer produced an image finding. It is
	// provenance only and is deliberately excluded from Fingerprint.
	LayerDigest string `json:"layer_digest,omitempty"`

	Fingerprint string `json:"fingerprint"`
}

// Package is one SBOM entry reported by a scanner.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl,omitempty"`
	Path      string `json:"path,omitempty"`
	// Direct is nil when the scanner does not report a direct/transitive
	// relationship.
	Direct *bool `json:"direct,omitempty"`
}

// Normalizer maps one scanner's raw output into bastion's model.
type Normalizer interface {
	Normalize(raw *scanners.RawResult, asset Asset) ([]Finding, []Package, error)
}

// ParseSeverity maps scanner severity strings onto the normalized scale.
func ParseSeverity(s string) Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// SortFindings orders findings deterministically for golden output and stable
// persistence.
func SortFindings(list []Finding) {
	slices.SortFunc(list, func(a, b Finding) int {
		if c := strings.Compare(string(a.Type), string(b.Type)); c != 0 {
			return c
		}
		if c := strings.Compare(a.RuleID, b.RuleID); c != 0 {
			return c
		}
		if c := strings.Compare(a.PackageName, b.PackageName); c != 0 {
			return c
		}
		if c := strings.Compare(a.Ecosystem, b.Ecosystem); c != 0 {
			return c
		}
		if c := strings.Compare(a.Location, b.Location); c != 0 {
			return c
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
}

// SortPackages orders SBOM entries deterministically.
func SortPackages(list []Package) {
	slices.SortFunc(list, func(a, b Package) int {
		if c := strings.Compare(a.Ecosystem, b.Ecosystem); c != 0 {
			return c
		}
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		if c := strings.Compare(a.Version, b.Version); c != 0 {
			return c
		}
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.PURL, b.PURL)
	})
}
