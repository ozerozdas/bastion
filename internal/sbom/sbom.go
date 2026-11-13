// Package sbom builds CycloneDX JSON BOMs (#24) from the package inventory a
// scan persisted. It is pure: the API and the CLI feed it packages they
// already hold, so both print the same document for the same scan.
//
// The document targets CycloneDX 1.6 and is assembled locally with encoding/json
// rather than through a library: only a handful of fields are emitted, and the
// official JSON schema is validated in the tests (sbom_test.go).
package sbom

import (
	"crypto/rand"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
)

// SpecVersion is the CycloneDX specification version the document declares.
const SpecVersion = "1.6"

// MediaType is the registered media type of a CycloneDX JSON document.
const MediaType = "application/vnd.cyclonedx+json"

// toolName is the tool recorded in metadata.tools.
const toolName = "bastion"

// Document is the subset of a CycloneDX BOM bastion emits. Optional CycloneDX
// fields that bastion does not fill (dependencies, vulnerabilities, services)
// are omitted rather than emitted empty.
type Document struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata identifies the BOM: when it was produced, by which tool, and for
// which scanned artifact.
type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     Tools     `json:"tools"`
	Component Component `json:"component"`
}

// Tools is the CycloneDX 1.5+ object form of the tool list.
type Tools struct {
	Components []Component `json:"components"`
}

// Component is one CycloneDX component: the scanned artifact in
// metadata.component, the tool in metadata.tools, one package in components.
type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	BOMRef  string `json:"bom-ref,omitempty"`
}

// Options carries what a golden test must pin. The zero value is the production
// default: the current time and a fresh random serial number.
type Options struct {
	// ToolVersion is the bastion version recorded in metadata.tools.
	ToolVersion string
	// Timestamp replaces the current time.
	Timestamp time.Time
	// SerialNumber replaces the generated urn:uuid serial number.
	SerialNumber string
}

// Build returns the CycloneDX BOM of one scan's package inventory. The asset
// becomes metadata.component; every distinct package becomes a library
// component, ordered by name, version and purl so two runs over the same
// packages produce the same document.
func Build(asset findings.Asset, packages []findings.Package, opts Options) Document {
	timestamp := opts.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	serial := opts.SerialNumber
	if serial == "" {
		serial = "urn:uuid:" + newUUID()
	}

	doc := Document{
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion,
		SerialNumber: serial,
		Version:      1,
		Metadata: Metadata{
			Timestamp: timestamp.UTC().Format(time.RFC3339),
			Tools: Tools{Components: []Component{{
				Type:    "application",
				Name:    toolName,
				Version: opts.ToolVersion,
			}}},
			Component: Component{
				Type:   assetComponentType(asset.Kind),
				Name:   assetName(asset),
				BOMRef: "asset",
			},
		},
		Components: buildComponents(packages),
	}
	return doc
}

// assetComponentType maps the scanned artifact kind onto a CycloneDX component
// type. Every other kind is an application: a path or a repository checkout.
func assetComponentType(kind findings.AssetKind) string {
	if kind == findings.AssetKindImage {
		return "container"
	}
	return "application"
}

// assetName names metadata.component. The display name is what the UI shows; a
// row without one (a not-yet-stored asset) falls back to its ref.
func assetName(asset findings.Asset) string {
	if asset.DisplayName != "" {
		return asset.DisplayName
	}
	return asset.Ref
}

// buildComponents converts the package inventory into sorted, de-duplicated
// library components. Two scanners reporting the same package, or one package
// found in two places of a monorepo, yield one component: a BOM lists a
// component once, and bom-ref must be unique.
func buildComponents(packages []findings.Package) []Component {
	seen := make(map[string]struct{}, len(packages))
	out := make([]Component, 0, len(packages))
	for _, pkg := range packages {
		if pkg.Name == "" {
			continue
		}
		component := Component{
			Type:    "library",
			Name:    pkg.Name,
			Version: pkg.Version,
			PURL:    packagePURL(pkg),
		}
		component.BOMRef = component.PURL
		if component.BOMRef == "" {
			component.BOMRef = "pkg:" + pkg.Ecosystem + "/" + pkg.Name + "@" + pkg.Version
		}
		if _, ok := seen[component.BOMRef]; ok {
			continue
		}
		seen[component.BOMRef] = struct{}{}
		out = append(out, component)
	}

	slices.SortFunc(out, func(a, b Component) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		if c := strings.Compare(a.Version, b.Version); c != 0 {
			return c
		}
		return strings.Compare(a.PURL, b.PURL)
	})
	return out
}

// packagePURL returns the package's purl: the one the scanner reported, or one
// derived for the ecosystems whose coordinates bastion knows. An ecosystem
// without a safe derivation (a Maven artifact without its group, an OS package
// without its distribution) keeps no purl rather than an invented one.
func packagePURL(pkg findings.Package) string {
	if pkg.PURL != "" {
		return pkg.PURL
	}
	purlType, ok := purlTypes[pkg.Ecosystem]
	if !ok || pkg.Name == "" {
		return ""
	}
	purl := "pkg:" + purlType + "/" + escapePURLName(pkg.Name, purlType)
	if pkg.Version != "" {
		purl += "@" + purlSegment(pkg.Version)
	}
	return purl
}

// purlTypes maps bastion's ecosystem names (see the Trivy normalizer) onto purl
// types. Ecosystems that need coordinates bastion does not store — os-deb,
// os-rpm, os-apk and maven — are deliberately absent.
var purlTypes = map[string]string{
	"cargo":    "cargo",
	"composer": "composer",
	"gem":      "gem",
	"go":       "golang",
	"npm":      "npm",
	"nuget":    "nuget",
	"pypi":     "pypi",
}

// escapePURLName percent-encodes a purl name, keeping its path separators: a Go
// module path and a composer package stay slash-separated, while an npm scope's
// "@" is escaped so it cannot be read as the version separator. pypi names are
// case-insensitive, so they are lowercased the way the purl spec requires.
func escapePURLName(name, purlType string) string {
	if purlType == "pypi" {
		name = strings.ToLower(name)
	}
	segments := strings.Split(name, "/")
	for i, segment := range segments {
		segments[i] = purlSegment(segment)
	}
	return strings.Join(segments, "/")
}

// purlSegment percent-encodes one purl segment. Only the unreserved characters
// and the sub-delimiters the spec allows stay as they are; everything else,
// "@" and ":" included, becomes an uppercase %XX.
func purlSegment(segment string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(segment))
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		if purlSafe(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// purlSafe reports whether c may appear unescaped in a purl segment.
func purlSafe(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '.', '-', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=':
		return true
	default:
		return false
	}
}

// newUUID returns a random RFC 4122 version 4 UUID, the shape a CycloneDX
// serialNumber requires. crypto/rand.Read never fails.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
