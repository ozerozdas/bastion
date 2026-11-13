package trivy

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
)

// Normalize maps a Trivy report into bastion's finding and package model.
//
// It decodes Trivy's JSON into minimal local structs so Trivy's Go types stay
// inside this package (§4.2). Locations are made workspace-relative; for
// misconfigurations the location is file + resource/cause identifier, never a
// line number (§5).
func (s *Scanner) Normalize(raw *scanners.RawResult, asset findings.Asset) ([]findings.Finding, []findings.Package, error) {
	if raw == nil {
		return nil, nil, errors.New("trivy: raw result is required")
	}
	var report report
	if err := json.Unmarshal(raw.Raw, &report); err != nil {
		return nil, nil, fmt.Errorf("trivy: decode report: %w", err)
	}

	// License entries do not carry versions; look them up in the package
	// inventory by package name (plus ecosystem when the report states one).
	versions := packageVersions(report)

	fs := make([]findings.Finding, 0)
	pkgs := make([]findings.Package, 0)
	for _, res := range report.Results {
		target := findings.NormalizeLocation(raw.WorkspaceDir, res.Target)
		eco := ecosystem(res)

		for _, p := range res.Packages {
			pkgs = append(pkgs, findings.Package{
				Ecosystem: eco,
				Name:      p.Name,
				Version:   p.Version,
				PURL:      p.Identifier.PURL,
				Path:      target,
				Direct:    directPtr(p.Relationship),
			})
		}

		for _, v := range res.Vulnerabilities {
			f := findings.Finding{
				AssetID:        asset.ID,
				Type:           findings.TypeVulnerability,
				RuleID:         v.VulnerabilityID,
				Severity:       findings.ParseSeverity(v.Severity),
				Title:          v.Title,
				PackageName:    v.PkgName,
				PackageVersion: v.InstalledVersion,
				FixedVersion:   v.FixedVersion,
				Ecosystem:      eco,
				Location:       target,
				CVSS:           maxCVSS(v.CVSS),
				Description:    v.Description,
				References:     references(v.PrimaryURL, v.References),
				Scanner:        s.Name(),
				Aliases:        vulnerabilityAliases(v),
			}
			f.Fingerprint = findings.Fingerprint(asset.ID, f)
			fs = append(fs, f)
		}

		for _, m := range res.Misconfigurations {
			location := target
			if cause := causeID(m.CauseMetadata); cause != "" {
				location += "#" + cause
			}
			description := m.Description
			if description == "" {
				description = m.Message
			}
			f := findings.Finding{
				AssetID:     asset.ID,
				Type:        findings.TypeMisconfig,
				RuleID:      m.ID,
				Severity:    findings.ParseSeverity(m.Severity),
				Title:       m.Title,
				Location:    location,
				Description: description,
				References:  references(m.PrimaryURL, m.References),
				Scanner:     s.Name(),
			}
			f.Fingerprint = findings.Fingerprint(asset.ID, f)
			fs = append(fs, f)
		}

		for _, l := range res.Licenses {
			// Permissive licences carry no action for the user; reporting them
			// would bury real issues (a Go module alone yields hundreds).
			switch strings.ToLower(l.Category) {
			case "notice", "permissive", "unencumbered":
				continue
			}
			// The remaining licences keep Trivy's upstream severity, mapped
			// onto the §5 scale unchanged. That severity is a policy category,
			// not exploit risk: the dashboard surfaces it next to the same
			// vulnerability severities. The Trivy category is kept in
			// Description so the distinction stays visible.
			f := findings.Finding{
				AssetID:        asset.ID,
				Type:           findings.TypeLicense,
				RuleID:         l.Name,
				Severity:       findings.ParseSeverity(l.Severity),
				Title:          l.Name + " license",
				PackageName:    l.PkgName,
				PackageVersion: lookupVersion(versions, eco, l.PkgName),
				Ecosystem:      eco,
				Location:       findings.NormalizeLocation(raw.WorkspaceDir, l.FilePath),
				Description:    l.Category,
				References:     references(l.Link, nil),
				Scanner:        s.Name(),
			}
			f.Fingerprint = findings.Fingerprint(asset.ID, f)
			fs = append(fs, f)
		}
	}

	findings.SortFindings(fs)
	findings.SortPackages(pkgs)
	return fs, pkgs, nil
}

// causeID returns the misconfiguration's resource or cause identifier. It is
// what distinguishes two findings of the same check in one file.
func causeID(c causeMetadata) string {
	if c.Resource != "" {
		return c.Resource
	}
	return c.Service
}

// references merges the primary URL with the advisory's reference list.
func references(primary string, refs []string) []string {
	out := slices.Clone(refs)
	if primary != "" && !slices.Contains(out, primary) {
		out = append([]string{primary}, out...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// vulnerabilityAliases returns the ids that identify a vulnerability: its
// primary id plus Trivy's vendor ids. Reference URLs are deliberately not
// parsed: they list related advisories as often as aliases, and OSV's own
// advisory aliases already bridge a GHSA to its CVE. The scan pipeline uses
// these ids to merge one advisory reported by another scanner; they are
// in-memory only.
func vulnerabilityAliases(v vuln) []string {
	set := make(map[string]struct{}, 1+len(v.VendorIDs))
	add := func(id string) {
		if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
			set[id] = struct{}{}
		}
	}
	add(v.VulnerabilityID)
	for _, id := range v.VendorIDs {
		add(id)
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// maxCVSS picks the highest CVSS v3 score across sources, falling back to the
// highest v2 score only when no source has a v3 score. Trivy reports one score
// per advisory source; bastion stores one column. Sources are visited in
// sorted key order so a map's iteration order can never change the result.
func maxCVSS(scores map[string]cvssScore) *float64 {
	sources := make([]string, 0, len(scores))
	for source := range scores {
		sources = append(sources, source)
	}
	slices.Sort(sources)

	var best float64
	for _, source := range sources {
		if v3 := scores[source].V3Score; v3 > best {
			best = v3
		}
	}
	if best > 0 {
		return &best
	}
	for _, source := range sources {
		if v2 := scores[source].V2Score; v2 > best {
			best = v2
		}
	}
	if best <= 0 {
		return nil
	}
	return &best
}

// pkgKey identifies a package inside a report. The ecosystem is empty when the
// report does not state one: Trivy license results carry Class "license" and
// no Type.
type pkgKey struct {
	ecosystem string
	name      string
}

// packageVersions indexes the package inventory by ecosystem plus name, and by
// name alone as a fallback. The target path is deliberately not part of the
// key: Trivy lists the same package under every manifest that references it,
// so a license entry must not depend on which target it was reported under.
func packageVersions(report report) map[pkgKey]string {
	versions := make(map[pkgKey]string)
	for _, res := range report.Results {
		eco := ecosystem(res)
		for _, p := range res.Packages {
			if p.Version == "" {
				continue
			}
			versions[pkgKey{ecosystem: eco, name: p.Name}] = p.Version
			nameOnly := pkgKey{name: p.Name}
			if _, ok := versions[nameOnly]; !ok {
				versions[nameOnly] = p.Version
			}
		}
	}
	return versions
}

// lookupVersion returns the version for a package, preferring the ecosystem
// specific entry and falling back to the name-only one.
func lookupVersion(versions map[pkgKey]string, eco, name string) string {
	if v := versions[pkgKey{ecosystem: eco, name: name}]; v != "" {
		return v
	}
	return versions[pkgKey{name: name}]
}

// ecosystem maps a Trivy result type onto a §5 ecosystem name.
func ecosystem(res result) string {
	typ := strings.ToLower(res.Type)
	if res.Class == "os-pkgs" {
		switch typ {
		case "alpine":
			return "os-apk"
		case "redhat", "centos", "rocky", "alma", "oracle", "amazon", "photon", "azurelinux", "opensuse", "suse":
			return "os-rpm"
		default:
			return "os-deb"
		}
	}
	switch typ {
	case "gomod", "gobinary", "go":
		return "go"
	case "pip", "poetry", "uv", "pipenv", "python-pkg":
		return "pypi"
	case "jar", "pom", "gradle":
		return "maven"
	case "yarn", "pnpm", "node-pkg":
		return "npm"
	case "bundler":
		return "gem"
	case "dotnet":
		return "nuget"
	default:
		return typ
	}
}

// directPtr converts Trivy's relationship string into the nullable direct flag.
func directPtr(relationship string) *bool {
	switch strings.ToLower(relationship) {
	case "direct":
		v := true
		return &v
	case "indirect":
		v := false
		return &v
	default:
		return nil
	}
}

// The types below mirror only the Trivy JSON fields bastion consumes; they are
// not Trivy's Go types and deliberately keep the dependency surface small.

type report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	Results       []result `json:"Results"`
}

type result struct {
	Target            string      `json:"Target"`
	Class             string      `json:"Class"`
	Type              string      `json:"Type"`
	Packages          []pkgEntry  `json:"Packages"`
	Vulnerabilities   []vuln      `json:"Vulnerabilities"`
	Misconfigurations []misconfig `json:"Misconfigurations"`
	Licenses          []license   `json:"Licenses"`
}

type pkgEntry struct {
	Name         string     `json:"Name"`
	Version      string     `json:"Version"`
	Identifier   identifier `json:"Identifier"`
	Relationship string     `json:"Relationship"`
}

type identifier struct {
	PURL string `json:"PURL"`
}

type vuln struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	VendorIDs        []string             `json:"VendorIDs"`
	PkgName          string               `json:"PkgName"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Title            string               `json:"Title"`
	Description      string               `json:"Description"`
	Severity         string               `json:"Severity"`
	PrimaryURL       string               `json:"PrimaryURL"`
	References       []string             `json:"References"`
	CVSS             map[string]cvssScore `json:"CVSS"`
}

type cvssScore struct {
	V2Score float64 `json:"V2Score"`
	V3Score float64 `json:"V3Score"`
}

type misconfig struct {
	ID            string        `json:"ID"`
	Title         string        `json:"Title"`
	Description   string        `json:"Description"`
	Message       string        `json:"Message"`
	Severity      string        `json:"Severity"`
	PrimaryURL    string        `json:"PrimaryURL"`
	References    []string      `json:"References"`
	CauseMetadata causeMetadata `json:"CauseMetadata"`
}

type causeMetadata struct {
	Resource string `json:"Resource"`
	Provider string `json:"Provider"`
	Service  string `json:"Service"`
}

type license struct {
	Severity string `json:"Severity"`
	Category string `json:"Category"`
	PkgName  string `json:"PkgName"`
	FilePath string `json:"FilePath"`
	Name     string `json:"Name"`
	Link     string `json:"Link"`
}
