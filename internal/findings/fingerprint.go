package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// Fingerprint returns the stable identity of a finding:
//
//	sha256(asset_id, type, rule_id, ecosystem, package_name, location_normalized)
//
// Each field is written as "<byte length>:<value>" before hashing, so the
// concatenation is unambiguous: a separator character inside a field can never
// be mistaken for a different split (PROJECT_SPEC.md §5).
//
// It deliberately excludes the package version, scan id, line numbers and
// layer digests, so re-scanning an unchanged target yields the same
// fingerprints (PROJECT_SPEC.md §5).
func Fingerprint(assetID int64, f Finding) string {
	var material strings.Builder
	for _, field := range fingerprintFields(assetID, f) {
		material.WriteString(strconv.Itoa(len(field)))
		material.WriteByte(':')
		material.WriteString(field)
	}
	sum := sha256.Sum256([]byte(material.String()))
	return hex.EncodeToString(sum[:])
}

// fingerprintFields returns the fingerprint material in a fixed order. A
// secret contributes its file, rule id and HMAC as separate fields rather than
// joining them into the location with a delimiter.
func fingerprintFields(assetID int64, f Finding) []string {
	fields := []string{
		strconv.FormatInt(assetID, 10),
		string(f.Type),
		f.RuleID,
		f.Ecosystem,
		f.PackageName,
	}
	loc := NormalizeLocation("", f.Location)
	switch f.Type {
	case TypeSecret:
		// A secret keeps its identity when lines shift: file + rule +
		// HMAC(secret) (PROJECT_SPEC.md §5). The rule also appears above;
		// repeating it keeps the §5 rule self-contained in the material.
		return append(fields, stripLine(loc), f.RuleID, f.SecretHMAC)
	default:
		// Image locations are package paths inside the image and misconfig
		// locations are file + resource/cause identifier. LayerDigest is not
		// consulted here, so a rebuild does not make findings new/fixed, and
		// no location carries a line number.
		return append(fields, loc)
	}
}

// NormalizeLocation makes a scanner location comparable across runs: it
// converts to slash form (including Windows-style separators on any OS),
// strips a workspace prefix and cleans relative segments. An empty location
// stays empty.
func NormalizeLocation(workspace, location string) string {
	loc := strings.ReplaceAll(strings.TrimSpace(location), "\\", "/")
	if workspace != "" && loc != "" {
		ws := strings.ReplaceAll(filepath.Clean(workspace), "\\", "/")
		switch {
		case loc == ws:
			loc = ""
		case strings.HasPrefix(loc, ws+"/"):
			loc = strings.TrimPrefix(loc, ws+"/")
		}
	}
	if loc == "" {
		return ""
	}
	loc = strings.TrimPrefix(loc, "./")
	cleaned := path.Clean(loc)
	if cleaned == "." {
		return ""
	}
	return cleaned
}

// stripLine removes a trailing ":<number>" from a file location, leaving
// other colons (such as Windows drive letters or URLs) untouched.
func stripLine(loc string) string {
	i := strings.LastIndexByte(loc, ':')
	if i < 0 || i == len(loc)-1 {
		return loc
	}
	if _, err := strconv.Atoi(loc[i+1:]); err != nil {
		return loc
	}
	return loc[:i]
}
