package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// Fingerprint returns the stable identity of a finding:
//
//	sha256(asset_id | type | rule_id | ecosystem | package_name | location_normalized)
//
// It deliberately excludes the package version, scan id, line numbers and
// layer digests, so re-scanning an unchanged target yields the same
// fingerprints (PROJECT_SPEC.md §5).
func Fingerprint(assetID int64, f Finding) string {
	loc := locationForFingerprint(f)
	material := fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		assetID, f.Type, f.RuleID, f.Ecosystem, f.PackageName, loc)
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

// locationForFingerprint applies the type-specific rules from §5.
func locationForFingerprint(f Finding) string {
	loc := NormalizeLocation("", f.Location)
	switch f.Type {
	case TypeSecret:
		// A secret keeps its identity when lines shift: file + rule +
		// HMAC(secret). rule_id is also in the overall material; keeping it
		// here documents the §5 rule and makes the location independent of
		// the other fields.
		return stripLine(loc) + "|" + f.RuleID + "|" + f.SecretHMAC
	case TypeMisconfig:
		// Normalizers encode file + resource/cause identifier in Location;
		// the line number never enters it.
		return loc
	default:
		// Image locations are package paths inside the image. LayerDigest is
		// not consulted here, so a rebuild does not make findings new/fixed.
		return loc
	}
}

// NormalizeLocation makes a scanner location comparable across runs: it
// converts to slash form, strips a workspace prefix and cleans relative
// segments. An empty location stays empty.
func NormalizeLocation(workspace, location string) string {
	loc := filepath.ToSlash(strings.TrimSpace(location))
	if workspace != "" && loc != "" {
		ws := filepath.ToSlash(filepath.Clean(workspace))
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
