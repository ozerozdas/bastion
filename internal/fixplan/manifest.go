package fixplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// This file edits the two manifests the first version of pull requests
// supports (#47): go.mod and package.json. The edits are string-level and keep
// the file's own formatting and line endings; the lockfile is never touched.
// The GitHub flow in internal/reports calls these functions, and their errors
// separate "the package is not in this manifest" (a transitive dependency) from
// "this entry cannot be bumped safely".

var (
	// ErrManifestNotFound means the package has no entry in the manifest, so it
	// is a transitive dependency: bump its parent instead.
	ErrManifestNotFound = errors.New("the package is not in the manifest")
	// ErrManifestUnsupported means the entry exists but its shape is one this
	// version does not edit (a workspace protocol, a range expression).
	ErrManifestUnsupported = errors.New("this manifest entry cannot be bumped safely")
)

// ManifestPath maps a finding's location to the manifest a package bump edits.
// The scanner reports the lockfile when a package comes from one, so the
// lockfile's sibling manifest is returned: package-lock.json, yarn.lock and
// pnpm-lock.yaml map to package.json; go.sum maps to go.mod. A location that
// already names the manifest stays as it is.
//
// The path must be repository-relative and clean: an absolute path, a ".."
// segment or anything under node_modules is refused instead of being sent to
// GitHub. Every refusal is ErrManifestUnsupported, which the API answers 422.
func ManifestPath(ecosystem, location string) (string, error) {
	file := locationPath(location)
	if !safeManifestPath(file) {
		return "", fmt.Errorf("%w: location %q is not a repository-relative manifest path", ErrManifestUnsupported, location)
	}
	dir, base := path.Split(file)
	switch strings.ToLower(ecosystem) {
	case "go":
		switch base {
		case "go.mod":
			return file, nil
		case "go.sum":
			return dir + "go.mod", nil
		}
	case "npm":
		switch base {
		case "package.json":
			return file, nil
		case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
			return dir + "package.json", nil
		}
	}
	return "", fmt.Errorf("%w: %q names no %s manifest", ErrManifestUnsupported, location, ecosystem)
}

// safeManifestPath reports whether a scanner location is a clean, relative
// repository path that may be read or written. node_modules holds installed
// copies, not the project's manifest, so it is refused too.
func safeManifestPath(file string) bool {
	if file == "" || path.IsAbs(file) || file != path.Clean(file) {
		return false
	}
	for _, segment := range strings.Split(file, "/") {
		switch segment {
		case "", ".", "..", "node_modules":
			return false
		}
	}
	return true
}

// locationPath turns a scanner location into a repository-relative file path:
// "file:12" and "file:12:3" lose the line and column, and a leading "./" is
// dropped.
func locationPath(location string) string {
	file := strings.TrimSpace(location)
	if i := strings.LastIndexByte(file, ':'); i > 0 && allDigits(file[i+1:]) {
		file = file[:i]
		if j := strings.LastIndexByte(file, ':'); j > 0 && allDigits(file[j+1:]) {
			file = file[:j]
		}
	}
	return strings.TrimPrefix(file, "./")
}

// allDigits reports whether s is a non-empty run of ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// goRequireLine matches one require entry, single-line or inside a block:
// optional indentation and "require", the module path, then the version. The
// rest of the line (an "// indirect" comment, the line ending) is untouched.
// Group 1 is the module, group 2 the version.
var goRequireLine = regexp.MustCompile(`^[ \t]*(?:require[ \t]+)?([^ \t\r\n]+)[ \t]+([^ \t\r\n]+)`)

// EditGoMod bumps module's require line to target and returns the new file.
// Both forms gofmt writes are handled:
//
//	require example.com/mod v1.2.3
//
//	require (
//		example.com/mod v1.2.3 // indirect
//	)
//
// Only the version token is replaced, so indentation, comments and the line
// endings stay exactly as they were. A module with no require entry is
// ErrManifestNotFound; go.sum and replace directives are never touched.
func EditGoMod(src []byte, module, target string) ([]byte, error) {
	if module == "" || target == "" {
		return nil, ErrManifestUnsupported
	}
	version := goModVersion(target)

	var out bytes.Buffer
	out.Grow(len(src))
	inBlock := false
	found := false
	for rest := src; len(rest) > 0; {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i+1], rest[i+1:]
		} else {
			rest = nil
		}

		trimmed := strings.TrimSpace(string(line))
		switch {
		case inBlock:
			if trimmed == ")" {
				inBlock = false
				break
			}
			if bumped, ok := bumpRequireLine(line, module, version); ok {
				found = true
				line = bumped
			}
		case trimmed == "require (" || strings.HasPrefix(trimmed, "require("):
			inBlock = true
		case strings.HasPrefix(trimmed, "require ") || strings.HasPrefix(trimmed, "require\t"):
			if bumped, ok := bumpRequireLine(line, module, version); ok {
				found = true
				line = bumped
			}
		}
		out.Write(line)
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrManifestNotFound, module)
	}
	return out.Bytes(), nil
}

// bumpRequireLine replaces the version in one line when the line's module is
// module.
func bumpRequireLine(line []byte, module, version string) ([]byte, bool) {
	match := goRequireLine.FindSubmatchIndex(line)
	if match == nil {
		return line, false
	}
	if string(line[match[2]:match[3]]) != module {
		return line, false
	}
	versionStart, versionEnd := match[4], match[5]

	bumped := make([]byte, 0, len(line)+len(version))
	bumped = append(bumped, line[:versionStart]...)
	bumped = append(bumped, version...)
	bumped = append(bumped, line[versionEnd:]...)
	return bumped, true
}

// goModVersion spells target the way go.mod writes a module version. Trivy
// reports Go versions both with and without the leading "v".
func goModVersion(target string) string {
	if strings.HasPrefix(target, "v") {
		return target
	}
	return "v" + target
}

// packageJSONSections are the dependency maps a bump looks in, in the order the
// UI reads them. A package in any of them can be bumped; one in none of them
// is transitive.
var packageJSONSections = []string{
	"dependencies",
	"devDependencies",
	"optionalDependencies",
	"peerDependencies",
}

// jsonSpan is a value's byte range inside the source.
type jsonSpan struct {
	start int
	end   int
}

// EditPackageJSON bumps pkg to target and returns the new file. The version
// keeps the range prefix its dependency object uses — "^", "~" or none at all
// for a pinned version — so "^4.17.0" becomes "^4.17.21" and "4.17.0" becomes
// "4.17.21". Only the version string's bytes change: indentation, key order and
// line endings stay exactly as they were. A package in none of the dependency
// sections is ErrManifestNotFound.
func EditPackageJSON(src []byte, pkg, target string) ([]byte, error) {
	if pkg == "" || target == "" {
		return nil, ErrManifestUnsupported
	}

	spans, err := topLevelSpans(src)
	if err != nil {
		return nil, fmt.Errorf("%w: package.json: %w", ErrManifestUnsupported, err)
	}

	type edit struct {
		span        jsonSpan
		replacement []byte
	}
	var edits []edit
	for _, section := range packageJSONSections {
		span, ok := spans[section]
		if !ok {
			continue
		}
		region := src[span.start:span.end]
		updated, changed, err := bumpDependency(region, pkg, target)
		if err != nil {
			return nil, err
		}
		if changed {
			edits = append(edits, edit{span: span, replacement: updated})
		}
	}
	if len(edits) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrManifestNotFound, pkg)
	}

	// Apply from the end so an earlier replacement cannot shift a later span.
	out := src
	for i := len(edits) - 1; i >= 0; i-- {
		e := edits[i]
		next := make([]byte, 0, len(out)+len(e.replacement))
		next = append(next, out[:e.span.start]...)
		next = append(next, e.replacement...)
		next = append(next, out[e.span.end:]...)
		out = next
	}
	return out, nil
}

// bumpDependency rewrites pkg's version inside one dependency object region.
// changed is false when the object has no such member.
func bumpDependency(region []byte, pkg, target string) (updated []byte, changed bool, err error) {
	quoted, err := json.Marshal(pkg)
	if err != nil {
		return nil, false, ErrManifestUnsupported
	}
	pattern := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(string(quoted)) + `[ \t\r\n]*:[ \t\r\n]*"((?:[^"\\]|\\.)*)"`)
	match := pattern.FindSubmatchIndex(region)
	if match == nil {
		return region, false, nil
	}

	current := region[match[2]:match[3]]
	currentRange, err := unquoteJSON(current)
	if err != nil {
		return nil, false, ErrManifestUnsupported
	}
	nextRange, err := bumpNPMRange(currentRange, target)
	if err != nil {
		return nil, false, err
	}

	updated = make([]byte, 0, len(region)+len(nextRange))
	updated = append(updated, region[:match[2]]...)
	updated = append(updated, nextRange...)
	updated = append(updated, region[match[3]:]...)
	return updated, true, nil
}

// unquoteJSON decodes the bytes of a JSON string body.
func unquoteJSON(raw []byte) (string, error) {
	var value string
	if err := json.Unmarshal(append(append([]byte{'"'}, raw...), '"'), &value); err != nil {
		return "", err
	}
	return value, nil
}

// bumpNPMRange keeps the range prefix the dependency object used. Only the
// shapes this version can preserve without guessing are accepted: a caret
// range, a tilde range and an exact version.
func bumpNPMRange(current, target string) (string, error) {
	switch {
	case strings.HasPrefix(current, "^"):
		return "^" + target, nil
	case strings.HasPrefix(current, "~"):
		return "~" + target, nil
	case current != "" && current[0] >= '0' && current[0] <= '9':
		return target, nil
	default:
		return "", fmt.Errorf("%w: npm range %q", ErrManifestUnsupported, current)
	}
}

// topLevelSpans maps every member of the file's top-level JSON object to its
// value's byte range, so an edit can stay inside the dependency section that
// holds it.
func topLevelSpans(src []byte) (map[string]jsonSpan, error) {
	dec := json.NewDecoder(bytes.NewReader(src))
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("the file is not a JSON object")
	}

	spans := make(map[string]jsonSpan)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("the file has a non-string key")
		}

		start := valueStart(src, int(dec.InputOffset()))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		spans[key] = jsonSpan{start: start, end: int(dec.InputOffset())}
	}
	return spans, nil
}

// valueStart skips the colon and whitespace after an object key and returns
// where its value begins.
func valueStart(src []byte, offset int) int {
	for offset < len(src) && isJSONSpace(src[offset]) {
		offset++
	}
	if offset < len(src) && src[offset] == ':' {
		offset++
	}
	for offset < len(src) && isJSONSpace(src[offset]) {
		offset++
	}
	return offset
}

// isJSONSpace reports whether b is whitespace JSON allows between tokens.
func isJSONSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
