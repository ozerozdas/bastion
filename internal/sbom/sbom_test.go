package sbom_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/sbom"
)

// fixtureAsset is the scanned artifact of the golden fixture.
func fixtureAsset() findings.Asset {
	return findings.Asset{
		Kind:        findings.AssetKindPath,
		Ref:         "/tmp/diff-demo",
		DisplayName: "Diff Demo",
	}
}

// fixturePackages is one scan's inventory, deliberately unsorted and with a
// duplicate, so the golden covers ordering and de-duplication: a package
// reported twice (two scanners, two lockfiles) is one component.
func fixturePackages() []findings.Package {
	return []findings.Package{
		{Ecosystem: "os-deb", Name: "openssl", Version: "3.0.11", Path: "var/lib/dpkg/status"},
		{Ecosystem: "npm", Name: "@types/react", Version: "19.2.0", PURL: "pkg:npm/%40types/react@19.2.0"},
		{Ecosystem: "go", Name: "github.com/spf13/cobra", Version: "v1.10.2"},
		{Ecosystem: "go", Name: "github.com/spf13/cobra", Version: "v1.10.2", Path: "tools"},
		{Ecosystem: "pypi", Name: "Django", Version: "4.2.0"},
		{Ecosystem: "maven", Name: "log4j-core", Version: "2.14.0"},
		// The same package without a scanner purl: it derives the one the
		// previous entry already states, so it must collapse onto it.
		{Ecosystem: "npm", Name: "@types/react", Version: "19.2.0"},
	}
}

// fixtureOptions pins the two non-deterministic fields, so the output is a
// golden.
func fixtureOptions() sbom.Options {
	return sbom.Options{
		ToolVersion:  "1.2.3",
		Timestamp:    time.Date(2026, 11, 13, 9, 30, 0, 0, time.UTC),
		SerialNumber: "urn:uuid:6ba7b810-9dad-41d1-80b4-00c04fd430c8",
	}
}

// buildFixture encodes the golden document the way both callers do.
func buildFixture(t *testing.T) []byte {
	t.Helper()

	body, err := json.MarshalIndent(sbom.Build(fixtureAsset(), fixturePackages(), fixtureOptions()), "", "  ")
	if err != nil {
		t.Fatalf("marshal BOM: %v", err)
	}
	return append(body, '\n')
}

// TestBuildGolden pins the whole document: the CycloneDX envelope, the metadata
// and the sorted, de-duplicated components.
func TestBuildGolden(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "golden", "basic.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got := buildFixture(t); !bytes.Equal(got, want) {
		t.Errorf("BOM mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestBuildValidatesAgainstCycloneDXSchema checks the done criterion of #24: the
// document validates against the official CycloneDX 1.6 JSON schema vendored in
// testdata (bom-1.6.schema.json plus the spdx.schema.json it references).
func TestBuildValidatesAgainstCycloneDXSchema(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	for _, name := range []string{"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"} {
		schema, err := loadSchema(filepath.Join("testdata", "cyclonedx", name))
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		if err := compiler.AddResource(schemaID(t, schema), schema); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}

	schema, err := compiler.Compile("http://cyclonedx.org/schema/bom-1.6.schema.json")
	if err != nil {
		t.Fatalf("compile CycloneDX schema: %v", err)
	}

	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(buildFixture(t)))
	if err != nil {
		t.Fatalf("decode BOM: %v", err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("BOM does not validate against the CycloneDX 1.6 schema: %v", err)
	}
}

// loadSchema reads one vendored schema file as a schema document.
func loadSchema(path string) (any, error) {
	//nolint:gosec // G304: the path is the test's own testdata directory.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return jsonschema.UnmarshalJSON(file)
}

// schemaID is the $id a vendored schema declares: the compiler needs it to
// resolve the $ref between bom-1.6.schema.json and spdx.schema.json.
func schemaID(t *testing.T, document any) string {
	t.Helper()

	object, ok := document.(map[string]any)
	if !ok {
		t.Fatal("schema document is not a JSON object")
	}
	id, ok := object["$id"].(string)
	if !ok || id == "" {
		t.Fatal("schema document has no $id")
	}
	return id
}

// TestBuildDefaults covers the production defaults: a random serial and the
// current time, so two runs of the same scan are distinct documents.
func TestBuildDefaults(t *testing.T) {
	serialPattern := regexp.MustCompile(
		`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	before := time.Now().UTC()
	first := sbom.Build(fixtureAsset(), fixturePackages(), sbom.Options{ToolVersion: "dev"})
	second := sbom.Build(fixtureAsset(), fixturePackages(), sbom.Options{ToolVersion: "dev"})

	if !serialPattern.MatchString(first.SerialNumber) {
		t.Errorf("SerialNumber = %q, want an RFC 4122 version 4 urn:uuid", first.SerialNumber)
	}
	if first.SerialNumber == second.SerialNumber {
		t.Errorf("two BOMs share the serial %q", first.SerialNumber)
	}
	stamp, err := time.Parse(time.RFC3339, first.Metadata.Timestamp)
	if err != nil {
		t.Fatalf("timestamp %q is not RFC 3339: %v", first.Metadata.Timestamp, err)
	}
	if stamp.Before(before.Add(-time.Minute)) || stamp.After(time.Now().UTC().Add(time.Minute)) {
		t.Errorf("timestamp %v is not the build time", stamp)
	}
}

// TestBuildPURLDerivation covers the ecosystems bastion derives a purl for, and
// the ones it leaves alone rather than inventing coordinates it does not store.
func TestBuildPURLDerivation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pkg     findings.Package
		wantPUR string
	}{
		{name: "go module", pkg: findings.Package{Ecosystem: "go", Name: "golang.org/x/mod", Version: "v0.42.0"},
			wantPUR: "pkg:golang/golang.org/x/mod@v0.42.0"},
		{name: "npm scope", pkg: findings.Package{Ecosystem: "npm", Name: "@tanstack/react-query", Version: "5.0.0"},
			wantPUR: "pkg:npm/%40tanstack/react-query@5.0.0"},
		{name: "pypi is lowercased", pkg: findings.Package{Ecosystem: "pypi", Name: "PyYAML", Version: "6.0.2"},
			wantPUR: "pkg:pypi/pyyaml@6.0.2"},
		{name: "gem", pkg: findings.Package{Ecosystem: "gem", Name: "rails", Version: "7.1.0"},
			wantPUR: "pkg:gem/rails@7.1.0"},
		{name: "cargo", pkg: findings.Package{Ecosystem: "cargo", Name: "serde", Version: "1.0.0"},
			wantPUR: "pkg:cargo/serde@1.0.0"},
		{name: "nuget", pkg: findings.Package{Ecosystem: "nuget", Name: "Newtonsoft.Json", Version: "13.0.3"},
			wantPUR: "pkg:nuget/Newtonsoft.Json@13.0.3"},
		{name: "composer", pkg: findings.Package{Ecosystem: "composer", Name: "monolog/monolog", Version: "3.0.0"},
			wantPUR: "pkg:composer/monolog/monolog@3.0.0"},
		{name: "no version", pkg: findings.Package{Ecosystem: "gem", Name: "rake"},
			wantPUR: "pkg:gem/rake"},
		{name: "scanner purl wins", pkg: findings.Package{Ecosystem: "go", Name: "example.com/x", Version: "v1.0.0",
			PURL: "pkg:golang/example.com/x@v1.0.0?type=module"}, wantPUR: "pkg:golang/example.com/x@v1.0.0?type=module"},
		{name: "maven needs a group", pkg: findings.Package{Ecosystem: "maven", Name: "junit", Version: "4.13.2"}},
		{name: "os-deb needs a distribution", pkg: findings.Package{Ecosystem: "os-deb", Name: "openssl", Version: "3.0.11"}},
		{name: "unknown ecosystem", pkg: findings.Package{Ecosystem: "conan", Name: "zlib", Version: "1.3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := sbom.Build(fixtureAsset(), []findings.Package{tc.pkg}, sbom.Options{SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000"})
			if len(doc.Components) != 1 {
				t.Fatalf("got %d components, want 1", len(doc.Components))
			}
			if got := doc.Components[0].PURL; got != tc.wantPUR {
				t.Errorf("purl = %q, want %q", got, tc.wantPUR)
			}
			// Every component keeps a unique bom-ref even without a purl.
			if doc.Components[0].BOMRef == "" {
				t.Error("bom-ref is empty")
			}
		})
	}
}

// TestBuildEmptyInventory covers a scan that found no packages: a valid BOM
// with an empty component list, not a null one.
func TestBuildEmptyInventory(t *testing.T) {
	doc := sbom.Build(fixtureAsset(), nil, sbom.Options{SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000"})
	if doc.Components == nil {
		t.Fatal("Components is nil, want an empty list")
	}
	if len(doc.Components) != 0 {
		t.Fatalf("got %d components, want 0", len(doc.Components))
	}
}
