package depsdev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
)

// stubServer answers deps.dev package lookups from a table keyed by
// "SYSTEM/name". A missing entry is a 404, as deps.dev answers for a package it
// does not know. hits counts every request so tests can prove nothing was sent.
type stubServer struct {
	*httptest.Server
	hits atomic.Int32
}

func newStubServer(t *testing.T, versions map[string]string) *stubServer {
	t.Helper()

	stub := &stubServer{}
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.hits.Add(1)
		// /v3/systems/{system}/packages/{name}; package names may contain
		// slashes, which the caller percent-escapes.
		parts := strings.Split(strings.Trim(r.URL.EscapedPath(), "/"), "/")
		if len(parts) != 5 || parts[0] != "v3" || parts[1] != "systems" || parts[3] != "packages" {
			http.NotFound(w, r)
			return
		}
		system, err := url.PathUnescape(parts[2])
		if err != nil {
			http.NotFound(w, r)
			return
		}
		name, err := url.PathUnescape(parts[4])
		if err != nil {
			http.NotFound(w, r)
			return
		}
		version, ok := versions[system+"/"+name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"versions":[{"versionKey":{"version":"` + version + `"},"isDefault":true}]}`))
	}))
	t.Cleanup(stub.Close)
	return stub
}

// failingServer answers every lookup with a server error.
func failingServer(t *testing.T) *stubServer {
	t.Helper()

	stub := &stubServer{}
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		stub.hits.Add(1)
		http.Error(w, "upstream unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(stub.Close)
	return stub
}

// newService builds an opted-in service pointed at the stub.
func newService(t *testing.T, stub *stubServer) *Service {
	t.Helper()

	service := New(Config{DataDir: t.TempDir(), BaseURL: stub.URL, Version: "test"})
	if err := service.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	return service
}

// npmPackage is one inventory entry in an ecosystem deps.dev serves.
func npmPackage(name, version, path string) findings.Package {
	return findings.Package{Ecosystem: "npm", Name: name, Version: version, Path: path}
}

func testAsset() findings.Asset {
	return findings.Asset{ID: 7, Kind: findings.AssetKindPath, Ref: "/tmp/outdated-test"}
}

func TestOffMakesNoRequest(t *testing.T) {
	stub := newStubServer(t, map[string]string{"NPM/lodash": "4.17.21"})
	service := New(Config{DataDir: t.TempDir(), BaseURL: stub.URL, Version: "test"})

	found, warnings, err := service.Match(context.Background(), []findings.Package{npmPackage("lodash", "4.17.20", "package-lock.json")}, testAsset())
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(found) != 0 || len(warnings) != 0 {
		t.Fatalf("findings = %d, warnings = %v, want none with the lookup off", len(found), warnings)
	}
	if got := stub.hits.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0 with the lookup off", got)
	}
}

func TestOutdatedFinding(t *testing.T) {
	stub := newStubServer(t, map[string]string{
		"NPM/lodash":           "4.17.21",
		"GO/golang.org/x/text": "0.3.8",
	})
	service := newService(t, stub)

	found, warnings, err := service.Match(context.Background(), []findings.Package{
		npmPackage("lodash", "4.17.20", "package-lock.json"),
		{Ecosystem: "go", Name: "golang.org/x/text", Version: "0.3.7", Path: "go.mod"},
	}, testAsset())
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(found) != 2 {
		t.Fatalf("findings = %d, want 2", len(found))
	}

	var lodash *findings.Finding
	for i := range found {
		if found[i].PackageName == "lodash" {
			lodash = &found[i]
		}
	}
	if lodash == nil {
		t.Fatal("no finding for lodash")
	}
	if lodash.Type != findings.TypeOutdated {
		t.Errorf("type = %q, want %q", lodash.Type, findings.TypeOutdated)
	}
	if lodash.PackageVersion != "4.17.20" || lodash.FixedVersion != "4.17.21" {
		t.Errorf("current/latest = %q/%q, want 4.17.20/4.17.21", lodash.PackageVersion, lodash.FixedVersion)
	}
	if lodash.Severity != findings.SeverityLow {
		t.Errorf("severity = %q, want low for a patch-level gap", lodash.Severity)
	}
	if lodash.Scanner != Name {
		t.Errorf("scanner = %q, want %q", lodash.Scanner, Name)
	}
	if lodash.Fingerprint == "" {
		t.Error("fingerprint is empty")
	}
}

func TestMajorGapIsMedium(t *testing.T) {
	stub := newStubServer(t, map[string]string{"NPM/lodash": "5.0.0"})
	service := newService(t, stub)

	found, _, err := service.Match(context.Background(), []findings.Package{
		npmPackage("lodash", "4.17.20", "package-lock.json"),
	}, testAsset())
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("findings = %d, want 1", len(found))
	}
	if found[0].Severity != findings.SeverityMedium {
		t.Errorf("severity = %q, want medium for a major-version gap", found[0].Severity)
	}
}

func TestEqualOrNewerIsNotOutdated(t *testing.T) {
	stub := newStubServer(t, map[string]string{
		"NPM/equal": "1.2.3",
		"NPM/newer": "1.2.3",
	})
	service := newService(t, stub)

	found, warnings, err := service.Match(context.Background(), []findings.Package{
		npmPackage("equal", "1.2.3", "package-lock.json"),
		npmPackage("newer", "1.3.0", "package-lock.json"),
	}, testAsset())
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(found) != 0 {
		t.Fatalf("findings = %+v, want none", found)
	}
}

func TestUnsupportedEcosystemSkipped(t *testing.T) {
	stub := newStubServer(t, map[string]string{"COMPOSER/monolog": "3.0.0"})
	service := newService(t, stub)

	found, warnings, err := service.Match(context.Background(), []findings.Package{
		{Ecosystem: "composer", Name: "monolog/monolog", Version: "2.0.0", Path: "composer.lock"},
	}, testAsset())
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(found) != 0 || len(warnings) != 0 {
		t.Fatalf("findings = %d, warnings = %v, want none", len(found), warnings)
	}
	if got := stub.hits.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0 for an unsupported ecosystem", got)
	}
}

func TestServerErrorIsWarningNotFailure(t *testing.T) {
	stub := failingServer(t)
	service := newService(t, stub)

	found, warnings, err := service.Match(context.Background(), []findings.Package{
		npmPackage("lodash", "4.17.20", "package-lock.json"),
	}, testAsset())
	if err != nil {
		t.Fatalf("Match returned a fatal error for an upstream 500: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("findings = %d, want none", len(found))
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "failed") {
		t.Fatalf("warnings = %v, want one failure warning", warnings)
	}
}

func TestCacheAvoidsSecondRequest(t *testing.T) {
	stub := newStubServer(t, map[string]string{"NPM/lodash": "4.17.21"})
	service := newService(t, stub)
	inventory := []findings.Package{npmPackage("lodash", "4.17.20", "package-lock.json")}

	if _, _, err := service.Match(context.Background(), inventory, testAsset()); err != nil {
		t.Fatalf("first Match: %v", err)
	}
	if got := stub.hits.Load(); got != 1 {
		t.Fatalf("requests after the first scan = %d, want 1", got)
	}

	if _, _, err := service.Match(context.Background(), inventory, testAsset()); err != nil {
		t.Fatalf("second Match: %v", err)
	}
	if got := stub.hits.Load(); got != 1 {
		t.Fatalf("requests after the second scan = %d, want 1 (cache hit)", got)
	}
}

func TestSetEnabledRoundTrip(t *testing.T) {
	dir := t.TempDir()
	stub := newStubServer(t, nil)

	first := New(Config{DataDir: dir, BaseURL: stub.URL, Version: "test"})
	if first.Enabled() {
		t.Fatal("enabled = true on a fresh install")
	}
	if err := first.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}

	// A restart reads the stored choice, so the CLI and the server agree.
	second := New(Config{DataDir: dir, BaseURL: stub.URL, Version: "test"})
	if !second.Enabled() {
		t.Fatal("enabled = false after it was stored")
	}
}

func TestMatchIsConcurrencySafe(t *testing.T) {
	stub := newStubServer(t, map[string]string{
		"NPM/a": "2.0.0",
		"NPM/b": "2.0.0",
		"NPM/c": "2.0.0",
	})
	service := newService(t, stub)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := service.Match(context.Background(), []findings.Package{
				npmPackage("a", "1.0.0", "package-lock.json"),
				npmPackage("b", "1.0.0", "package-lock.json"),
				npmPackage("c", "1.0.0", "package-lock.json"),
			}, testAsset()); err != nil {
				t.Errorf("Match: %v", err)
			}
		}()
	}
	wg.Wait()
}
