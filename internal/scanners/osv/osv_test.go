package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
)

// newMatcher starts an HTTP server for the OSV API routes the matcher uses and
// returns a Matcher pointed at it.
func newMatcher(t *testing.T, handler http.HandlerFunc) *Matcher {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	m := New("test")
	m.BaseURL = srv.URL
	return m
}

// writeJSON encodes v as the response body.
func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

func TestMatchMalware(t *testing.T) {
	var uaMu sync.Mutex
	var gotUA string
	m := newMatcher(t, func(w http.ResponseWriter, r *http.Request) {
		uaMu.Lock()
		gotUA = r.Header.Get("User-Agent")
		uaMu.Unlock()
		switch r.URL.Path {
		case "/v1/querybatch":
			var req batchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if len(req.Queries) != 1 {
				t.Fatalf("got %d queries, want 1", len(req.Queries))
			}
			if req.Queries[0].Package.Name != "-harseurl" ||
				req.Queries[0].Package.Ecosystem != "npm" ||
				req.Queries[0].Version != "0.0.1" {
				t.Fatalf("unexpected query: %+v", req.Queries[0])
			}
			writeJSON(t, w, batchResponse{Results: []batchResult{{
				Vulns: []vulnID{{ID: "MAL-2022-7"}, {ID: "GHSA-3hch-9p9x-342x"}},
			}}})
		case "/v1/vulns/MAL-2022-7":
			writeJSON(t, w, vulnerability{
				ID:      "MAL-2022-7",
				Summary: "Malicious code in -harseurl (npm)",
				Details: "Any computer that has this package installed should be considered compromised.",
			})
		case "/v1/vulns/GHSA-3hch-9p9x-342x":
			writeJSON(t, w, vulnerability{
				ID:               "GHSA-3hch-9p9x-342x",
				Summary:          "Prototype pollution in -harseurl",
				Details:          "A crafted property path pollutes Object.prototype.",
				Aliases:          []string{"CVE-2021-99999"},
				DatabaseSpecific: databaseSpecific{Severity: "MODERATE"},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	asset := findings.Asset{ID: 7, Kind: findings.AssetKindPath, DisplayName: "project"}
	fs, err := m.Match(context.Background(), []findings.Package{{
		Ecosystem: "npm",
		Name:      "-harseurl",
		Version:   "0.0.1",
		Path:      "package-lock.json",
	}}, asset)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	uaMu.Lock()
	gotUAValue := gotUA
	uaMu.Unlock()
	if gotUAValue != "bastion/test" {
		t.Errorf("User-Agent = %q, want bastion/test", gotUAValue)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want the MAL and the GHSA advisory: %+v", len(fs), fs)
	}
	var malware, vulnFinding *findings.Finding
	for i := range fs {
		switch fs[i].RuleID {
		case "MAL-2022-7":
			malware = &fs[i]
		case "GHSA-3hch-9p9x-342x":
			vulnFinding = &fs[i]
		}
	}
	if malware == nil || vulnFinding == nil {
		t.Fatalf("findings = %+v, want one MAL- and one GHSA- finding", fs)
	}
	f := *malware
	if f.Type != findings.TypeMalware || f.Severity != findings.SeverityCritical {
		t.Errorf("type/severity = %s/%s, want malware/critical", f.Type, f.Severity)
	}
	if f.RuleID != "MAL-2022-7" {
		t.Errorf("rule_id = %q, want MAL-2022-7", f.RuleID)
	}
	if f.Title != "Malicious code in -harseurl (npm)" {
		t.Errorf("title = %q", f.Title)
	}
	if f.Description == "" {
		t.Error("description is empty")
	}
	if f.PackageName != "-harseurl" || f.PackageVersion != "0.0.1" || f.Ecosystem != "npm" {
		t.Errorf("package = %s@%s (%s)", f.PackageName, f.PackageVersion, f.Ecosystem)
	}
	if f.Location != "package-lock.json" {
		t.Errorf("location = %q, want package-lock.json", f.Location)
	}
	if f.Scanner != "osv" {
		t.Errorf("scanner = %q, want osv", f.Scanner)
	}
	if want := findings.Fingerprint(asset.ID, f); f.Fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", f.Fingerprint, want)
	}

	v := *vulnFinding
	if v.Type != findings.TypeVulnerability {
		t.Errorf("non-MAL type = %q, want vulnerability", v.Type)
	}
	if v.Severity != findings.SeverityMedium {
		t.Errorf("non-MAL severity = %q, want medium for OSV MODERATE", v.Severity)
	}
	if v.Title != "Prototype pollution in -harseurl" || v.Description == "" {
		t.Errorf("non-MAL title/description = %q/%q", v.Title, v.Description)
	}
	if want := []string{"CVE-2021-99999"}; !slices.Equal(v.Aliases, want) {
		t.Errorf("non-MAL aliases = %v, want %v", v.Aliases, want)
	}
}

func TestMatchNoAdvisories(t *testing.T) {
	m := newMatcher(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
		writeJSON(t, w, batchResponse{Results: []batchResult{{}}})
	})

	fs, err := m.Match(context.Background(), []findings.Package{{
		Ecosystem: "npm",
		Name:      "lodash",
		Version:   "4.17.21",
	}}, findings.Asset{ID: 1})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want none: %+v", len(fs), fs)
	}
}

func TestMatchSkipsUnmappedEcosystems(t *testing.T) {
	m := newMatcher(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("OSV was called for an ecosystem it does not name")
	})

	fs, err := m.Match(context.Background(), []findings.Package{
		{Ecosystem: "os-deb", Name: "libc6", Version: "2.36"},
		{Ecosystem: "unknown", Name: "thing", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "no-version"},
	}, findings.Asset{ID: 1})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want none", len(fs))
	}
}

func TestMatchBatchesAtLimit(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	m := newMatcher(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		mu.Lock()
		sizes = append(sizes, len(req.Queries))
		mu.Unlock()
		results := make([]batchResult, len(req.Queries))
		writeJSON(t, w, batchResponse{Results: results})
	})

	inventory := make([]findings.Package, 0, 1500)
	for i := range 1500 {
		inventory = append(inventory, findings.Package{
			Ecosystem: "npm",
			Name:      fmt.Sprintf("pkg-%d", i),
			Version:   "1.0.0",
		})
	}
	if _, err := m.Match(context.Background(), inventory, findings.Asset{ID: 1}); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(sizes) != 2 || sizes[0] != 1000 || sizes[1] != 500 {
		t.Fatalf("batch sizes = %v, want [1000 500]", sizes)
	}
}

func TestMatchServerError(t *testing.T) {
	m := newMatcher(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	fs, err := m.Match(context.Background(), []findings.Package{{
		Ecosystem: "npm",
		Name:      "-harseurl",
		Version:   "0.0.1",
	}}, findings.Asset{ID: 1})
	if err == nil {
		t.Fatal("Match succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("error = %v, want it to mention status 500", err)
	}
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want none", len(fs))
	}
}

func TestMatchDetailFailureFallsBack(t *testing.T) {
	m := newMatcher(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			writeJSON(t, w, batchResponse{Results: []batchResult{{
				Vulns: []vulnID{{ID: "MAL-2022-7"}, {ID: "GHSA-3hch-9p9x-342x"}},
			}}})
		case "/v1/vulns/MAL-2022-7", "/v1/vulns/GHSA-3hch-9p9x-342x":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	})

	fs, err := m.Match(context.Background(), []findings.Package{{
		Ecosystem: "npm",
		Name:      "-harseurl",
		Version:   "0.0.1",
	}}, findings.Asset{ID: 1})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want both ids without details", len(fs))
	}
	for _, f := range fs {
		switch f.RuleID {
		case "MAL-2022-7":
			if f.Title != "Malicious package -harseurl" {
				t.Errorf("malware title = %q, want the fallback title", f.Title)
			}
		case "GHSA-3hch-9p9x-342x":
			// Without details there are no aliases, but the id still names
			// the finding.
			if f.Title != "GHSA-3hch-9p9x-342x" {
				t.Errorf("vulnerability title = %q, want the advisory id", f.Title)
			}
			if f.Severity != findings.SeverityUnknown || f.Aliases != nil {
				t.Errorf("vulnerability severity/aliases = %q/%v, want unknown/nil", f.Severity, f.Aliases)
			}
		default:
			t.Errorf("unexpected rule id %q", f.RuleID)
		}
	}
}

func TestMatchPagination(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	m := newMatcher(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			mu.Lock()
			calls++
			call := calls
			mu.Unlock()

			var req batchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if len(req.Queries) != 1 {
				t.Fatalf("got %d queries, want 1", len(req.Queries))
			}
			switch call {
			case 1:
				if req.Queries[0].PageToken != "" {
					t.Fatalf("first request has page token %q", req.Queries[0].PageToken)
				}
				writeJSON(t, w, batchResponse{Results: []batchResult{{
					Vulns:         []vulnID{{ID: "MAL-2022-7"}},
					NextPageToken: "page-2",
				}}})
			case 2:
				if req.Queries[0].PageToken != "page-2" {
					t.Fatalf("page token = %q, want page-2", req.Queries[0].PageToken)
				}
				writeJSON(t, w, batchResponse{Results: []batchResult{{
					Vulns: []vulnID{{ID: "MAL-2022-8"}},
				}}})
			default:
				t.Fatalf("unexpected querybatch call %d", call)
			}
		case "/v1/vulns/MAL-2022-7", "/v1/vulns/MAL-2022-8":
			writeJSON(t, w, vulnerability{ID: strings.TrimPrefix(r.URL.Path, "/v1/vulns/"), Summary: "Malicious code"})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	})

	fs, err := m.Match(context.Background(), []findings.Package{{
		Ecosystem: "npm",
		Name:      "-harseurl",
		Version:   "0.0.1",
	}}, findings.Asset{ID: 1})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 2 {
		t.Errorf("querybatch calls = %d, want 2", gotCalls)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2 across pages: %+v", len(fs), fs)
	}
}

func TestEcosystem(t *testing.T) {
	tests := map[string]string{
		"npm":             "npm",
		"pypi":            "PyPI",
		"go":              "Go",
		"maven":           "Maven",
		"gem":             "RubyGems",
		"nuget":           "NuGet",
		"cargo":           "crates.io",
		"composer":        "Packagist",
		"composer-vendor": "Packagist",
		"conan":           "ConanCenter",
		"julia":           "Julia",
		// Unmapped: OSV has no single ecosystem for OS packages, and it
		// rejects CocoaPods. These must stay out rather than be guessed.
		"os-deb":     "",
		"packagist":  "",
		"cocoapods":  "",
		"cran":       "",
		"unknown-ec": "",
	}
	for in, want := range tests {
		got, ok := ecosystem(in)
		if want == "" {
			if ok {
				t.Errorf("ecosystem(%q) = %q, want unmapped", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("ecosystem(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestMatchDeduplicatesQueries(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	m := newMatcher(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			mu.Lock()
			calls++
			mu.Unlock()
			var req batchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if len(req.Queries) != 1 {
				t.Fatalf("got %d queries, want 1 for the same package", len(req.Queries))
			}
			writeJSON(t, w, batchResponse{Results: []batchResult{{
				Vulns: []vulnID{{ID: "MAL-2022-7"}},
			}}})
		case "/v1/vulns/MAL-2022-7":
			writeJSON(t, w, vulnerability{ID: "MAL-2022-7", Summary: "Malicious code"})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	})

	fs, err := m.Match(context.Background(), []findings.Package{
		{Ecosystem: "npm", Name: "-harseurl", Version: "0.0.1", Path: "a/package-lock.json"},
		{Ecosystem: "npm", Name: "-harseurl", Version: "0.0.1", Path: "b/package-lock.json"},
	}, findings.Asset{ID: 1})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 1 {
		t.Errorf("querybatch calls = %d, want 1", gotCalls)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want one per inventory entry", len(fs))
	}
}
