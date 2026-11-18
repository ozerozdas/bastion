package eol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
)

const alpineBody = `{"result":{"releases":[
{"name":"3.24","isEol":false,"eolFrom":"2028-06-01"},
{"name":"3.18","isEol":true,"eolFrom":"2025-05-09"},
{"name":"3.1","isEol":true,"eolFrom":"2016-11-01"}]}}`

func newService(t *testing.T, handler http.HandlerFunc) *Service {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	s := New(Config{DataDir: t.TempDir(), BaseURL: server.URL})
	if err := s.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMatchReportsEOLOSOnceWithDate(t *testing.T) {
	var requests atomic.Int32
	s := newService(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/api/v1/products/alpine-linux" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(alpineBody))
	})

	for range 2 { // The second scan is served from the cache.
		got, warnings, err := s.Match(context.Background(), "alpine", "3.18.4", nil, findings.Asset{ID: 1})
		if err != nil || len(warnings) != 0 {
			t.Fatalf("err = %v, warnings = %v", err, warnings)
		}
		if len(got) != 1 {
			t.Fatalf("findings = %d, want 1", len(got))
		}
		f := got[0]
		if f.Type != findings.TypeOutdated || !strings.Contains(f.Title, "2025-05-09") || f.FixedVersion != "3.24" {
			t.Fatalf("finding = %+v", f)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", requests.Load())
	}
}

func TestMatchIgnoresSupportedAndUnknownReleases(t *testing.T) {
	s := newService(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(alpineBody))
	})
	for _, version := range []string{"3.24.1", "3.19.1", "edge"} {
		got, _, err := s.Match(context.Background(), "alpine", version, nil, findings.Asset{ID: 1})
		if err != nil || len(got) != 0 {
			t.Fatalf("%s: findings = %v, err = %v", version, got, err)
		}
	}
}

func TestMatchCollapsesGoBinariesOnTheSameRelease(t *testing.T) {
	s := newService(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"releases":[{"name":"1.20","isEol":true,"eolFrom":"2024-02-06"}]}}`))
	})
	inventory := []findings.Package{
		{Ecosystem: "go", Name: "stdlib", Version: "v1.20.3", Path: "a"},
		{Ecosystem: "go", Name: "stdlib", Version: "v1.20.3", Path: "b"},
		{Ecosystem: "npm", Name: "stdlib", Version: "1.20.3"},
	}
	got, _, err := s.Match(context.Background(), "", "", inventory, findings.Asset{ID: 1})
	if err != nil || len(got) != 1 {
		t.Fatalf("findings = %v, err = %v", got, err)
	}
}

func TestMatchDegradesToWarning(t *testing.T) {
	s := newService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	got, warnings, err := s.Match(context.Background(), "debian", "12.5", nil, findings.Asset{ID: 1})
	if err != nil || len(got) != 0 || len(warnings) != 1 {
		t.Fatalf("findings = %v, warnings = %v, err = %v", got, warnings, err)
	}
}

func TestOffMakesNoRequestAndSettingPersists(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(server.Close)
	dir := t.TempDir()

	s := New(Config{DataDir: dir, BaseURL: server.URL})
	if _, _, err := s.Match(context.Background(), "alpine", "3.18.4", nil, findings.Asset{ID: 1}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d, want 0", requests.Load())
	}
	if err := s.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if !New(Config{DataDir: dir}).Enabled() {
		t.Fatal("setting did not persist")
	}
}
