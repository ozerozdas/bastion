package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/sbom"
	"github.com/ozerozdas/bastion/internal/store"
)

// The tests in this file drive GET /api/scans/{id}/sbom through the real server,
// so the hand-written route, the reports read model and the download headers
// are covered together.

// seedSBOMScan persists one finished scan with a package inventory and returns
// its id.
func seedSBOMScan(t *testing.T, ts *testServer, assetID int64, status string, list ...findings.Package) int64 {
	t.Helper()

	scanID, err := store.StartScan(t.Context(), ts.db, assetID, store.ScanTriggerCLI)
	if err != nil {
		t.Fatalf("StartScan(asset %d): %v", assetID, err)
	}
	if err := store.SaveScanResult(t.Context(), ts.db, scanID, store.ScanResult{
		Status:     status,
		FinishedAt: reportAt(9),
		Packages:   list,
	}); err != nil {
		t.Fatalf("SaveScanResult(scan %d): %v", scanID, err)
	}
	return scanID
}

// seedSBOMAsset resolves the project the BOM names.
func seedSBOMAsset(t *testing.T, ts *testServer, displayName string) findings.Asset {
	t.Helper()

	asset, err := store.GetOrCreateAsset(t.Context(), ts.db, findings.Asset{
		Kind:        findings.AssetKindPath,
		Ref:         "/tmp/" + strings.ToLower(displayName),
		DisplayName: displayName,
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset(%q): %v", displayName, err)
	}
	return asset
}

// TestGetScanSBOM covers the succeeded scan: CycloneDX media type, an attachment
// filename derived from the project name, and the scan's packages as components.
func TestGetScanSBOM(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	asset := seedSBOMAsset(t, ts, "Alpha Repo")
	scanID := seedSBOMScan(t, ts, asset.ID, store.ScanStatusSucceeded,
		findings.Package{Ecosystem: "go", Name: "github.com/spf13/cobra", Version: "v1.10.2"},
		findings.Package{Ecosystem: "npm", Name: "react", Version: "19.2.0"})

	resp := ts.do(t, http.MethodGet, fmt.Sprintf("/api/scans/%d/sbom", scanID), withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	if got := resp.Header.Get("Content-Type"); got != sbom.MediaType {
		t.Errorf("Content-Type = %q, want %q", got, sbom.MediaType)
	}
	wantDisposition := fmt.Sprintf("attachment; filename=%q", fmt.Sprintf("Alpha-Repo-scan-%d.cdx.json", scanID))
	if got := resp.Header.Get("Content-Disposition"); got != wantDisposition {
		t.Errorf("Content-Disposition = %q, want %q", got, wantDisposition)
	}

	body := readBody(t, resp)
	var doc sbom.Document
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode BOM %q: %v", body, err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != sbom.SpecVersion {
		t.Errorf("BOM envelope = %q %q, want CycloneDX %q", doc.BOMFormat, doc.SpecVersion, sbom.SpecVersion)
	}
	if doc.Metadata.Component.Name != "Alpha Repo" {
		t.Errorf("metadata.component.name = %q, want the project name", doc.Metadata.Component.Name)
	}
	// The stored finish time is the BOM timestamp, so a stored scan always
	// produces the same document.
	if doc.Metadata.Timestamp != "2026-11-10T09:00:00Z" {
		t.Errorf("metadata.timestamp = %q, want the scan's finish time", doc.Metadata.Timestamp)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("got %d components, want 2: %+v", len(doc.Components), doc.Components)
	}
	if doc.Components[0].Name != "github.com/spf13/cobra" || doc.Components[1].Name != "react" {
		t.Errorf("components = %q, %q; want them sorted by name",
			doc.Components[0].Name, doc.Components[1].Name)
	}
	if doc.Components[1].PURL != "pkg:npm/react@19.2.0" {
		t.Errorf("react purl = %q, want the derived npm purl", doc.Components[1].PURL)
	}
	if !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") {
		t.Errorf("serialNumber = %q, want a urn:uuid", doc.SerialNumber)
	}
}

// TestGetScanSBOMRejects covers the problem+json mapping: an unknown or
// malformed id is 404, a scan without a complete result is 409.
func TestGetScanSBOMRejects(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	asset := seedSBOMAsset(t, ts, "Beta")
	failed := seedSBOMScan(t, ts, asset.ID, store.ScanStatusFailed,
		findings.Package{Ecosystem: "go", Name: "example.com/x", Version: "v1.0.0"})

	for _, tc := range []struct {
		name   string
		path   string
		status int
	}{
		{name: "unknown scan", path: "/api/scans/9999/sbom", status: http.StatusNotFound},
		{name: "malformed id", path: "/api/scans/abc/sbom", status: http.StatusNotFound},
		{name: "failed scan", path: fmt.Sprintf("/api/scans/%d/sbom", failed), status: http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := ts.do(t, http.MethodGet, tc.path, withCookie(cookie))
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d: %s", resp.StatusCode, tc.status, readBody(t, resp))
			}
			if got := resp.Header.Get("Content-Disposition"); got != "" {
				t.Errorf("Content-Disposition = %q on an error, want none", got)
			}
			readProblem(t, resp)
		})
	}
}
