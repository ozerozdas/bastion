package httpapi

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// TestReportSnapshotHandler covers each document format: its media type, the
// attachment filename stamped from the snapshot, nosniff and, for HTML, the
// restrictive CSP.
func TestReportSnapshotHandler(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	tests := []struct {
		name        string
		query       string
		contentType string
		ext         string
		header      string
	}{
		{
			name:        "default json",
			query:       "",
			contentType: "application/json",
			ext:         "json",
			header:      `"generated_at"`,
		},
		{
			name:        "markdown",
			query:       "?format=md",
			contentType: "text/markdown; charset=utf-8",
			ext:         "md",
			header:      "# Bastion security report",
		},
		{
			name:        "html",
			query:       "?format=html",
			contentType: "text/html; charset=utf-8",
			ext:         "html",
			header:      "<!DOCTYPE html>",
		},
	}

	filename := regexp.MustCompile(`^attachment; filename="bastion-report-\d{8}-\d{4}\.(json|md|html)"$`)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp := ts.do(t, http.MethodGet, "/api/reports/snapshot"+test.query, withCookie(cookie))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
			}
			if got := resp.Header.Get("Content-Type"); got != test.contentType {
				t.Errorf("Content-Type = %q, want %q", got, test.contentType)
			}
			disposition := resp.Header.Get("Content-Disposition")
			if !filename.MatchString(disposition) {
				t.Errorf("Content-Disposition = %q, want a bastion-report attachment", disposition)
			}
			if !strings.HasSuffix(disposition, "."+test.ext+`"`) {
				t.Errorf("Content-Disposition = %q, want the %s extension", disposition, test.ext)
			}
			if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}

			csp := resp.Header.Get("Content-Security-Policy")
			if test.ext == "html" {
				if want := "default-src 'none'; style-src 'unsafe-inline'"; csp != want {
					t.Errorf("Content-Security-Policy = %q, want %q", csp, want)
				}
			} else if csp != "" {
				t.Errorf("Content-Security-Policy = %q, want none outside HTML", csp)
			}

			body := string(readBody(t, resp))
			if body == "" {
				t.Fatal("body is empty")
			}
			if !strings.Contains(body, test.header) {
				t.Errorf("body = %q, want it to contain %q", firstLine(body), test.header)
			}
		})
	}
}

// TestReportSnapshotHandlerAssetScope covers a valid asset id: a missing asset
// is an empty snapshot, not an error, matching reports.Service.Snapshot.
func TestReportSnapshotHandlerAssetScope(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/reports/snapshot?format=json&asset_id=42", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

// TestReportSnapshotHandlerRequiresSession keeps the download behind the same
// cookie as every other GET.
func TestReportSnapshotHandlerRequiresSession(t *testing.T) {
	ts := newTestServer(t)

	resp := ts.do(t, http.MethodGet, "/api/reports/snapshot", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	readProblem(t, resp)
}

// TestReportSnapshotHandlerRejectsBadQuery covers the problem responses.
func TestReportSnapshotHandlerRejectsBadQuery(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	for _, path := range []string{
		"/api/reports/snapshot?format=xml",
		"/api/reports/snapshot?format=pdf&asset_id=1",
		"/api/reports/snapshot?asset_id=0",
		"/api/reports/snapshot?asset_id=-1",
		"/api/reports/snapshot?asset_id=nope",
	} {
		resp := ts.do(t, http.MethodGet, path, withCookie(cookie))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s: status = %d, want %d: %s", path, resp.StatusCode,
				http.StatusBadRequest, readBody(t, resp))
			continue
		}
		if got := resp.Header.Get("Content-Type"); got != "application/problem+json" {
			t.Errorf("GET %s: Content-Type = %q, want a problem response", path, got)
		}
	}
}
