package main

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// testReportDeps wires the production services against a temp database, like
// the doctor tests: the user's data directory is never touched.
func testReportDeps(t *testing.T) reportDeps {
	t.Helper()

	dir := t.TempDir()
	return reportDeps{
		paths:   app.Paths{DataDir: dir, CacheDir: filepath.Join(dir, "cache")},
		openDB:  store.Open,
		closeDB: (*sql.DB).Close,
		newService: func(db *sql.DB) (*reports.Service, error) {
			return reports.NewService(db)
		},
	}
}

// TestRunReportFormats covers each renderer: non-empty output that starts with
// its document's header.
func TestRunReportFormats(t *testing.T) {
	tests := []struct {
		format string
		header string
	}{
		{format: reportFormatMarkdown, header: "# Bastion security report"},
		{format: reportFormatHTML, header: "<!DOCTYPE html>"},
		{format: reportFormatJSON, header: `"generated_at"`},
	}

	for _, test := range tests {
		t.Run(test.format, func(t *testing.T) {
			var out bytes.Buffer
			opts := reportOptions{format: test.format}

			if err := runReport(context.Background(), &out, opts, testReportDeps(t)); err != nil {
				t.Fatalf("runReport: %v", err)
			}
			body := out.String()
			if body == "" {
				t.Fatal("report output is empty")
			}
			if !strings.Contains(body, test.header) {
				t.Errorf("report output = %q, want it to contain %q", firstChunk(body), test.header)
			}
		})
	}
}

// TestRunReportDefaultFormatIsMarkdown keeps the command's default honest.
func TestRunReportDefaultFormatIsMarkdown(t *testing.T) {
	cmd := newReportCmd(&rootOptions{})
	flag := cmd.Flags().Lookup("format")
	if flag == nil {
		t.Fatal("report has no --format flag")
	}
	if flag.DefValue != reportFormatMarkdown {
		t.Errorf("--format default = %q, want %q", flag.DefValue, reportFormatMarkdown)
	}
}

// TestRunReportRejectsUnknownFormat proves a typo fails before any database is
// opened: the deps have no openDB.
func TestRunReportRejectsUnknownFormat(t *testing.T) {
	var out bytes.Buffer
	err := runReport(context.Background(), &out,
		reportOptions{format: "pdf"}, reportDeps{paths: app.Paths{}})
	if err == nil {
		t.Fatal("runReport accepted format \"pdf\"")
	}
	for _, want := range []string{"unsupported format", "md", "html", "json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want nothing on an invalid format", out.String())
	}
}

// TestRunReportUnknownAsset proves a mis-typed id is an error, not an empty
// fleet report.
func TestRunReportUnknownAsset(t *testing.T) {
	var out bytes.Buffer
	err := runReport(context.Background(), &out,
		reportOptions{format: reportFormatMarkdown, assetID: 99}, testReportDeps(t))
	if err == nil {
		t.Fatal("runReport accepted an unknown asset")
	}
	if !strings.Contains(err.Error(), "no asset with id 99") {
		t.Errorf("error = %q, want it to name the missing asset", err)
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want nothing for a missing asset", out.String())
	}
}

// TestRunReportArchivedAsset proves a removed asset is an error too: the
// snapshot excludes archived assets, so a valid-looking empty report would hide
// the removal.
func TestRunReportArchivedAsset(t *testing.T) {
	ctx := context.Background()
	deps := testReportDeps(t)

	db, err := store.Open(ctx, deps.paths.DBPath())
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	asset, err := store.GetOrCreateAsset(ctx, db, findings.Asset{
		Kind:        findings.AssetKindRepo,
		DisplayName: "Archived repo",
		Ref:         "octo/archived",
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if _, err := sqlcdb.New(db).ArchiveAsset(ctx, sqlcdb.ArchiveAssetParams{
		ArchivedAt: sql.NullString{String: "2026-11-27T09:00:00Z", Valid: true},
		ID:         asset.ID,
	}); err != nil {
		t.Fatalf("archive asset: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	var out bytes.Buffer
	err = runReport(ctx, &out,
		reportOptions{format: reportFormatMarkdown, assetID: asset.ID}, deps)
	if err == nil {
		t.Fatal("runReport accepted an archived asset")
	}
	if !strings.Contains(err.Error(), "is archived") {
		t.Errorf("error = %q, want it to say the asset is archived", err)
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want nothing for an archived asset", out.String())
	}
}

// TestRunReportRejectsNegativeAsset covers the other side of the id check.
func TestRunReportRejectsNegativeAsset(t *testing.T) {
	var out bytes.Buffer
	err := runReport(context.Background(), &out,
		reportOptions{format: reportFormatMarkdown, assetID: -1}, testReportDeps(t))
	if err == nil || !strings.Contains(err.Error(), "positive asset id") {
		t.Fatalf("error = %v, want a positive asset id rejection", err)
	}
}

// firstChunk shortens a document for a failure message.
func firstChunk(body string) string {
	const limit = 64
	if len(body) <= limit {
		return body
	}
	return body[:limit]
}
