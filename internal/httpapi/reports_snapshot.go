package httpapi

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	reportrender "github.com/ozerozdas/bastion/internal/report/render"
	"github.com/ozerozdas/bastion/internal/reports"
)

// The formats GET /api/reports/snapshot writes (#204).
const (
	reportSnapshotMarkdown = "md"
	reportSnapshotHTML     = "html"
	reportSnapshotJSON     = "json"
)

// handleReportSnapshot serves GET /api/reports/snapshot. It is hand-written
// like handleLicenseCSV: the generated strict server cannot set the
// Content-Disposition header a download needs, so the operation is excluded
// from codegen (api/oapi-codegen.yaml) and documented in the spec.
//
// The filename is stamped from the snapshot's own GeneratedAt, not time.Now,
// so the document and its name describe the same instant.
func (s *Server) handleReportSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.reports == nil {
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error", reportsUnavailable)
		return
	}

	format, ok := reportSnapshotFormat(r.URL.Query().Get("format"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "Bad Request",
			"format must be one of md, html or json")
		return
	}

	var assetID *int64
	if raw := strings.TrimSpace(r.URL.Query().Get("asset_id")); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 1 {
			writeProblem(w, http.StatusBadRequest, "Bad Request",
				"asset_id must be a positive integer")
			return
		}
		assetID = &id
	}

	snapshot, err := s.reports.Snapshot(r.Context(), assetID)
	if err != nil {
		if errors.Is(err, reports.ErrInvalid) {
			writeProblem(w, http.StatusBadRequest, "Bad Request", err.Error())
			return
		}
		s.log.Error("report snapshot", "error", err)
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error",
			"could not build the report snapshot; see the server log")
		return
	}

	var body bytes.Buffer
	switch format {
	case reportSnapshotMarkdown:
		err = reportrender.Markdown(&body, snapshot)
	case reportSnapshotHTML:
		err = reportrender.HTML(&body, snapshot)
	case reportSnapshotJSON:
		err = reportrender.JSON(&body, snapshot)
	}
	if err != nil {
		s.log.Error("render report snapshot", "format", format, "error", err)
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error",
			"could not render the report; see the server log")
		return
	}

	header := w.Header()
	header.Set("Content-Type", reportSnapshotMediaType(format))
	header.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q",
		reportSnapshotFilename(format, snapshot.GeneratedAt.UTC())))
	header.Set("Content-Length", strconv.Itoa(body.Len()))
	header.Set("X-Content-Type-Options", "nosniff")
	if format == reportSnapshotHTML {
		// The page is self-contained and carries inline CSS only: it can neither
		// fetch anything nor run script, even when opened from disk.
		header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body.Bytes()); err != nil {
		// The status line is already written, so the log is the only signal left.
		s.log.Error("write report snapshot", "format", format, "error", err)
	}
}

// reportSnapshotFormat normalizes the query value. An empty value is JSON, the
// machine-readable default.
func reportSnapshotFormat(value string) (string, bool) {
	format := strings.ToLower(strings.TrimSpace(value))
	if format == "" {
		return reportSnapshotJSON, true
	}
	switch format {
	case reportSnapshotMarkdown, reportSnapshotHTML, reportSnapshotJSON:
		return format, true
	default:
		return "", false
	}
}

// reportSnapshotMediaType is the Content-Type of one format.
func reportSnapshotMediaType(format string) string {
	switch format {
	case reportSnapshotMarkdown:
		return "text/markdown; charset=utf-8"
	case reportSnapshotHTML:
		return "text/html; charset=utf-8"
	default:
		return "application/json"
	}
}

// reportSnapshotFilename names the attachment from the snapshot's timestamp in
// UTC: bastion-report-<YYYYMMDD-HHMM>.<ext>.
func reportSnapshotFilename(format string, generatedAt time.Time) string {
	return "bastion-report-" + generatedAt.Format("20060102-1504") + "." + format
}
