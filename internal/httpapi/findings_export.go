package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/export"
	"github.com/ozerozdas/bastion/internal/reports"
)

// handleFindingsExport serves GET /api/findings/export. It is hand-written like
// handleScanSBOM: the generated strict server writes the body itself and cannot
// set the Content-Disposition header a download needs, so the operation is
// excluded from codegen (api/oapi-codegen.yaml) and documented in the spec.
//
// The filters are the findings list's own: the export reads the same
// reports.Filter, so archived assets, decision expiry and effective status mean
// exactly what they mean on the page. The full result is written, never a page.
func (s *Server) handleFindingsExport(w http.ResponseWriter, r *http.Request) {
	if s.reports == nil {
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error", reportsUnavailable)
		return
	}

	query := r.URL.Query()

	format := strings.ToLower(strings.TrimSpace(query.Get("format")))
	if !export.ValidFormat(format) {
		writeProblem(w, http.StatusBadRequest, "Bad Request",
			"format must be one of csv, xlsx or json")
		return
	}

	view := strings.TrimSpace(query.Get("view"))
	if view == "" {
		view = export.ViewGrouped
	}
	if !export.ValidView(view) {
		writeProblem(w, http.StatusBadRequest, "Bad Request",
			"view must be one of grouped or single")
		return
	}

	filter := reports.Filter{
		Severity:  strings.TrimSpace(query.Get("severity")),
		Type:      strings.TrimSpace(query.Get("type")),
		Status:    strings.TrimSpace(query.Get("status")),
		DecidedBy: strings.TrimSpace(query.Get("decided_by")),
		Query:     query.Get("q"),
	}
	if raw := strings.TrimSpace(query.Get("asset_id")); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 1 {
			writeProblem(w, http.StatusBadRequest, "Bad Request",
				"asset_id must be a positive integer")
			return
		}
		filter.AssetID = id
	}

	findings, err := s.reports.Findings(r.Context(), filter)
	if err != nil {
		if errors.Is(err, reports.ErrInvalid) {
			writeProblem(w, http.StatusBadRequest, "Bad Request", err.Error())
			return
		}
		s.log.Error("export findings", "error", err)
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error",
			"could not read the findings; see the server log")
		return
	}

	names, err := s.reports.AssetNames(r.Context())
	if err != nil {
		s.log.Error("export findings asset names", "error", err)
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error",
			"could not read the projects; see the server log")
		return
	}

	epssEnabled := s.epss != nil && s.epss.Enabled()
	var table export.Table
	if view == export.ViewGrouped {
		table = export.Grouped(findings, names, epssEnabled)
	} else {
		table = export.Single(findings, names, epssEnabled)
	}

	body, err := encodeExport(table, format)
	if err != nil {
		s.log.Error("encode findings export", "format", format, "error", err)
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error",
			"could not write the export; see the server log")
		return
	}

	header := w.Header()
	header.Set("Content-Type", exportMediaType(format))
	header.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q",
		exportFilename(view, format)))
	header.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		// The status line is already written, so the log is the only signal left.
		s.log.Error("write findings export", "format", format, "error", err)
	}
}

// encodeExport writes the table in the requested format.
func encodeExport(table export.Table, format string) ([]byte, error) {
	switch format {
	case export.FormatCSV:
		return export.CSV(table)
	case export.FormatXLSX:
		return export.XLSX(table)
	case export.FormatJSON:
		return export.JSON(table)
	}
	return nil, fmt.Errorf("unsupported export format %q", format)
}

// exportMediaType is the download's Content-Type.
func exportMediaType(format string) string {
	switch format {
	case export.FormatCSV:
		return "text/csv; charset=utf-8"
	case export.FormatXLSX:
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case export.FormatJSON:
		return "application/json"
	}
	return "application/octet-stream"
}

// exportFilename is the download name:
// bastion-findings-<view>-<YYYYMMDD>.<ext>.
func exportFilename(view, format string) string {
	return fmt.Sprintf("bastion-findings-%s-%s.%s",
		view, time.Now().UTC().Format("20060102"), export.Extension(format))
}
