package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/export"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/reports"
)

// GetReportLicenses implements gen.StrictServerInterface.
func (s *Server) GetReportLicenses(ctx context.Context, request gen.GetReportLicensesRequestObject) (gen.GetReportLicensesResponseObject, error) {
	if s.reports == nil {
		return gen.GetReportLicenses500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", reportsUnavailable),
		}, nil
	}

	assetID, ok := reportAssetID(request.Params.AssetId)
	if !ok {
		return gen.GetReportLicenses400ApplicationProblemPlusJSONResponse(
			newProblem(http.StatusBadRequest, "Bad Request", "asset_id must be a positive integer"),
		), nil
	}
	report, err := s.reports.Licenses(ctx, assetID)
	if err != nil {
		if errors.Is(err, reports.ErrInvalid) {
			return gen.GetReportLicenses400ApplicationProblemPlusJSONResponse(
				newProblem(http.StatusBadRequest, "Bad Request", err.Error()),
			), nil
		}
		s.log.Error("report licenses", "asset", assetID, "error", err)
		return gen.GetReportLicenses500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error",
				"could not read the licence inventory; see the server log"),
		}, nil
	}

	out := gen.LicensesReport{Licenses: make([]gen.LicenseEntry, 0, len(report.Licenses))}
	for _, entry := range report.Licenses {
		items := make([]gen.LicenseItem, 0, len(entry.Items))
		for _, item := range entry.Items {
			items = append(items, gen.LicenseItem{
				PackageName:    item.PackageName,
				PackageVersion: item.PackageVersion,
				Ecosystem:      item.Ecosystem,
				AssetId:        item.AssetID,
				DisplayName:    item.DisplayName,
			})
		}
		out.Licenses = append(out.Licenses, gen.LicenseEntry{
			License:  entry.License,
			Policy:   gen.LicenseEntryPolicy(entry.Policy),
			Packages: entry.Packages,
			Assets:   entry.Assets,
			Items:    items,
		})
	}
	return gen.GetReportLicenses200JSONResponse(out), nil
}

// handleLicenseCSV serves GET /api/reports/licenses.csv. It is hand-written
// like handleFindingsExport: the generated strict server cannot set the
// Content-Disposition header a download needs, so the operation is excluded
// from codegen and documented in the spec. One row is written per finding.
func (s *Server) handleLicenseCSV(w http.ResponseWriter, r *http.Request) {
	if s.reports == nil {
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error", reportsUnavailable)
		return
	}

	var assetID int64
	if raw := strings.TrimSpace(r.URL.Query().Get("asset_id")); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 1 {
			writeProblem(w, http.StatusBadRequest, "Bad Request",
				"asset_id must be a positive integer")
			return
		}
		assetID = id
	}

	report, err := s.reports.Licenses(r.Context(), assetID)
	if err != nil {
		if errors.Is(err, reports.ErrInvalid) {
			writeProblem(w, http.StatusBadRequest, "Bad Request", err.Error())
			return
		}
		s.log.Error("export licences", "error", err)
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error",
			"could not read the licence inventory; see the server log")
		return
	}

	table := licenseTable(report)
	body, err := export.CSV(table)
	if err != nil {
		s.log.Error("encode licence CSV", "error", err)
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error",
			"could not write the export; see the server log")
		return
	}

	header := w.Header()
	header.Set("Content-Type", "text/csv; charset=utf-8")
	header.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q",
		"bastion-licenses-"+time.Now().UTC().Format("20060102")+".csv"))
	header.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		// The status line is already written, so the log is the only signal.
		s.log.Error("write licence CSV", "error", err)
	}
}

// licenseTable flattens the report into one row per finding.
func licenseTable(report reports.LicenseReport) export.Table {
	table := export.Table{Columns: []export.Column{
		{Key: "license", Header: "license"},
		{Key: "policy", Header: "policy"},
		{Key: "package", Header: "package"},
		{Key: "version", Header: "version"},
		{Key: "ecosystem", Header: "ecosystem"},
		{Key: "asset", Header: "asset"},
	}}
	for _, entry := range report.Licenses {
		for _, item := range entry.Items {
			table.Rows = append(table.Rows, []export.Cell{
				export.TextCell(entry.License),
				export.TextCell(entry.Policy),
				export.TextCell(item.PackageName),
				export.TextCell(item.PackageVersion),
				export.TextCell(item.Ecosystem),
				export.TextCell(item.DisplayName),
			})
		}
	}
	return table
}
