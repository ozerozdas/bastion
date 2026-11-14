package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/sbom"
)

// handleScanSBOM serves GET /api/scans/{id}/sbom (#24). It is hand-written like
// handleEvents: the generated strict server writes the body itself and cannot
// set the Content-Disposition header a download needs, so the operation is
// excluded from codegen (api/oapi-codegen.yaml) and documented in the spec.
func (s *Server) handleScanSBOM(w http.ResponseWriter, r *http.Request) {
	if s.reports == nil {
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error", reportsUnavailable)
		return
	}

	// A malformed id is an unknown scan, exactly like GET /api/scans/{id}.
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeProblem(w, http.StatusNotFound, "Not Found", "scan not found")
		return
	}

	doc, err := s.reports.ScanSBOM(r.Context(), id, sbom.Options{ToolVersion: s.version})
	if err != nil {
		switch {
		case errors.Is(err, reports.ErrNotFound):
			writeProblem(w, http.StatusNotFound, "Not Found", err.Error())
		case errors.Is(err, reports.ErrConflict):
			writeProblem(w, http.StatusConflict, "Conflict", err.Error())
		case errors.Is(err, reports.ErrInvalid):
			writeProblem(w, http.StatusNotFound, "Not Found", err.Error())
		default:
			s.log.Error("scan sbom", "id", id, "error", err)
			writeProblem(w, http.StatusInternalServerError, "Internal Server Error",
				"could not build the SBOM; see the server log")
		}
		return
	}

	header := w.Header()
	header.Set("Content-Type", sbom.MediaType)
	header.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", sbomFilename(doc, id)))
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		// The status line is already written, so the log is the only signal left.
		s.log.Error("write sbom response", "id", id, "error", err)
	}
}

// sbomFilename is the download name: <project>-scan-<id>.cdx.json, with every
// character that is unsafe in a header or a filename replaced.
func sbomFilename(doc sbom.Document, scanID int64) string {
	name := filenameSlug(doc.Metadata.Component.Name)
	if name == "" {
		name = "asset"
	}
	return fmt.Sprintf("%s-scan-%d.cdx.json", name, scanID)
}

// filenameSlug reduces a display name to ASCII letters, digits, ".", "_" and
// "-", collapsing every other run into one "-". It keeps the slug short enough
// to stay a comfortable filename.
func filenameSlug(name string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_':
			b.WriteRune(r)
			lastDash = false
		case !lastDash && b.Len() > 0:
			b.WriteByte('-')
			lastDash = true
		}
		if b.Len() >= 60 {
			break
		}
	}
	return strings.Trim(b.String(), "-.")
}
