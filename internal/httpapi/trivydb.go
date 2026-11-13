package httpapi

import (
	"context"
	"net/http"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/scanners/trivy"
)

// trivyDBUnavailable is the detail for the vulnerability DB endpoints when
// serve did not wire a manager (some tests build a Server without one).
const trivyDBUnavailable = "vulnerability DB management is not configured; start bastion with its data directory"

// GetTrivyDB implements gen.StrictServerInterface. Status never waits for a
// download, so this handler never blocks on the network.
func (s *Server) GetTrivyDB(_ context.Context, _ gen.GetTrivyDBRequestObject) (gen.GetTrivyDBResponseObject, error) {
	if s.trivyDB == nil {
		return gen.GetTrivyDB500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", trivyDBUnavailable),
		}, nil
	}
	return gen.GetTrivyDB200JSONResponse(trivyDBStatus(s.trivyDB.Status())), nil
}

// DownloadTrivyDB implements gen.StrictServerInterface. Starting a download is
// idempotent: while one is in flight, whatever started it, this call starts no
// second one and answers with that download's state.
func (s *Server) DownloadTrivyDB(_ context.Context, _ gen.DownloadTrivyDBRequestObject) (gen.DownloadTrivyDBResponseObject, error) {
	if s.trivyDB == nil {
		return gen.DownloadTrivyDB500ApplicationProblemPlusJSONResponse{
			Body: newProblem(http.StatusInternalServerError, "Internal Server Error", trivyDBUnavailable),
		}, nil
	}
	return gen.DownloadTrivyDB202JSONResponse(trivyDBStatus(s.trivyDB.StartDownload())), nil
}

// trivyDBStatus maps the domain status onto the API shape. Absent optional
// values stay absent rather than becoming "".
func trivyDBStatus(status trivy.DBStatus) gen.TrivyDBStatus {
	out := gen.TrivyDBStatus{
		State:     gen.TrivyDBState(status.State),
		UpdatedAt: status.UpdatedAt,
	}
	if status.Error != "" {
		out.Error = &status.Error
	}
	if status.Trigger != "" {
		trigger := gen.TrivyDBStatusTrigger(status.Trigger)
		out.Trigger = &trigger
	}
	return out
}
