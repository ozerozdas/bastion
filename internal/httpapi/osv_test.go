package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/scanners/osv"
)

func readOSVStatus(t *testing.T, resp *http.Response) gen.OSVStatus {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var status gen.OSVStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode OSV status: %v", err)
	}
	return status
}

func TestOSVOnByDefault(t *testing.T) {
	ts := newTestServerWithOSV(t, osv.NewSettings(t.TempDir()))
	cookie := ts.login(t)

	// A missing settings file means on, which keeps the behaviour of versions
	// that predate the toggle.
	status := readOSVStatus(t, ts.do(t, http.MethodGet, "/api/osv", withCookie(cookie)))
	if !status.Enabled {
		t.Error("enabled = false on a fresh install")
	}
}

func TestSetOSVEnabledPersists(t *testing.T) {
	dir := t.TempDir()
	ts := newTestServerWithOSV(t, osv.NewSettings(dir))
	cookie := ts.login(t)

	off := readOSVStatus(t, ts.doJSON(t, http.MethodPut, "/api/osv", `{"enabled":false}`, cookie, true))
	if off.Enabled {
		t.Error("enabled = true after opting out")
	}

	// The setting is stored, not just echoed: a fresh Settings over the same
	// data directory reads the same choice.
	if osv.NewSettings(dir).Enabled() {
		t.Error("enabled = true on a fresh read of the stored setting")
	}

	status := readOSVStatus(t, ts.do(t, http.MethodGet, "/api/osv", withCookie(cookie)))
	if status.Enabled {
		t.Error("enabled = true on the next read")
	}

	on := readOSVStatus(t, ts.doJSON(t, http.MethodPut, "/api/osv", `{"enabled":true}`, cookie, true))
	if !on.Enabled {
		t.Error("enabled = false after opting in")
	}
	if !osv.NewSettings(dir).Enabled() {
		t.Error("enabled = false on a fresh read after opting in")
	}
}

func TestSetOSVEnabledStoreErrorIs500(t *testing.T) {
	// Settings without a data directory cannot store the choice.
	ts := newTestServerWithOSV(t, &osv.Settings{})
	cookie := ts.login(t)

	resp := ts.doJSON(t, http.MethodPut, "/api/osv", `{"enabled":false}`, cookie, true)
	problem := readProblem(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	wantDetail := "could not store the OSV online lookup choice; see the server log"
	if problem.Detail == nil || *problem.Detail != wantDetail {
		t.Errorf("detail = %v, want %q", problem.Detail, wantDetail)
	}
}

func TestSetOSVNilBodyIs400(t *testing.T) {
	ts := newTestServerWithOSV(t, osv.NewSettings(t.TempDir()))
	cookie := ts.login(t)

	// The generated strict handler binds the body, so an empty request never
	// reaches the handler with a nil body.
	if resp := ts.doJSON(t, http.MethodPut, "/api/osv", "", cookie, true); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty body status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	// The nil-body branch is the handler's own guard, reached when the body
	// could not be bound at all.
	response, err := ts.SetOSVEnabled(t.Context(), gen.SetOSVEnabledRequestObject{})
	if err != nil {
		t.Fatalf("SetOSVEnabled: %v", err)
	}
	badRequest, ok := response.(gen.SetOSVEnabled400ApplicationProblemPlusJSONResponse)
	if !ok {
		t.Fatalf("response = %T, want 400 problem", response)
	}
	if badRequest.Body.Status != http.StatusBadRequest {
		t.Errorf("problem status = %d, want %d", badRequest.Body.Status, http.StatusBadRequest)
	}
}

func TestOSVWithoutServiceIs500(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	get := ts.do(t, http.MethodGet, "/api/osv", withCookie(cookie))
	getProblem := readProblem(t, get)
	if get.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET status = %d, want %d", get.StatusCode, http.StatusInternalServerError)
	}
	if getProblem.Detail == nil || *getProblem.Detail != osvUnavailable {
		t.Errorf("GET detail = %v, want %q", getProblem.Detail, osvUnavailable)
	}

	put := ts.doJSON(t, http.MethodPut, "/api/osv", `{"enabled":false}`, cookie, true)
	putProblem := readProblem(t, put)
	if put.StatusCode != http.StatusInternalServerError {
		t.Fatalf("PUT status = %d, want %d", put.StatusCode, http.StatusInternalServerError)
	}
	if putProblem.Detail == nil || *putProblem.Detail != osvUnavailable {
		t.Errorf("PUT detail = %v, want %q", putProblem.Detail, osvUnavailable)
	}
}
