package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// putPreferences stores one preference set and returns the response.
func putPreferences(t *testing.T, ts *testServer, cookie *http.Cookie, body map[string]string) *http.Response {
	t.Helper()
	return doJSON(t, ts, http.MethodPut, "/api/preferences", body, withBastion(cookie))
}

// getPreferences reads the stored set.
func getPreferences(t *testing.T, ts *testServer, cookie *http.Cookie) map[string]string {
	t.Helper()

	resp := ts.do(t, http.MethodGet, "/api/preferences", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var stored map[string]string
	if err := json.Unmarshal(readBody(t, resp), &stored); err != nil {
		t.Fatalf("decode preferences: %v", err)
	}
	return stored
}

// TestPreferencesRoundTripAndMerge is the #150 contract: an empty install has
// no values, a PUT stores only its keys, and a later PUT leaves the rest.
func TestPreferencesRoundTripAndMerge(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	if stored := getPreferences(t, ts, cookie); len(stored) != 0 {
		t.Fatalf("initial preferences = %v, want empty", stored)
	}

	resp := putPreferences(t, ts, cookie, map[string]string{
		"bastion-theme": "nord",
		"bastion-mode":  "dark",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first PUT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var first gen.Preferences
	if err := json.Unmarshal(readBody(t, resp), &first); err != nil {
		t.Fatalf("decode first PUT: %v", err)
	}
	if first["bastion-theme"] != "nord" || first["bastion-mode"] != "dark" {
		t.Fatalf("first PUT = %v, want theme=nord mode=dark", first)
	}

	resp = putPreferences(t, ts, cookie, map[string]string{"bastion-language": "tr"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("merge PUT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var merged gen.Preferences
	if err := json.Unmarshal(readBody(t, resp), &merged); err != nil {
		t.Fatalf("decode merge PUT: %v", err)
	}
	want := map[string]string{
		"bastion-theme":    "nord",
		"bastion-mode":     "dark",
		"bastion-language": "tr",
	}
	if len(merged) != len(want) {
		t.Fatalf("merge PUT = %v, want %v", merged, want)
	}
	for key, value := range want {
		if merged[key] != value {
			t.Fatalf("merge PUT[%q] = %q, want %q", key, merged[key], value)
		}
	}

	// A fresh GET sees the same merged set.
	stored := getPreferences(t, ts, cookie)
	for key, value := range want {
		if stored[key] != value {
			t.Fatalf("GET[%q] = %q, want %q", key, stored[key], value)
		}
	}
}

// TestPreferencesRejectsUnknownKeyAndLongValue covers the validation the
// whitelist exists for: a stale client must not grow the table, and a value
// has to stay short.
func TestPreferencesRejectsUnknownKeyAndLongValue(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := putPreferences(t, ts, cookie, map[string]string{"not-a-preference": "x"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown key status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if problem := readProblem(t, resp); !strings.Contains(problemDetail(problem), "not-a-preference") {
		t.Fatalf("unknown key detail = %q, want it to name the key", problemDetail(problem))
	}

	resp = putPreferences(t, ts, cookie, map[string]string{
		"bastion-theme": strings.Repeat("a", 65),
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("long value status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	// Neither rejected request wrote anything.
	if stored := getPreferences(t, ts, cookie); len(stored) != 0 {
		t.Fatalf("preferences after rejected writes = %v, want empty", stored)
	}
}

// problemDetail returns a problem's detail, or its title when absent.
func problemDetail(problem gen.Problem) string {
	if problem.Detail != nil {
		return *problem.Detail
	}
	return problem.Title
}
