package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ozerozdas/bastion/internal/connections/github"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/reports"
)

// githubCall is one request the fake GitHub API received.
type githubCall struct {
	Method string
	Path   string
	Query  string
	Body   []byte
}

// fakeGitHubAPI serves the write sequence a manifest pull request makes and
// records every call, so a test can assert the exact order.
type fakeGitHubAPI struct {
	mu            sync.Mutex
	calls         []githubCall
	manifest      string
	refExists     bool
	existingPRURL string
	// failPut makes the contents write answer 500 once, so a test can prove the
	// branch is deleted after a partial failure.
	failPut bool
	// The recorded pull request's state, as GET /pulls/{number} answers it.
	prState  string
	prMerged bool
	prGetErr bool
}

// newFakeGitHubAPI starts the fake API. The default branch is main, HEAD is a
// fixed SHA and package.json holds one caret dependency.
func newFakeGitHubAPI(t *testing.T) (*fakeGitHubAPI, *httptest.Server) {
	t.Helper()
	api := &fakeGitHubAPI{
		manifest: `{
  "name": "app",
  "dependencies": {
    "lodash": "^4.17.0"
  }
}
`,
	}
	server := httptest.NewServer(http.HandlerFunc(api.handle))
	t.Cleanup(server.Close)
	return api, server
}

const fakeHeadSHA = "0123456789abcdef0123456789abcdef01234567"

func (a *fakeGitHubAPI) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	a.calls = append(a.calls, githubCall{
		Method: r.Method,
		Path:   r.URL.Path,
		Query:  r.URL.RawQuery,
		Body:   body,
	})
	existingPRURL, refExists, manifest, failPut := a.existingPRURL, a.refExists, a.manifest, a.failPut
	prState, prMerged, prGetErr := a.prState, a.prMerged, a.prGetErr
	a.mu.Unlock()

	key := r.Method + " " + r.URL.Path
	switch key {
	case "GET /repos/acme/app":
		writeJSON(w, http.StatusOK, map[string]any{
			"full_name":      "acme/app",
			"name":           "app",
			"default_branch": "main",
			"owner":          map[string]any{"login": "acme"},
		})
	case "GET /repos/acme/app/commits/main":
		w.Header().Set("Content-Type", "application/vnd.github.sha")
		_, _ = io.WriteString(w, fakeHeadSHA)
	case "GET /repos/acme/app/git/ref/heads/bastion/bump-lodash-4.17.21":
		if refExists {
			writeJSON(w, http.StatusOK, map[string]any{"object": map[string]any{"sha": fakeHeadSHA}})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	case "GET /repos/acme/app/pulls/12", "GET /repos/acme/app/pulls/7":
		if prGetErr {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "boom"})
			return
		}
		number := 12
		if strings.HasSuffix(r.URL.Path, "/7") {
			number = 7
		}
		state := prState
		if state == "" {
			state = "open"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"number":   number,
			"html_url": "https://github.com/acme/app/pull/" + strconv.Itoa(number),
			"state":    state,
			"merged":   prMerged,
		})
	case "GET /repos/acme/app/pulls":
		prs := []map[string]any{}
		if existingPRURL != "" {
			prs = append(prs, map[string]any{"number": 7, "html_url": existingPRURL})
		}
		writeJSON(w, http.StatusOK, prs)
	case "GET /repos/acme/app/contents/package.json":
		writeJSON(w, http.StatusOK, map[string]any{
			"type":     "file",
			"encoding": "base64",
			"path":     "package.json",
			"sha":      "file-sha",
			"content":  base64.StdEncoding.EncodeToString([]byte(manifest)),
		})
	case "POST /repos/acme/app/git/refs":
		writeJSON(w, http.StatusCreated, map[string]any{"ref": "refs/heads/bastion/bump-lodash-4.17.21"})
	case "PUT /repos/acme/app/contents/package.json":
		if failPut {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "boom"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"content": map[string]any{"path": "package.json", "sha": "new-sha"},
		})
	case "DELETE /repos/acme/app/git/refs/heads/bastion/bump-lodash-4.17.21":
		w.WriteHeader(http.StatusNoContent)
	case "POST /repos/acme/app/pulls":
		writeJSON(w, http.StatusCreated, map[string]any{
			"number":   12,
			"html_url": "https://github.com/acme/app/pull/12",
		})
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"message": "unexpected " + key})
	}
}

// writeJSON answers with a JSON body.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// (calls) returns a copy of the recorded request log.
func (a *fakeGitHubAPI) recorded() []githubCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]githubCall, len(a.calls))
	copy(out, a.calls)
	return out
}

// newPullRequestServer builds the test server with the fix plan pull request
// endpoint dialing baseURL through the real GitHub client.
func newPullRequestServer(t *testing.T, baseURL string) *testServer {
	t.Helper()
	fake := newFakeGitHub()
	fake.pullRequestFactory = func(token string) (reports.PullRequestClient, error) {
		return github.New(github.Config{Token: token, BaseURL: baseURL})
	}
	return newTestServerWithGitHub(t, fake)
}

// addRepoAsset creates a GitHub connection and a repository asset on it
// through the API.
func addRepoAsset(t *testing.T, ts *testServer, cookie *http.Cookie) gen.Asset {
	t.Helper()

	created := doJSON(t, ts, http.MethodPost, "/api/connections", map[string]any{
		"kind":  "github",
		"name":  "acme",
		"token": "test-token",
	}, withBastion(cookie))
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("create connection: status = %d, body = %s", created.StatusCode, readBody(t, created))
	}
	var connection gen.Connection
	if err := json.Unmarshal(readBody(t, created), &connection); err != nil {
		t.Fatalf("decode connection: %v", err)
	}

	resp := doJSON(t, ts, http.MethodPost, "/api/assets", map[string]any{
		"kind":          "repo",
		"ref":           "acme/app",
		"connection_id": connection.Id,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create asset: status = %d, body = %s", resp.StatusCode, readBody(t, resp))
	}
	var asset gen.Asset
	if err := json.Unmarshal(readBody(t, resp), &asset); err != nil {
		t.Fatalf("decode asset: %v", err)
	}
	return asset
}

// npmFinding builds one open lodash finding whose scanner location is the
// lockfile, as Trivy reports npm packages.
func npmFinding(assetID int64, ruleID, pkg, installed, fixed string, severity findings.Severity) findings.Finding {
	finding := fixPlanFinding(assetID, ruleID, pkg, installed, fixed, severity)
	finding.Location = "package-lock.json:1"
	finding.Fingerprint = findings.Fingerprint(assetID, finding)
	return finding
}

func TestOpenFixPlanPullRequest(t *testing.T) {
	api, server := newFakeGitHubAPI(t)
	ts := newPullRequestServer(t, server.URL)
	cookie := ts.login(t)

	asset := addRepoAsset(t, ts, cookie)
	seedReportScan(t, ts.db, asset.Id, "succeeded", reportAt(10),
		npmFinding(asset.Id, "CVE-2021-1111", "lodash", "4.17.0", "4.17.19", findings.SeverityCritical),
		npmFinding(asset.Id, "CVE-2021-2222", "lodash", "4.17.0", "4.17.21", findings.SeverityHigh),
	)

	resp := doJSON(t, ts, http.MethodPost, "/api/assets/"+itoa(asset.Id)+"/fix-plan/pull-request", map[string]any{
		"ecosystem": "npm",
		"package":   "lodash",
		"target":    "4.17.21",
		"confirm":   true,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, readBody(t, resp))
	}
	var result gen.FixPlanPullRequestResult
	if err := json.Unmarshal(readBody(t, resp), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Url != "https://github.com/acme/app/pull/12" || result.Number != 12 {
		t.Fatalf("result = %+v", result)
	}
	if result.Branch != "bastion/bump-lodash-4.17.21" {
		t.Errorf("branch = %q", result.Branch)
	}
	if result.Manifest != "package.json" {
		t.Errorf("manifest = %q", result.Manifest)
	}

	calls := api.recorded()
	want := []string{
		"GET /repos/acme/app",
		"GET /repos/acme/app/commits/main",
		"GET /repos/acme/app/git/ref/heads/bastion/bump-lodash-4.17.21",
		"GET /repos/acme/app/contents/package.json",
		"POST /repos/acme/app/git/refs",
		"PUT /repos/acme/app/contents/package.json",
		"POST /repos/acme/app/pulls",
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %+v, want %d", calls, len(want))
	}
	for i, call := range calls {
		if got := call.Method + " " + call.Path; got != want[i] {
			t.Fatalf("call %d = %s, want %s", i, got, want[i])
		}
	}

	// The manifest is edited through the contents API, on the new branch, and
	// the commit message names the bump.
	var put struct {
		Message string `json:"message"`
		Content string `json:"content"`
		Branch  string `json:"branch"`
		SHA     string `json:"sha"`
	}
	if err := json.Unmarshal(calls[5].Body, &put); err != nil {
		t.Fatalf("decode PUT body: %v", err)
	}
	if put.Branch != "bastion/bump-lodash-4.17.21" || put.SHA != "file-sha" {
		t.Errorf("PUT body = %+v", put)
	}
	if put.Message != "fix(deps): bump lodash to 4.17.21" {
		t.Errorf("commit message = %q", put.Message)
	}
	manifest, err := base64.StdEncoding.DecodeString(put.Content)
	if err != nil {
		t.Fatalf("decode content: %v", err)
	}
	if !strings.Contains(string(manifest), `"lodash": "^4.17.21"`) {
		t.Fatalf("manifest = %s, want the caret range kept", manifest)
	}

	var pr struct {
		Title string `json:"title"`
		Head  string `json:"head"`
		Base  string `json:"base"`
		Body  string `json:"body"`
	}
	if err := json.Unmarshal(calls[6].Body, &pr); err != nil {
		t.Fatalf("decode pull request body: %v", err)
	}
	if pr.Base != "main" || pr.Head != "bastion/bump-lodash-4.17.21" {
		t.Errorf("pull request = %+v", pr)
	}
	pullRequest := fixPlanPullRequest(t, ts, cookie, asset.Id)
	if pullRequest == nil || pullRequest.Number != 12 || pullRequest.State != gen.FixPlanPullRequestStateOpen {
		t.Fatalf("plan pull_request = %+v, want #12 open recorded by the create", pullRequest)
	}

	for _, want := range []string{
		"Bumps `lodash` to `4.17.21`.",
		"- `CVE-2021-1111` (critical)",
		"- `CVE-2021-2222` (high)",
		"Only the manifest was changed. Regenerate the lockfile (go mod tidy / npm install) before merging.",
		"Opened by bastion after you confirmed it.",
	} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("pull request body misses %q:\n%s", want, pr.Body)
		}
	}
}

func TestOpenFixPlanPullRequestNeedsConfirmation(t *testing.T) {
	api, server := newFakeGitHubAPI(t)
	ts := newPullRequestServer(t, server.URL)
	cookie := ts.login(t)
	asset := addRepoAsset(t, ts, cookie)
	seedReportScan(t, ts.db, asset.Id, "succeeded", reportAt(10),
		npmFinding(asset.Id, "CVE-2021-1111", "lodash", "4.17.0", "4.17.21", findings.SeverityHigh))

	resp := doJSON(t, ts, http.MethodPost, "/api/assets/"+itoa(asset.Id)+"/fix-plan/pull-request", map[string]any{
		"ecosystem": "npm",
		"package":   "lodash",
		"target":    "4.17.21",
		"confirm":   false,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", resp.StatusCode, readBody(t, resp))
	}
	if calls := api.recorded(); len(calls) != 0 {
		t.Fatalf("GitHub was called without confirmation: %+v", calls)
	}
}

func TestOpenFixPlanPullRequestStepNotInPlan(t *testing.T) {
	api, server := newFakeGitHubAPI(t)
	ts := newPullRequestServer(t, server.URL)
	cookie := ts.login(t)
	asset := addRepoAsset(t, ts, cookie)
	seedReportScan(t, ts.db, asset.Id, "succeeded", reportAt(10),
		npmFinding(asset.Id, "CVE-2021-1111", "lodash", "4.17.0", "4.17.21", findings.SeverityHigh))

	resp := doJSON(t, ts, http.MethodPost, "/api/assets/"+itoa(asset.Id)+"/fix-plan/pull-request", map[string]any{
		"ecosystem": "npm",
		"package":   "lodash",
		"target":    "9.9.9",
		"confirm":   true,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", resp.StatusCode, readBody(t, resp))
	}
	if calls := api.recorded(); len(calls) != 0 {
		t.Fatalf("GitHub was called for a step outside the plan: %+v", calls)
	}
}

func TestOpenFixPlanPullRequestTransitive(t *testing.T) {
	api, server := newFakeGitHubAPI(t)
	ts := newPullRequestServer(t, server.URL)
	cookie := ts.login(t)
	// The step exists (Trivy saw left-pad in package-lock.json) but the
	// manifest has no such dependency: it is transitive.
	asset := addRepoAsset(t, ts, cookie)
	seedReportScan(t, ts.db, asset.Id, "succeeded", reportAt(10),
		npmFinding(asset.Id, "CVE-2021-3333", "left-pad", "1.2.0", "1.3.0", findings.SeverityHigh))

	resp := doJSON(t, ts, http.MethodPost, "/api/assets/"+itoa(asset.Id)+"/fix-plan/pull-request", map[string]any{
		"ecosystem": "npm",
		"package":   "left-pad",
		"target":    "1.3.0",
		"confirm":   true,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", resp.StatusCode, readBody(t, resp))
	}
	problem := readProblem(t, resp)
	if problem.Detail == nil || !strings.Contains(*problem.Detail, "transitive dependency; bump its parent") {
		t.Fatalf("detail = %v, want the transitive message", problem.Detail)
	}

	// The manifest was read, but no branch, commit or pull request was made.
	for _, call := range api.recorded() {
		if call.Method != http.MethodGet {
			t.Fatalf("a write reached GitHub for a transitive dependency: %+v", call)
		}
	}
}

func TestOpenFixPlanPullRequestBranchExists(t *testing.T) {
	api, server := newFakeGitHubAPI(t)
	api.refExists = true
	api.existingPRURL = "https://github.com/acme/app/pull/7"
	ts := newPullRequestServer(t, server.URL)
	cookie := ts.login(t)
	asset := addRepoAsset(t, ts, cookie)
	seedReportScan(t, ts.db, asset.Id, "succeeded", reportAt(10),
		npmFinding(asset.Id, "CVE-2021-1111", "lodash", "4.17.0", "4.17.21", findings.SeverityHigh))

	resp := doJSON(t, ts, http.MethodPost, "/api/assets/"+itoa(asset.Id)+"/fix-plan/pull-request", map[string]any{
		"ecosystem": "npm",
		"package":   "lodash",
		"target":    "4.17.21",
		"confirm":   true,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", resp.StatusCode, readBody(t, resp))
	}
	problem := readProblem(t, resp)
	if problem.PrUrl == nil || *problem.PrUrl != "https://github.com/acme/app/pull/7" {
		t.Fatalf("pr_url = %v, want the existing pull request", problem.PrUrl)
	}

	pullRequest := fixPlanPullRequest(t, ts, cookie, asset.Id)
	if pullRequest == nil || pullRequest.Number != 7 {
		t.Fatalf("plan pull_request = %+v, want the existing #7 recorded", pullRequest)
	}
}

// TestOpenFixPlanPullRequestRejectsInjectedTarget proves a target that could
// break the manifest (a newline in go.mod, a JSON member in package.json) is
// refused before GitHub is contacted.
func TestOpenFixPlanPullRequestRejectsInjectedTarget(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		target    string
	}{
		{
			name:      "go newline and require",
			ecosystem: "go",
			target:    "v1.0.1\n\nrequire evil.example/x v1.0.0",
		},
		{
			name:      "npm json member",
			ecosystem: "npm",
			target:    `4.17.21", "evil": "1.0.0`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, server := newFakeGitHubAPI(t)
			ts := newPullRequestServer(t, server.URL)
			cookie := ts.login(t)
			asset := addRepoAsset(t, ts, cookie)
			seedReportScan(t, ts.db, asset.Id, "succeeded", reportAt(10),
				npmFinding(asset.Id, "CVE-2021-1111", "lodash", "4.17.0", "4.17.21", findings.SeverityHigh))

			resp := doJSON(t, ts, http.MethodPost, "/api/assets/"+itoa(asset.Id)+"/fix-plan/pull-request", map[string]any{
				"ecosystem": tt.ecosystem,
				"package":   "lodash",
				"target":    tt.target,
				"confirm":   true,
			}, withBastion(cookie))
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body = %s", resp.StatusCode, readBody(t, resp))
			}
			if calls := api.recorded(); len(calls) != 0 {
				t.Fatalf("GitHub was called for an injected target: %+v", calls)
			}
		})
	}
}

// TestOpenFixPlanPullRequestCleansUpAfterFailure proves a failed contents write
// deletes the branch it created, so pressing Open PR again can succeed.
func TestOpenFixPlanPullRequestCleansUpAfterFailure(t *testing.T) {
	api, server := newFakeGitHubAPI(t)
	api.failPut = true
	ts := newPullRequestServer(t, server.URL)
	cookie := ts.login(t)
	asset := addRepoAsset(t, ts, cookie)
	seedReportScan(t, ts.db, asset.Id, "succeeded", reportAt(10),
		npmFinding(asset.Id, "CVE-2021-1111", "lodash", "4.17.0", "4.17.21", findings.SeverityHigh))

	body := map[string]any{
		"ecosystem": "npm",
		"package":   "lodash",
		"target":    "4.17.21",
		"confirm":   true,
	}
	resp := doJSON(t, ts, http.MethodPost, "/api/assets/"+itoa(asset.Id)+"/fix-plan/pull-request", body, withBastion(cookie))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body = %s", resp.StatusCode, readBody(t, resp))
	}
	deleted := false
	for _, call := range api.recorded() {
		if call.Method == http.MethodDelete && call.Path == "/repos/acme/app/git/refs/heads/bastion/bump-lodash-4.17.21" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("the branch was not deleted after the failed write: %+v", api.recorded())
	}

	// The retry finds no branch and succeeds.
	api.mu.Lock()
	api.failPut = false
	api.mu.Unlock()
	resp = doJSON(t, ts, http.MethodPost, "/api/assets/"+itoa(asset.Id)+"/fix-plan/pull-request", body, withBastion(cookie))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("retry status = %d, want 201; body = %s", resp.StatusCode, readBody(t, resp))
	}
}

// fixPlanPullRequest reads the asset's fix plan and returns the first step's
// recorded pull request.
func fixPlanPullRequest(t *testing.T, ts *testServer, cookie *http.Cookie, assetID int64) *gen.FixPlanPullRequest {
	t.Helper()

	resp := ts.do(t, http.MethodGet, "/api/assets/"+itoa(assetID)+"/fix-plan", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fix plan status = %d, body = %s", resp.StatusCode, readBody(t, resp))
	}
	var plan gen.FixPlan
	if err := json.Unmarshal(readBody(t, resp), &plan); err != nil {
		t.Fatalf("decode fix plan: %v", err)
	}
	if len(plan.Steps) == 0 {
		t.Fatalf("fix plan has no steps: %+v", plan)
	}
	return plan.Steps[0].PullRequest
}

// recordPullRequest opens the pull request once, so the follow-up reads have a
// recorded step to refresh.
func recordPullRequest(t *testing.T, ts *testServer, cookie *http.Cookie, assetID int64) {
	t.Helper()

	resp := doJSON(t, ts, http.MethodPost, "/api/assets/"+itoa(assetID)+"/fix-plan/pull-request", map[string]any{
		"ecosystem": "npm",
		"package":   "lodash",
		"target":    "4.17.21",
		"confirm":   true,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("open pull request: status = %d, body = %s", resp.StatusCode, readBody(t, resp))
	}
}

// TestFixPlanClosedPullRequestForgetsIt proves a pull request closed without
// merging is deleted, so the step offers the action again.
func TestFixPlanClosedPullRequestForgetsIt(t *testing.T) {
	api, server := newFakeGitHubAPI(t)
	ts := newPullRequestServer(t, server.URL)
	cookie := ts.login(t)
	asset := addRepoAsset(t, ts, cookie)
	seedReportScan(t, ts.db, asset.Id, "succeeded", reportAt(10),
		npmFinding(asset.Id, "CVE-2021-1111", "lodash", "4.17.0", "4.17.21", findings.SeverityHigh))
	recordPullRequest(t, ts, cookie, asset.Id)

	api.mu.Lock()
	api.prState = "closed"
	api.mu.Unlock()

	if pullRequest := fixPlanPullRequest(t, ts, cookie, asset.Id); pullRequest != nil {
		t.Fatalf("plan pull_request = %+v, want none after a close without merge", pullRequest)
	}
}

// TestFixPlanMergedPullRequest keeps the record and reports the merged state.
func TestFixPlanMergedPullRequest(t *testing.T) {
	api, server := newFakeGitHubAPI(t)
	ts := newPullRequestServer(t, server.URL)
	cookie := ts.login(t)
	asset := addRepoAsset(t, ts, cookie)
	seedReportScan(t, ts.db, asset.Id, "succeeded", reportAt(10),
		npmFinding(asset.Id, "CVE-2021-1111", "lodash", "4.17.0", "4.17.21", findings.SeverityHigh))
	recordPullRequest(t, ts, cookie, asset.Id)

	api.mu.Lock()
	api.prState = "closed"
	api.prMerged = true
	api.mu.Unlock()

	pullRequest := fixPlanPullRequest(t, ts, cookie, asset.Id)
	if pullRequest == nil || pullRequest.State != gen.FixPlanPullRequestStateMerged {
		t.Fatalf("plan pull_request = %+v, want merged", pullRequest)
	}
}

// TestFixPlanPullRequestGitHubError keeps the last known state, so a GitHub
// outage never hides the recorded pull request or fails the plan read.
func TestFixPlanPullRequestGitHubError(t *testing.T) {
	api, server := newFakeGitHubAPI(t)
	ts := newPullRequestServer(t, server.URL)
	cookie := ts.login(t)
	asset := addRepoAsset(t, ts, cookie)
	seedReportScan(t, ts.db, asset.Id, "succeeded", reportAt(10),
		npmFinding(asset.Id, "CVE-2021-1111", "lodash", "4.17.0", "4.17.21", findings.SeverityHigh))
	recordPullRequest(t, ts, cookie, asset.Id)

	api.mu.Lock()
	api.prGetErr = true
	api.mu.Unlock()

	pullRequest := fixPlanPullRequest(t, ts, cookie, asset.Id)
	if pullRequest == nil || pullRequest.State != gen.FixPlanPullRequestStateOpen {
		t.Fatalf("plan pull_request = %+v, want #12 kept open", pullRequest)
	}
}
