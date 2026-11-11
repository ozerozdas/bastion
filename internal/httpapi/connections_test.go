package httpapi

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/connections"
	"github.com/ozerozdas/bastion/internal/connections/github"
	"github.com/ozerozdas/bastion/internal/httpapi/gen"
	"github.com/ozerozdas/bastion/internal/secrets"
)

// doJSON sends a JSON request. A nil body sends no body.
func doJSON(t *testing.T, ts *testServer, method, path string, body any, mutate func(*http.Request)) *http.Response {
	t.Helper()

	var reader io.Reader = http.NoBody
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode request body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(t.Context(), method, ts.url+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if mutate != nil {
		mutate(req)
	}

	resp, err := ts.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// withBastion authenticates a mutating request (cookie + CSRF header).
func withBastion(cookie *http.Cookie) func(*http.Request) {
	return func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(csrfHeaderName, csrfHeaderVal)
	}
}

// readBody consumes and returns a response body.
func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

// decodeConnection decodes a Connection response.
func decodeConnection(t *testing.T, body []byte) gen.Connection {
	t.Helper()
	var conn gen.Connection
	if err := json.Unmarshal(body, &conn); err != nil {
		t.Fatalf("decode connection %q: %v", body, err)
	}
	return conn
}

// decodeConnectionList decodes a ConnectionList response.
func decodeConnectionList(t *testing.T, body []byte) gen.ConnectionList {
	t.Helper()
	var list gen.ConnectionList
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode connection list %q: %v", body, err)
	}
	return list
}

func stringPtr(value string) *string { return &value }

// TestConnectionLifecycle is the happy path: create (which tests), list, test,
// delete. It also proves the token is absent from every response body, every
// captured log line and every text column of the database.
func TestConnectionLifecycle(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	const token = "ghp_bst020_lifecycle_secret" //nolint:gosec // G101: test fixture, not a credential

	var bodies [][]byte

	create := doJSON(t, ts, http.MethodPost, "/api/connections", gen.CreateConnectionRequest{
		Kind:  gen.CreateConnectionRequestKindGithub,
		Name:  "work",
		Token: stringPtr(token),
	}, withBastion(cookie))
	if create.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want %d", create.StatusCode, http.StatusCreated)
	}
	createdBody := readBody(t, create)
	bodies = append(bodies, createdBody)
	created := decodeConnection(t, createdBody)
	if created.Id < 1 {
		t.Fatalf("created.id = %d, want positive", created.Id)
	}
	if created.Kind != gen.ConnectionKind(connections.KindGitHub) {
		t.Errorf("created.kind = %q, want %q", created.Kind, connections.KindGitHub)
	}
	if created.Status != gen.ConnectionStatus(connections.StatusOK) {
		t.Errorf("created.status = %q, want %q", created.Status, connections.StatusOK)
	}
	if created.Login == nil || *created.Login != "octocat" {
		t.Errorf("created.login = %v, want octocat", created.Login)
	}
	if created.LastCheckedAt == nil {
		t.Error("created.last_checked_at is nil after a test")
	}
	if created.CreatedAt.IsZero() {
		t.Error("created.created_at is zero")
	}

	// The token is in the keyring under the row-derived key, and nowhere in
	// the database or the response.
	stored, err := ts.secretStore.Get(connections.SecretRef(created.Id))
	if err != nil {
		t.Fatalf("secret under %s: %v", connections.SecretRef(created.Id), err)
	}
	if stored != token {
		t.Fatalf("stored secret = %q, want the created token", stored)
	}
	if strings.Contains(string(createdBody), token) {
		t.Error("create response contains the token")
	}
	assertNotInDatabase(t, ts.db, token)

	// A duplicate (kind, name) is a conflict, not a second row.
	duplicate := doJSON(t, ts, http.MethodPost, "/api/connections", gen.CreateConnectionRequest{
		Kind:  gen.CreateConnectionRequestKindGithub,
		Name:  "work",
		Token: stringPtr("ghp_another_token"),
	}, withBastion(cookie))
	if duplicate.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want %d", duplicate.StatusCode, http.StatusConflict)
	}
	readProblem(t, duplicate)

	// List exposes the identity, never the credential.
	list := ts.do(t, http.MethodGet, "/api/connections", withCookie(cookie))
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want %d", list.StatusCode, http.StatusOK)
	}
	listBody := readBody(t, list)
	bodies = append(bodies, listBody)
	listValue := decodeConnectionList(t, listBody)
	if len(listValue.Connections) != 1 {
		t.Fatalf("list has %d connections, want 1", len(listValue.Connections))
	}
	if listValue.Connections[0].Id != created.Id {
		t.Errorf("list id = %d, want %d", listValue.Connections[0].Id, created.Id)
	}
	if strings.Contains(string(listBody), token) {
		t.Error("list response contains the token")
	}

	// Test again: same result, status and login refreshed.
	test := doJSON(t, ts, http.MethodPost,
		fmt.Sprintf("/api/connections/%d/test", created.Id), nil, withBastion(cookie))
	if test.StatusCode != http.StatusOK {
		t.Fatalf("test status = %d, want %d", test.StatusCode, http.StatusOK)
	}
	testBody := readBody(t, test)
	bodies = append(bodies, testBody)
	tested := decodeConnection(t, testBody)
	if tested.Status != gen.ConnectionStatus(connections.StatusOK) {
		t.Errorf("tested.status = %q, want %q", tested.Status, connections.StatusOK)
	}
	if tested.Hint != nil {
		t.Errorf("tested.hint = %q, want nil after success", *tested.Hint)
	}

	// Delete removes the keyring entry and the row.
	del := doJSON(t, ts, http.MethodDelete,
		fmt.Sprintf("/api/connections/%d", created.Id), nil, withBastion(cookie))
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d", del.StatusCode, http.StatusNoContent)
	}
	if body := readBody(t, del); len(body) != 0 {
		t.Errorf("delete body = %q, want empty", body)
	}
	if _, err := ts.secretStore.Get(connections.SecretRef(created.Id)); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("secret after delete = %v, want ErrNotFound", err)
	}
	if _, err := ts.connections.Get(t.Context(), created.Id); !errors.Is(err, connections.ErrNotFound) {
		t.Errorf("connection after delete = %v, want ErrNotFound", err)
	}

	again := doJSON(t, ts, http.MethodDelete,
		fmt.Sprintf("/api/connections/%d", created.Id), nil, withBastion(cookie))
	if again.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete status = %d, want %d", again.StatusCode, http.StatusNotFound)
	}
	readProblem(t, again)

	for i, body := range bodies {
		if strings.Contains(string(body), token) {
			t.Errorf("response body %d contains the token", i)
		}
	}
	if logs := ts.logs.String(); strings.Contains(logs, token) {
		t.Errorf("captured logs contain the token:\n%s", logs)
	}
}

// TestConnectionTestRecordsGitHubFailure: a 401 is a connection status, not an
// API error. The hint is the ADR-005 explanation.
func TestConnectionTestRecordsGitHubFailure(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	create := doJSON(t, ts, http.MethodPost, "/api/connections", gen.CreateConnectionRequest{
		Kind:  gen.CreateConnectionRequestKindGithub,
		Name:  "expiring",
		Token: stringPtr("ghp_will_expire"),
	}, withBastion(cookie))
	if create.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want %d", create.StatusCode, http.StatusCreated)
	}
	created := decodeConnection(t, readBody(t, create))

	ts.github.setUserErr(&github.Error{Op: "get user", StatusCode: http.StatusUnauthorized, Hint: "token invalid or expired"})

	resp := doJSON(t, ts, http.MethodPost,
		fmt.Sprintf("/api/connections/%d/test", created.Id), nil, withBastion(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test status = %d, want %d (a failed test is not an API error)", resp.StatusCode, http.StatusOK)
	}
	tested := decodeConnection(t, readBody(t, resp))
	if tested.Status != gen.ConnectionStatus(connections.StatusError) {
		t.Errorf("tested.status = %q, want %q", tested.Status, connections.StatusError)
	}
	if tested.Hint == nil || *tested.Hint != "token invalid or expired" {
		t.Errorf("tested.hint = %v, want %q", tested.Hint, "token invalid or expired")
	}
	if tested.LastCheckedAt == nil {
		t.Error("tested.last_checked_at is nil after a test")
	}

	// The status survives a reload from SQLite, not just the response.
	list := decodeConnectionList(t, readBody(t, ts.do(t, http.MethodGet, "/api/connections", withCookie(cookie))))
	if len(list.Connections) != 1 {
		t.Fatalf("list has %d connections, want 1", len(list.Connections))
	}
	if list.Connections[0].Status != gen.ConnectionStatus(connections.StatusError) {
		t.Errorf("listed status = %q, want %q", list.Connections[0].Status, connections.StatusError)
	}
	if list.Connections[0].Hint == nil || *list.Connections[0].Hint != "token invalid or expired" {
		t.Errorf("listed hint = %v, want %q", list.Connections[0].Hint, "token invalid or expired")
	}
}

// TestConnectionCreateWithBadToken: create still succeeds (the row is useful
// for editing later) and records the failure.
func TestConnectionCreateWithBadToken(t *testing.T) {
	fake := newFakeGitHub()
	fake.setUserErr(&github.Error{Op: "get user", StatusCode: http.StatusUnauthorized, Hint: "token invalid or expired"})
	ts := newTestServerWithGitHub(t, fake)
	cookie := ts.login(t)

	resp := doJSON(t, ts, http.MethodPost, "/api/connections", gen.CreateConnectionRequest{
		Kind:  gen.CreateConnectionRequestKindGithub,
		Name:  "typo",
		Token: stringPtr("ghp_typo"),
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	created := decodeConnection(t, readBody(t, resp))
	if created.Status != gen.ConnectionStatus(connections.StatusError) {
		t.Errorf("created.status = %q, want %q", created.Status, connections.StatusError)
	}
	if created.Hint == nil || *created.Hint != "token invalid or expired" {
		t.Errorf("created.hint = %v, want %q", created.Hint, "token invalid or expired")
	}

	// Correcting the token on the same connection clears the hint.
	fake.setUserErr(nil)
	tested := decodeConnection(t, readBody(t, doJSON(t, ts, http.MethodPost,
		fmt.Sprintf("/api/connections/%d/test", created.Id), nil, withBastion(cookie))))
	if tested.Status != gen.ConnectionStatus(connections.StatusOK) {
		t.Errorf("tested.status = %q, want %q", tested.Status, connections.StatusOK)
	}
	if tested.Hint != nil {
		t.Errorf("tested.hint = %q, want nil after recovery", *tested.Hint)
	}
}

// TestConnectionDiscoverMarksAlreadyAdded: a repo that exists as an asset is
// flagged, everything else is offered.
func TestConnectionDiscoverMarksAlreadyAdded(t *testing.T) {
	fake := newFakeGitHub()
	fake.setRepos([]github.Repo{
		{FullName: "octo/hello", DefaultBranch: "main", Private: true},
		{FullName: "octo/new", DefaultBranch: "trunk"},
		{FullName: "octo/old", DefaultBranch: "master", Archived: true},
	}, nil)
	ts := newTestServerWithGitHub(t, fake)
	cookie := ts.login(t)

	create := doJSON(t, ts, http.MethodPost, "/api/connections", gen.CreateConnectionRequest{
		Kind:  gen.CreateConnectionRequestKindGithub,
		Name:  "discover",
		Token: stringPtr("ghp_discover"),
	}, withBastion(cookie))
	if create.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want %d", create.StatusCode, http.StatusCreated)
	}
	created := decodeConnection(t, readBody(t, create))

	if _, err := ts.db.ExecContext(t.Context(), `
		INSERT INTO assets (kind, connection_id, display_name, ref, default_branch)
		VALUES ('repo', ?, 'hello', 'octo/hello', 'main')`, created.Id); err != nil {
		t.Fatalf("insert asset: %v", err)
	}

	resp := ts.do(t, http.MethodGet,
		fmt.Sprintf("/api/connections/%d/discover", created.Id), withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discover status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var discovered gen.DiscoverReposResponse
	if err := json.Unmarshal(readBody(t, resp), &discovered); err != nil {
		t.Fatalf("decode discover: %v", err)
	}
	if len(discovered.Repos) != 3 {
		t.Fatalf("discovered %d repos, want 3", len(discovered.Repos))
	}

	byName := make(map[string]gen.DiscoveredRepo, len(discovered.Repos))
	for _, repo := range discovered.Repos {
		byName[repo.FullName] = repo
	}
	if repo := byName["octo/hello"]; !repo.AlreadyAdded {
		t.Error("octo/hello.already_added = false, want true (asset exists)")
	}
	if repo := byName["octo/hello"]; !repo.Private || repo.DefaultBranch != "main" {
		t.Errorf("octo/hello metadata = private %v, branch %q", repo.Private, repo.DefaultBranch)
	}
	if repo := byName["octo/new"]; repo.AlreadyAdded {
		t.Error("octo/new.already_added = true, want false")
	}
	if repo := byName["octo/old"]; !repo.Archived {
		t.Error("octo/old.archived = false, want true")
	}
}

// TestConnectionDiscoverGitHubFailure: an upstream failure is a problem+json
// 502 carrying the hint, not a bare 500.
func TestConnectionDiscoverGitHubFailure(t *testing.T) {
	fake := newFakeGitHub()
	fake.setRepos(nil, &github.Error{Op: "list repos", StatusCode: http.StatusForbidden,
		Hint: "rate limited until 2026-11-11T13:00:00Z"})
	ts := newTestServerWithGitHub(t, fake)
	cookie := ts.login(t)

	created := decodeConnection(t, readBody(t, doJSON(t, ts, http.MethodPost, "/api/connections",
		gen.CreateConnectionRequest{
			Kind:  gen.CreateConnectionRequestKindGithub,
			Name:  "limited",
			Token: stringPtr("ghp_limited"),
		}, withBastion(cookie))))

	resp := ts.do(t, http.MethodGet,
		fmt.Sprintf("/api/connections/%d/discover", created.Id), withCookie(cookie))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("discover status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	problem := readProblem(t, resp)
	if problem.Detail == nil || !strings.Contains(*problem.Detail, "rate limited") {
		t.Errorf("problem.detail = %v, want the rate-limit hint", problem.Detail)
	}
}

// TestConnectionsRequireCSRFHeader: the existing middleware rejects mutating
// connection requests without X-Bastion, before any handler runs.
func TestConnectionsRequireCSRFHeader(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	post := doJSON(t, ts, http.MethodPost, "/api/connections", gen.CreateConnectionRequest{
		Kind:  gen.CreateConnectionRequestKindGithub,
		Name:  "csrf",
		Token: stringPtr("ghp_csrf"),
	}, withCookie(cookie))
	if post.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without X-Bastion: status = %d, want %d", post.StatusCode, http.StatusForbidden)
	}
	readProblem(t, post)

	// Nothing was created.
	list := decodeConnectionList(t, readBody(t, ts.do(t, http.MethodGet, "/api/connections", withCookie(cookie))))
	if len(list.Connections) != 0 {
		t.Fatalf("blocked POST created %d connections, want 0", len(list.Connections))
	}

	created := decodeConnection(t, readBody(t, doJSON(t, ts, http.MethodPost, "/api/connections",
		gen.CreateConnectionRequest{
			Kind:  gen.CreateConnectionRequestKindGithub,
			Name:  "csrf",
			Token: stringPtr("ghp_csrf"),
		}, withBastion(cookie))))

	del := doJSON(t, ts, http.MethodDelete,
		fmt.Sprintf("/api/connections/%d", created.Id), nil, withCookie(cookie))
	if del.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE without X-Bastion: status = %d, want %d", del.StatusCode, http.StatusForbidden)
	}
	readProblem(t, del)

	if _, err := ts.connections.Get(t.Context(), created.Id); err != nil {
		t.Errorf("blocked DELETE removed the connection: %v", err)
	}
}

// assertNotInDatabase fails when needle appears in any text column of any
// table. Columns are discovered from the schema, so a future migration cannot
// silently escape the check.
func assertNotInDatabase(t *testing.T, db *sql.DB, needle string) {
	t.Helper()

	tables, err := db.QueryContext(t.Context(),
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer func() { _ = tables.Close() }()

	var names []string
	for tables.Next() {
		var name string
		if err := tables.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		names = append(names, name)
	}
	if err := tables.Err(); err != nil {
		t.Fatalf("list tables: %v", err)
	}

	for _, table := range names {
		quoted := quoteIdentifier(table)
		columns, err := db.QueryContext(t.Context(), "PRAGMA table_info("+quoted+")")
		if err != nil {
			t.Fatalf("table_info(%s): %v", table, err)
		}
		for columns.Next() {
			var (
				cid       int
				name      string
				columnTyp string
				notNull   int
				defaultV  sql.NullString
				pk        int
			)
			if err := columns.Scan(&cid, &name, &columnTyp, &notNull, &defaultV, &pk); err != nil {
				_ = columns.Close()
				t.Fatalf("scan table_info(%s): %v", table, err)
			}
			if !isTextColumn(columnTyp) {
				continue
			}
			rows, err := db.QueryContext(t.Context(),
				"SELECT "+quoteIdentifier(name)+" FROM "+quoted) //nolint:gosec // G202: identifiers come from sqlite_master and are quoted; no values are interpolated
			if err != nil {
				_ = columns.Close()
				t.Fatalf("select %s.%s: %v", table, name, err)
			}
			for rows.Next() {
				var value sql.NullString
				if err := rows.Scan(&value); err != nil {
					_ = rows.Close()
					_ = columns.Close()
					t.Fatalf("scan %s.%s: %v", table, name, err)
				}
				if value.Valid && strings.Contains(value.String, needle) {
					t.Errorf("token found in %s.%s", table, name)
				}
			}
			if err := rows.Err(); err != nil {
				_ = rows.Close()
				_ = columns.Close()
				t.Fatalf("select %s.%s: %v", table, name, err)
			}
			_ = rows.Close()
		}
		if err := columns.Err(); err != nil {
			_ = columns.Close()
			t.Fatalf("table_info(%s): %v", table, err)
		}
		_ = columns.Close()
	}
}

func isTextColumn(declared string) bool {
	upper := strings.ToUpper(declared)
	return strings.Contains(upper, "TEXT") ||
		strings.Contains(upper, "CHAR") ||
		strings.Contains(upper, "CLOB")
}

func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
