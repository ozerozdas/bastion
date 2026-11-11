// Package github is bastion's client for the five GitHub REST endpoints it
// uses (ADR-005): the authenticated user, the repository list used for
// discovery, one repository's metadata, a ref resolved to a commit SHA, and
// the source tarball for that SHA.
//
// Calls happen only on user action and carry the connection's token.
// Request URLs are never logged and never appear in errors: codeload redirect
// URLs can carry a short-lived token= query, so error text and log lines name
// the operation and the repository ("get repo owner/name") instead.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// DefaultBaseURL is the GitHub REST API root. GitHub Enterprise is out of
	// scope for v0.1 (ADR-005); tests inject their own base URL.
	DefaultBaseURL = "https://api.github.com"

	// DefaultMaxTarballBytes is the compressed tarball budget (ADR-005).
	DefaultMaxTarballBytes = 512 << 20

	apiVersion = "2022-11-28"
	acceptJSON = "application/vnd.github+json"
	// acceptSHA makes the commits endpoint answer with the bare commit SHA.
	acceptSHA = "application/vnd.github.sha"

	// repoPageSize is the per_page value for ListRepos.
	repoPageSize = 100
	// maxRepoPages caps ListRepos' Link pagination (50 pages, 5 000
	// repositories). Reaching it fails the call instead of silently returning
	// a truncated list.
	maxRepoPages = 50
	// maxJSONBytes bounds an API response body. A page of 100 repositories is
	// well under a megabyte.
	maxJSONBytes = 8 << 20
	// maxSHABytes bounds the body of a SHA resolution; a SHA is 40 bytes.
	maxSHABytes = 128
)

// Config configures a Client. Only Token is required.
type Config struct {
	// Token is a classic or fine-grained PAT with read-only access. It is
	// sent as a bearer token and never logged.
	Token string
	// BaseURL overrides the API root. Empty means DefaultBaseURL; tests point
	// it at an httptest server.
	BaseURL string
	// HTTPClient performs the requests. Nil means a client without an overall
	// timeout: each call is bounded by its context, and tarballs can be large.
	HTTPClient *http.Client
	// Version is reported in the User-Agent as "bastion/<Version>". Empty
	// means "dev".
	Version string
	// MaxTarballBytes caps the compressed tarball returned by Tarball. Zero
	// means DefaultMaxTarballBytes.
	MaxTarballBytes int64
	// Logger receives debug request logs (operation and status only, never a
	// URL). Nil means slog.Default().
	Logger *slog.Logger
}

// Client calls the GitHub REST API. It is safe for concurrent use.
type Client struct {
	base       *url.URL
	http       *http.Client
	token      string
	userAgent  string
	maxTarball int64
	log        *slog.Logger
}

// New validates cfg and returns a client.
func New(cfg Config) (*Client, error) {
	if cfg.Token == "" {
		return nil, errors.New("github: token is required")
	}

	base := cfg.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("github: parse base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("github: base URL scheme %q is not http or https", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("github: base URL has no host")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("github: base URL must not carry a query or fragment")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	version := strings.TrimSpace(cfg.Version)
	if version == "" {
		version = "dev"
	}

	maxTarball := cfg.MaxTarballBytes
	if maxTarball <= 0 {
		maxTarball = DefaultMaxTarballBytes
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Client{
		base:       u,
		http:       httpClient,
		token:      cfg.Token,
		userAgent:  "bastion/" + version,
		maxTarball: maxTarball,
		log:        logger,
	}, nil
}

// User returns the account the token belongs to (GET /user). It doubles as the
// connection test: a 401 means the token is invalid or expired.
func (c *Client) User(ctx context.Context) (User, error) {
	const op = "get user"

	var user User
	if _, err := c.get(ctx, op, c.apiURL("user"), acceptJSON, &user); err != nil {
		return User{}, err
	}
	return user, nil
}

// ListRepos lists the repositories the token can see, most recently pushed
// first (GET /user/repos?per_page=100&sort=pushed), following GitHub's
// rel="next" Link header.
//
// Pagination stops after maxRepoPages (50) pages. A connection with more
// repositories than that returns an error rather than a silently truncated
// list.
func (c *Client) ListRepos(ctx context.Context) ([]Repo, error) {
	const op = "list repos"

	u := c.apiURL("user", "repos")
	q := u.Query()
	q.Set("per_page", strconv.Itoa(repoPageSize))
	q.Set("sort", "pushed")
	u.RawQuery = q.Encode()

	var repos []Repo
	for page := 1; ; page++ {
		var batch []Repo
		header, err := c.get(ctx, op, u, acceptJSON, &batch)
		if err != nil {
			return nil, err
		}
		repos = append(repos, batch...)

		next, err := c.nextPageURL(op, header.Get("Link"))
		if err != nil {
			return nil, err
		}
		if next == nil {
			return repos, nil
		}
		if page >= maxRepoPages {
			return nil, &Error{
				Op:   op,
				Hint: fmt.Sprintf("stopped after %d pages (%d repositories)", maxRepoPages, maxRepoPages*repoPageSize),
			}
		}
		u = next
	}
}

// Repo returns one repository (GET /repos/{owner}/{repo}).
func (c *Client) Repo(ctx context.Context, owner, name string) (Repo, error) {
	op, err := repoOp("get repo", owner, name)
	if err != nil {
		return Repo{}, err
	}

	var repo Repo
	if _, err := c.get(ctx, op, c.apiURL("repos", owner, name), acceptJSON, &repo); err != nil {
		return Repo{}, err
	}
	return repo, nil
}

// ResolveSHA resolves a branch, tag or ref to the commit SHA GitHub records
// for it (GET /repos/{owner}/{repo}/commits/{ref} with Accept:
// application/vnd.github.sha). The answer must be 40 hex characters and is
// returned lower-case, ready to pass to Tarball.
//
// A ref may contain slashes ("release/2.x"); every segment is validated, so a
// ref cannot escape the commits endpoint.
func (c *Client) ResolveSHA(ctx context.Context, owner, name, ref string) (string, error) {
	op, err := repoOp("resolve sha", owner, name)
	if err != nil {
		return "", err
	}
	op += "@" + ref

	segments, err := refSegments(ref)
	if err != nil {
		return "", err
	}
	u := c.apiURL(append([]string{"repos", owner, name, "commits"}, segments...)...)

	req, err := c.request(ctx, op, u, acceptSHA)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", c.transportError(op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	c.log.Debug("github request", "op", op, "status", resp.StatusCode)

	if err := checkStatus(op, resp); err != nil {
		return "", err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSHABytes))
	if err != nil {
		return "", &Error{Op: op, Hint: "could not read the response", Err: err}
	}
	sha := strings.TrimSpace(string(body))
	if !isSHA(sha) {
		return "", &Error{Op: op, Hint: "GitHub did not return a commit SHA"}
	}
	return strings.ToLower(sha), nil
}

// Tarball downloads the source archive of a commit (GET
// /repos/{owner}/{repo}/tarball/{sha}) and returns the compressed stream,
// which the caller must Close.
//
// GitHub answers 302 to codeload.github.com. net/http drops Authorization on a
// redirect to another host, and the redirect URL's token= query is never
// logged. Reads are capped at MaxTarballBytes: reading past the cap returns an
// error instead of a shortened archive.
func (c *Client) Tarball(ctx context.Context, owner, name, sha string) (io.ReadCloser, error) {
	op, err := repoOp("download tarball", owner, name)
	if err != nil {
		return nil, err
	}
	if err := validateSegment("sha", sha); err != nil {
		return nil, err
	}
	if !isSHA(sha) {
		return nil, fmt.Errorf("github: invalid sha %q", sha)
	}
	sha = strings.ToLower(sha)
	op += "@" + sha

	req, err := c.request(ctx, op, c.apiURL("repos", owner, name, "tarball", sha), acceptJSON)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.transportError(op, err)
	}
	c.log.Debug("github request", "op", op, "status", resp.StatusCode)

	if err := checkStatus(op, resp); err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	if resp.ContentLength > c.maxTarball {
		_ = resp.Body.Close()
		return nil, c.tooLarge(op)
	}
	return &cappedReader{rc: resp.Body, remaining: c.maxTarball, limit: c.maxTarball, op: op}, nil
}

// get performs a GET and decodes a JSON body into out. It returns the response
// headers so callers can read pagination links.
func (c *Client) get(ctx context.Context, op string, u *url.URL, accept string, out any) (http.Header, error) {
	req, err := c.request(ctx, op, u, accept)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.transportError(op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	c.log.Debug("github request", "op", op, "status", resp.StatusCode)

	if err := checkStatus(op, resp); err != nil {
		return nil, err
	}
	// io.LimitReader never returns an error, so a body that is too large
	// surfaces as a decode failure rather than a truncated value.
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBytes)).Decode(out); err != nil {
		return nil, &Error{Op: op, Hint: "unexpected response from GitHub", Err: err}
	}
	return resp.Header, nil
}

// request builds a GET carrying the headers every ADR-005 call sets.
func (c *Client) request(ctx context.Context, op string, u *url.URL, accept string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		// url.Error embeds the URL, which may one day carry a query string,
		// so the cause is deliberately not wrapped.
		return nil, &Error{Op: op, Hint: "could not build the request"}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", c.userAgent)
	return req, nil
}

// transportError converts a net/http error into an *Error without the request
// URL that *url.Error carries.
func (c *Client) transportError(op string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return &Error{Op: op, Hint: "could not reach GitHub", Err: err}
}

// apiURL joins validated path segments onto the base URL. The query is not
// carried over; callers set it explicitly.
func (c *Client) apiURL(segments ...string) *url.URL {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/")
	for _, s := range segments {
		u.Path += "/" + s
	}
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return &u
}

// nextPageURL returns the rel="next" target from a Link header, or nil when
// there is none. A link that leaves the API host is refused: the target would
// receive the Authorization header.
func (c *Client) nextPageURL(op, link string) (*url.URL, error) {
	raw := parseNextLink(link)
	if raw == "" {
		return nil, nil //nolint:nilnil // nil, nil means "last page".
	}
	next, err := url.Parse(raw)
	if err != nil {
		return nil, &Error{Op: op, Hint: "GitHub returned a malformed pagination link"}
	}
	if !sameHost(c.base, next) {
		return nil, &Error{Op: op, Hint: "GitHub returned a pagination link to another host"}
	}
	return next, nil
}

// parseNextLink extracts the rel="next" URL from a Link header. It returns ""
// when the header is empty or has no next relation.
func parseNextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		target, params, ok := strings.Cut(part, ";")
		if !ok {
			continue
		}
		target = strings.TrimSpace(target)
		if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		for _, param := range strings.Split(params, ";") {
			param = strings.TrimSpace(param)
			if strings.EqualFold(param, `rel="next"`) || strings.EqualFold(param, "rel=next") {
				return strings.TrimSuffix(strings.TrimPrefix(target, "<"), ">")
			}
		}
	}
	return ""
}

// sameHost reports whether two URLs share scheme and host, so a request to b
// must not carry a credential meant for a.
func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// cappedReader fails once the tarball exceeds the byte budget, so a truncated
// archive can never look complete.
type cappedReader struct {
	rc        io.ReadCloser
	remaining int64
	limit     int64
	op        string
}

// Read passes the stream through, reading at most one byte past the budget to
// learn that it was exceeded.
func (r *cappedReader) Read(p []byte) (int, error) {
	if r.remaining < 0 {
		return 0, r.tooLarge()
	}
	if int64(len(p)) > r.remaining+1 {
		p = p[:r.remaining+1]
	}
	n, err := r.rc.Read(p)
	r.remaining -= int64(n)
	if r.remaining < 0 {
		return 0, r.tooLarge()
	}
	return n, err
}

// Close closes the underlying body.
func (r *cappedReader) Close() error { return r.rc.Close() }

func (r *cappedReader) tooLarge() error {
	return &Error{Op: r.op, Hint: "tarball is larger than " + sizeLabel(r.limit)}
}

// tooLarge reports that the tarball exceeded the configured budget.
func (c *Client) tooLarge(op string) error {
	return &Error{Op: op, Hint: "tarball is larger than " + sizeLabel(c.maxTarball)}
}

// sizeLabel formats a byte budget for a user-facing hint.
func sizeLabel(n int64) string {
	const mib = 1 << 20
	if n >= mib && n%mib == 0 {
		return fmt.Sprintf("%d MiB", n/mib)
	}
	return fmt.Sprintf("%d bytes", n)
}

// validateSegment rejects a value that could change the shape of the request
// path. Owner and repository names come from the database and the API, so they
// are untrusted.
func validateSegment(kind, value string) error {
	if value == "" {
		return fmt.Errorf("github: %s is empty", kind)
	}
	if value == "." || value == ".." {
		return fmt.Errorf("github: invalid %s %q", kind, value)
	}
	if strings.ContainsAny(value, "/\\?#") {
		return fmt.Errorf("github: invalid %s %q", kind, value)
	}
	if strings.ContainsFunc(value, isControl) {
		return fmt.Errorf("github: invalid %s %q", kind, value)
	}
	return nil
}

// refSegments validates a git ref and returns it as path segments. Slashes are
// allowed because branch names such as "release/2.x" are common; "." and ".."
// segments are not, so a ref stays inside the commits endpoint.
func refSegments(ref string) ([]string, error) {
	if ref == "" {
		return nil, errors.New("github: ref is empty")
	}
	segments := strings.Split(ref, "/")
	for _, s := range segments {
		if err := validateSegment("ref", s); err != nil {
			return nil, err
		}
	}
	return segments, nil
}

// repoOp validates the repository identifiers and returns the operation label
// used in logs and errors ("get repo owner/name"). It never contains a URL.
func repoOp(op, owner, name string) (string, error) {
	if err := validateSegment("owner", owner); err != nil {
		return "", err
	}
	if err := validateSegment("repo", name); err != nil {
		return "", err
	}
	return op + " " + owner + "/" + name, nil
}

// isControl reports whether r is an ASCII control character.
func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// isSHA reports whether s is a 40-character hexadecimal commit SHA.
func isSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
