package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// This file is the write side of ADR-005's client (#47): the five REST calls a
// manifest pull request needs. Each one is only made after the user confirmed
// the change; like every other call it carries the connection's token, and its
// errors name the operation and repository, never the request URL.

// File is a file's text at one ref.
type File struct {
	Path    string
	SHA     string
	Content []byte
}

// FileContent is the contents API's response shape. Only what a manifest edit
// needs is decoded.
type FileContent struct {
	Path     string `json:"path"`
	SHA      string `json:"sha"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	Type     string `json:"type"`
}

// PullRequest is a pull request as the API describes it.
type PullRequest struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

// PullRequestInput is one POST /repos/{owner}/{repo}/pulls body.
type PullRequestInput struct {
	Owner string
	Name  string
	Title string
	Head  string
	Base  string
	Body  string
}

// PutFileInput is one PUT /repos/{owner}/{repo}/contents/{path} body.
type PutFileInput struct {
	Owner   string
	Name    string
	Path    string
	Branch  string
	Message string
	Content []byte
	// SHA is the blob SHA the edit replaces, so GitHub refuses the write when
	// the file changed since it was read.
	SHA string
}

// putFileResponse is the contents API's write answer: the new blob sits under
// "content".
type putFileResponse struct {
	Content struct {
		Path string `json:"path"`
		SHA  string `json:"sha"`
	} `json:"content"`
}

// putFileBody is the contents API's write shape.
type putFileBody struct {
	Message string `json:"message"`
	Content string `json:"content"`
	SHA     string `json:"sha"`
	Branch  string `json:"branch"`
}

// createRefBody is the git refs API's write shape.
type createRefBody struct {
	Ref string `json:"ref"`
	SHA string `json:"sha"`
}

// createPullRequestBody is the pulls API's write shape.
type createPullRequestBody struct {
	Title string `json:"title"`
	Head  string `json:"head"`
	Base  string `json:"base"`
	Body  string `json:"body"`
}

// refResponse is the git refs API's read shape.
type refResponse struct {
	Object struct {
		SHA string `json:"sha"`
	} `json:"object"`
}

// File reads a file's content at ref (GET /repos/{owner}/{repo}/contents/{path}).
// The contents API answers base64; the decoded bytes are returned so the caller
// can edit the text.
func (c *Client) File(ctx context.Context, owner, name, path, ref string) (File, error) {
	op, err := fileOp("get file", owner, name, path)
	if err != nil {
		return File{}, err
	}

	u, err := c.contentsURL(owner, name, path)
	if err != nil {
		return File{}, err
	}
	if ref != "" {
		q := u.Query()
		q.Set("ref", ref)
		u.RawQuery = q.Encode()
	}

	var content FileContent
	if _, err := c.get(ctx, op, u, acceptJSON, &content); err != nil {
		return File{}, err
	}
	if content.Type != "" && content.Type != "file" {
		return File{}, &Error{Op: op, Hint: "the path is not a file"}
	}
	if content.Encoding != "base64" {
		return File{}, &Error{Op: op, Hint: "GitHub did not return the file's text"}
	}
	decoded, err := base64.StdEncoding.DecodeString(content.Content)
	if err != nil {
		return File{}, &Error{Op: op, Hint: "GitHub returned unreadable file content"}
	}
	return File{Path: content.Path, SHA: content.SHA, Content: decoded}, nil
}

// RefSHA resolves a branch to its commit SHA (GET
// /repos/{owner}/{repo}/git/ref/heads/{branch}). found is false when the ref
// does not exist, which is how the pull request flow learns a branch name is
// still free.
func (c *Client) RefSHA(ctx context.Context, owner, name, branch string) (sha string, found bool, err error) {
	op, err := repoOp("get ref", owner, name)
	if err != nil {
		return "", false, err
	}
	op += "@" + branch

	u, err := c.refURL(owner, name, branch)
	if err != nil {
		return "", false, err
	}

	var ref refResponse
	if _, err := c.get(ctx, op, u, acceptJSON, &ref); err != nil {
		var ghErr *Error
		if errors.As(err, &ghErr) && ghErr.StatusCode == http.StatusNotFound {
			return "", false, nil
		}
		return "", false, err
	}
	if ref.Object.SHA == "" {
		return "", false, &Error{Op: op, Hint: "GitHub did not return a commit SHA"}
	}
	return ref.Object.SHA, true, nil
}

// CreateRef creates a branch (POST /repos/{owner}/{repo}/git/refs).
func (c *Client) CreateRef(ctx context.Context, owner, name, branch, sha string) error {
	op, err := repoOp("create ref", owner, name)
	if err != nil {
		return err
	}
	op += "@" + branch

	if err := validateBranch(branch); err != nil {
		return err
	}
	if !isSHA(sha) {
		return fmt.Errorf("github: invalid sha %q", sha)
	}

	if _, err := c.send(ctx, op, http.MethodPost, c.apiURL("repos", owner, name, "git", "refs"),
		createRefBody{Ref: "refs/heads/" + branch, SHA: sha}, nil); err != nil {
		return err
	}
	return nil
}

// DeleteRef deletes a branch (DELETE
// /repos/{owner}/{repo}/git/refs/heads/{branch}). The pull request flow calls it
// to undo a branch whose commit or pull request failed.
func (c *Client) DeleteRef(ctx context.Context, owner, name, branch string) error {
	op, err := repoOp("delete ref", owner, name)
	if err != nil {
		return err
	}
	op += "@" + branch

	segments, err := refSegments(branch)
	if err != nil {
		return err
	}
	u := c.apiURL(append([]string{"repos", owner, name, "git", "refs", "heads"}, segments...)...)
	if _, err := c.send(ctx, op, http.MethodDelete, u, nil, nil); err != nil {
		return err
	}
	return nil
}

// PutFile writes one file on a branch (PUT
// /repos/{owner}/{repo}/contents/{path}). GitHub creates the commit on branch;
// the branch must already exist.
func (c *Client) PutFile(ctx context.Context, in PutFileInput) (File, error) {
	op, err := fileOp("put file", in.Owner, in.Name, in.Path)
	if err != nil {
		return File{}, err
	}

	u, err := c.contentsURL(in.Owner, in.Name, in.Path)
	if err != nil {
		return File{}, err
	}

	var response putFileResponse
	body := putFileBody{
		Message: in.Message,
		Content: base64.StdEncoding.EncodeToString(in.Content),
		SHA:     in.SHA,
		Branch:  in.Branch,
	}
	if _, err := c.send(ctx, op, http.MethodPut, u, body, &response); err != nil {
		return File{}, err
	}
	return File{Path: response.Content.Path, SHA: response.Content.SHA}, nil
}

// CreatePullRequest opens a pull request (POST /repos/{owner}/{repo}/pulls).
func (c *Client) CreatePullRequest(ctx context.Context, in PullRequestInput) (PullRequest, error) {
	op, err := repoOp("create pull request", in.Owner, in.Name)
	if err != nil {
		return PullRequest{}, err
	}

	var pr PullRequest
	if _, err := c.send(ctx, op, http.MethodPost, c.apiURL("repos", in.Owner, in.Name, "pulls"),
		createPullRequestBody{
			Title: in.Title,
			Head:  in.Head,
			Base:  in.Base,
			Body:  in.Body,
		}, &pr); err != nil {
		return PullRequest{}, err
	}
	if pr.HTMLURL == "" || pr.Number <= 0 {
		return PullRequest{}, &Error{Op: op, Hint: "GitHub did not return the pull request"}
	}
	return pr, nil
}

// PullRequestsForHead lists the open pull requests whose head branch is
// head (GET /repos/{owner}/{repo}/pulls?state=open&head=...). head is
// "owner:branch", as GitHub spells it.
func (c *Client) PullRequestsForHead(ctx context.Context, owner, name, head string) ([]PullRequest, error) {
	op, err := repoOp("list pull requests", owner, name)
	if err != nil {
		return nil, err
	}

	u := c.apiURL("repos", owner, name, "pulls")
	q := u.Query()
	q.Set("state", "open")
	q.Set("head", head)
	u.RawQuery = q.Encode()

	var prs []PullRequest
	if _, err := c.get(ctx, op, u, acceptJSON, &prs); err != nil {
		return nil, err
	}
	return prs, nil
}

// send performs a JSON request with a body and decodes the JSON response into
// out when it is not nil.
func (c *Client) send(ctx context.Context, op, method string, u *url.URL, in, out any) (http.Header, error) {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return nil, &Error{Op: op, Hint: "could not encode the request"}
		}
		body = bytes.NewReader(encoded)
	}

	req, err := c.newRequest(ctx, op, method, u, acceptJSON, body)
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
	if out == nil {
		return resp.Header, nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBytes)).Decode(out); err != nil {
		return nil, &Error{Op: op, Hint: "unexpected response from GitHub", Err: err}
	}
	return resp.Header, nil
}

// contentsURL is /repos/{owner}/{repo}/contents/{path}. Every path segment is
// validated so a finding's location cannot change the shape of the request.
func (c *Client) contentsURL(owner, name, path string) (*url.URL, error) {
	segments := []string{"repos", owner, name, "contents"}
	for _, segment := range strings.Split(path, "/") {
		if err := validateSegment("path", segment); err != nil {
			return nil, err
		}
		segments = append(segments, segment)
	}
	return c.apiURL(segments...), nil
}

// refURL is /repos/{owner}/{repo}/git/ref/heads/{branch}; branch segments stay
// separate so "bastion/bump-x" addresses the branch, not a missing path.
func (c *Client) refURL(owner, name, branch string) (*url.URL, error) {
	segments, err := refSegments(branch)
	if err != nil {
		return nil, err
	}
	return c.apiURL(append([]string{"repos", owner, name, "git", "ref", "heads"}, segments...)...), nil
}

// validateBranch rejects a branch name that cannot be part of a ref.
func validateBranch(branch string) error {
	_, err := refSegments(branch)
	return err
}

// fileOp builds the operation label and validates a file path's segments.
func fileOp(op, owner, name, path string) (string, error) {
	label, err := repoOp(op, owner, name)
	if err != nil {
		return "", err
	}
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return "", errors.New("github: path is empty")
	}
	for _, part := range parts {
		if err := validateSegment("path", part); err != nil {
			return "", err
		}
	}
	return label + "/" + path, nil
}
