package github

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Error is a failed GitHub API call. Hint is safe to show to the user;
// Error() names the operation and the repository, never the request URL, its
// query string or the token (ADR-005).
type Error struct {
	// Op is the operation that failed, such as "get repo owner/name".
	Op string
	// StatusCode is the HTTP status, or 0 when no response was received.
	StatusCode int
	// Hint is a user-facing explanation, empty when the status speaks for
	// itself.
	Hint string
	// Err is the underlying cause, if any.
	Err error
}

// Error implements error.
func (e *Error) Error() string {
	msg := "github: " + e.Op
	if e.StatusCode != 0 {
		msg += fmt.Sprintf(": %d %s", e.StatusCode, http.StatusText(e.StatusCode))
	}
	if e.Hint != "" {
		msg += ": " + e.Hint
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying cause so callers can test for context.Canceled
// and friends.
func (e *Error) Unwrap() error { return e.Err }

// checkStatus maps a non-2xx response to an *Error with the ADR-005 hint.
// GitHub's response body is not read: it is untrusted text and can echo the
// request back.
func checkStatus(op string, resp *http.Response) error {
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}

	e := &Error{Op: op, StatusCode: resp.StatusCode}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		e.Hint = "token invalid or expired"
	case resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0":
		e.Hint = rateLimitHint(resp.Header.Get("X-RateLimit-Reset"))
	case resp.StatusCode == http.StatusNotFound:
		e.Hint = "repo not found or token lacks access"
	}
	return e
}

// rateLimitHint describes when the rate limit resets.
func rateLimitHint(reset string) string {
	sec, err := strconv.ParseInt(reset, 10, 64)
	if err != nil || sec <= 0 {
		return "rate limited, try again later"
	}
	return "rate limited until " + time.Unix(sec, 0).UTC().Format(time.RFC3339)
}
