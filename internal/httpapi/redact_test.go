package httpapi

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	// A 43-char base64url value, like a real token.
	const token = "W4nqHbpPCDk1yCUZb3yHKp2_voosFmx3lnkCMXb_9dk" //nolint:gosec // G101: fake test token. gitleaks:allow

	tests := []struct {
		name       string
		in         string
		wantAbsent []string
		want       string
	}{
		{
			name:       "startup token query parameter",
			in:         "/?t=" + token,
			wantAbsent: []string{token},
			want:       "/?t=" + redacted,
		},
		{
			name:       "named token parameter",
			in:         "/api/connections?token=" + token + "&limit=10",
			wantAbsent: []string{token},
			want:       "/api/connections?token=" + redacted + "&limit=10",
		},
		{
			name:       "api key parameter",
			in:         "GET /api/assets?api_key=abc123&other=1",
			wantAbsent: []string{"abc123"},
			want:       "GET /api/assets?api_key=" + redacted + "&other=1",
		},
		{
			name:       "authorization header",
			in:         "Authorization: Bearer ghp_abcdefghijklmnop",
			wantAbsent: []string{"ghp_abcdefghijklmnop"},
			want:       "Authorization: " + redacted,
		},
		{
			name:       "cookie header",
			in:         "Cookie: bastion_session=" + token,
			wantAbsent: []string{token},
			want:       "Cookie: " + redacted,
		},
		{
			name:       "bare bearer scheme",
			in:         "header value bearer ghp_abcdefghijklmnop",
			wantAbsent: []string{"ghp_abcdefghijklmnop"},
			want:       "header value bearer " + redacted,
		},
		{
			name: "ordinary text untouched",
			in:   "/api/scans/42/findings?severity=critical&limit=20",
			want: "/api/scans/42/findings?severity=critical&limit=20",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			if got != tc.want {
				t.Errorf("Redact(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for _, secret := range tc.wantAbsent {
				if strings.Contains(got, secret) {
					t.Errorf("Redact(%q) = %q still contains %q", tc.in, got, secret)
				}
			}
		})
	}
}

// TestRedactRemovesBrowserURLToken covers the actual value the server hands
// out: even a whole browser URL loses its token.
func TestRedactRemovesBrowserURLToken(t *testing.T) {
	srv, err := New(Config{Version: "test", Port: 12345})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	redactedURL := Redact(srv.BrowserURL())
	if strings.Contains(redactedURL, srv.token) {
		t.Fatalf("Redact(BrowserURL()) = %q still contains the token", redactedURL)
	}
	if !strings.Contains(redactedURL, "http://127.0.0.1:12345/") {
		t.Errorf("Redact removed more than the token: %q", redactedURL)
	}
}

// TestTokensAreRandomAndDistinct: the startup token and the session value must
// not be predictable or equal to each other.
func TestTokensAreRandomAndDistinct(t *testing.T) {
	first, err := New(Config{Version: "test", Port: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	second, err := New(Config{Version: "test", Port: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if first.token == second.token || first.session == second.session {
		t.Error("two servers generated the same secrets")
	}
	if first.token == first.session {
		t.Error("token and session value are the same")
	}
	for _, token := range []string{first.token, first.session} {
		// 32 random bytes base64url-encoded without padding.
		if len(token) != 43 {
			t.Errorf("token length = %d, want 43", len(token))
		}
	}
}
