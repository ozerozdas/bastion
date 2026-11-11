package httpapi

import "regexp"

// redacted replaces a credential-shaped value in log output.
const redacted = "[REDACTED]"

var (
	// Query and form style parameters: `?t=…`, `token=…`, `api_key=…`.
	// `t` is included because it is the name of bastion's own startup token.
	// The `\b` keeps words such as `result=` or `content=` untouched.
	redactParamPattern = regexp.MustCompile(
		`(?i)\b(t|token|access_token|refresh_token|id_token|api_key|apikey|key|secret|client_secret|password|passwd|sig|signature|code)=([^&\s"'#;]+)`)

	// Header style values: `Authorization: Bearer …`, `Cookie: …`.
	redactHeaderPattern = regexp.MustCompile(
		`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-bastion-token)\s*[:=]\s*([^\r\n]+)`)

	// Credential schemes that are not tied to a header name.
	redactSchemePattern = regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+([A-Za-z0-9._~+/=-]{8,})`)
)

// Redact removes credential-shaped values from a string before it is logged.
//
// It is a safety net, not a licence to log untrusted text: callers log the
// request path and never the query string or headers, so the startup token
// (PROJECT_SPEC.md §4.3) has no route into the log at all.
func Redact(value string) string {
	if value == "" {
		return value
	}
	out := redactParamPattern.ReplaceAllString(value, `$1=`+redacted)
	out = redactHeaderPattern.ReplaceAllString(out, `$1: `+redacted)
	out = redactSchemePattern.ReplaceAllString(out, `$1 `+redacted)
	return out
}
