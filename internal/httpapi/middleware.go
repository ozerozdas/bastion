package httpapi

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// checkHost rejects DNS-rebinding attempts: the Host header must name the
// loopback interface and the exact port we are serving on (PROJECT_SPEC.md
// §4.3). It applies to every route, including the UI.
func (s *Server) checkHost(next http.Handler) http.Handler {
	allowed := [2]string{
		"127.0.0.1:" + strconv.Itoa(s.port),
		"localhost:" + strconv.Itoa(s.port),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != allowed[0] && r.Host != allowed[1] {
			writeProblem(w, http.StatusMisdirectedRequest, "Misdirected Request",
				"bastion only answers requests for "+allowed[0]+" or "+allowed[1])
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireSession is the authentication and CSRF middleware.
//
//   - A request carrying the startup token for "/" exchanges it for the session
//     cookie and is redirected (303) to the same URL without the token, so the
//     token leaves the address bar and history immediately. The token is
//     single-use; a second presentation is rejected even though the cookie set
//     by the first one keeps working for the process lifetime.
//   - Every other request must present the session cookie, otherwise it gets
//     401 problem+json. The UI is included: there is no unauthenticated surface.
//   - Mutating /api/* requests must also send `X-Bastion: 1`, which a
//     cross-site form or a simple request cannot do (CSRF, §4.3). There is no
//     CORS support at all, so browsers never let another origin add it.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token := r.URL.Query().Get("t"); token != "" && isTokenExchange(r) {
			s.exchangeToken(w, r, token)
			return
		}

		if !s.validSession(r) {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized",
				"missing or invalid "+SessionCookieName+" cookie; open the URL printed by `bastion serve`")
			return
		}

		if isMutating(r.Method) && isAPIPath(r.URL.Path) && r.Header.Get(csrfHeaderName) != csrfHeaderVal {
			writeProblem(w, http.StatusForbidden, "Forbidden",
				"mutating API requests require the "+csrfHeaderName+": "+csrfHeaderVal+" header")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isTokenExchange reports whether this request is the one the browser makes
// when it opens the startup URL.
func isTokenExchange(r *http.Request) bool {
	if r.URL.Path != "/" {
		return false
	}
	return r.Method == http.MethodGet || r.Method == http.MethodHead
}

// exchangeToken validates the single-use startup token and replaces it with the
// session cookie.
func (s *Server) exchangeToken(w http.ResponseWriter, r *http.Request, presented string) {
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.token)) != 1 {
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "invalid startup token")
		return
	}
	// Swap instead of Load+Store so two concurrent requests cannot both win.
	if !s.tokenUsed.CompareAndSwap(false, true) {
		writeProblem(w, http.StatusUnauthorized, "Unauthorized",
			"startup token was already used; reuse the session cookie or restart `bastion serve`")
		return
	}

	// Secure is deliberately unset: plain HTTP on loopback (§4.3); a Secure
	// cookie would never be sent back.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: loopback HTTP, see above
		Name:     SessionCookieName,
		Value:    s.session,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// No Secure: the transport is plain HTTP on loopback (§4.3).
	})

	// Redirect to the same path without t=, keeping any other query parameter.
	query := r.URL.Query()
	query.Del("t")
	target := r.URL.Path
	if encoded := query.Encode(); encoded != "" {
		target += "?" + encoded
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusSeeOther)
}

// validSession reports whether the request carries the session cookie. The
// comparison is constant-time so the cookie value cannot be recovered byte by
// byte from response timing.
func (s *Server) validSession(r *http.Request) bool {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.session)) == 1
}

// securityHeaders sets the headers that must be on every response (§4.3). The
// CSP for HTML is set where HTML is served, since it says nothing about JSON.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// statusRecorder remembers the status code for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Flush keeps streaming responses (SSE, Phase 1) working through the recorder.
func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// logRequests logs one line per request: method, path, status and duration.
//
// The query string is deliberately never logged: it is where the startup token
// arrives. Everything logged still goes through Redact as a second line of
// defence.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)

		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		s.log.LogAttrs(r.Context(), slog.LevelInfo, "http request",
			slog.String("method", r.Method),
			slog.String("path", Redact(r.URL.Path)),
			slog.Int("status", status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		)
	})
}

// isMutating reports whether a method may change state.
func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// isAPIPath reports whether path is under /api/.
func isAPIPath(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}
