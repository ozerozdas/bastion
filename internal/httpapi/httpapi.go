// Package httpapi is bastion's local HTTP server: the generated OpenAPI
// handlers, the §4.3 security middleware around them and the embedded UI.
//
// The server answers on 127.0.0.1 only and authenticates every request with a
// session cookie that was obtained by exchanging the single-use startup token
// printed by `bastion serve` (PROJECT_SPEC.md §4.3).
package httpapi

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

const (
	// SessionCookieName is the cookie that carries the session value. It is set
	// by the server when it exchanges the startup token, never by the UI.
	SessionCookieName = "bastion_session"

	// tokenBytes is the entropy of both the startup token and the session
	// value: 32 bytes, base64url-encoded to 43 characters.
	tokenBytes = 32

	// csrfHeaderName/Val are the CSRF guard required on mutating /api/* requests.
	csrfHeaderName = "X-Bastion"
	csrfHeaderVal  = "1"

	shutdownGrace = 5 * time.Second
	// readHeaderTimeout bounds slow-header clients; the server is local, so
	// every legitimate request is fast.
	readHeaderTimeout = 10 * time.Second
)

// placeholderHTML is the stand-in UI. BST-009 replaces it with an embed of the
// built SPA (web/dist).
//
//go:embed index.html
var placeholderHTML []byte

// Config configures a Server. Port must be the port the listener actually
// bound, because the Host header check compares against it.
type Config struct {
	Version string
	Port    int
	// Logger receives request logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// Server serves the bastion API and UI. Create it with New, take its handler
// with Handler (for tests) or serve it with Serve.
type Server struct {
	version string
	port    int
	log     *slog.Logger

	// token arrives once, in the browser URL. session is the cookie value that
	// replaces it. They are distinct values: a token that leaked into shell
	// history or a proxy log can never be replayed as a cookie.
	token     string
	session   string
	tokenUsed atomic.Bool
	handler   http.Handler
}

// New generates the startup token and session value and wires the handler.
func New(cfg Config) (*Server, error) {
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	session, err := randomToken()
	if err != nil {
		return nil, err
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		version: cfg.Version,
		port:    cfg.Port,
		log:     logger,
		token:   token,
		session: session,
	}
	s.handler = s.buildHandler()
	return s, nil
}

// randomToken returns a fresh 32-byte random value, base64url-encoded.
func randomToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// BaseURL is the origin the server answers on.
func (s *Server) BaseURL() string {
	return "http://127.0.0.1:" + strconv.Itoa(s.port)
}

// BrowserURL is the URL to open: the origin plus the single-use token. It is
// printed to the user's terminal and never logged.
func (s *Server) BrowserURL() string {
	return s.BaseURL() + "/?t=" + s.token
}

// Handler is the fully wrapped server handler, security middleware included.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// GetHealth implements gen.StrictServerInterface.
func (s *Server) GetHealth(_ context.Context, _ gen.GetHealthRequestObject) (gen.GetHealthResponseObject, error) {
	return gen.GetHealth200JSONResponse{
		Status:  gen.Ok,
		Version: s.version,
	}, nil
}

// buildHandler registers the generated API routes and the UI on one mux, then
// wraps it in the §4.3 middleware. Wrapping order (outermost first) matters:
//
//	logging → security headers → Host check → session/CSRF → routes
//
// so every response, including the rejections, carries the security headers and
// appears in the request log.
func (s *Server) buildHandler() http.Handler {
	mux := http.NewServeMux()

	gen.HandlerWithOptions(gen.NewStrictHandler(s, nil), gen.StdHTTPServerOptions{
		BaseRouter: mux,
	})

	// Unknown /api/* paths must not fall through to the UI handler.
	mux.HandleFunc("GET /api/", func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, http.StatusNotFound, "Not Found",
			"no such API endpoint: "+Redact(r.URL.Path))
	})
	mux.HandleFunc("/", s.handleUI)

	var h http.Handler = mux
	h = s.requireSession(h)
	h = s.checkHost(h)
	h = securityHeaders(h)
	h = s.logRequests(h)
	return h
}

// handleUI serves the embedded UI. BST-009 replaces the placeholder with the
// built SPA; the CSP stays as is, so the bundle must not rely on inline script
// or style.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeProblem(w, http.StatusNotFound, "Not Found", "no such path: "+Redact(r.URL.Path))
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed",
			"the UI is only served over GET")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(placeholderHTML); err != nil {
		s.log.Debug("write UI response", "error", err)
	}
}

// writeProblem writes an RFC 9457 problem+json response. All bastion errors use
// this shape (PROJECT_SPEC.md §6).
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)

	problem := gen.Problem{
		Type:   "about:blank",
		Title:  title,
		Status: status,
		Detail: &detail,
	}
	if err := json.NewEncoder(w).Encode(problem); err != nil {
		slog.Debug("write problem response", "status", status, "error", err)
	}
}

// Listen binds the loopback interface. port 0 picks a free port; the caller
// learns it from the returned listener.
func Listen(port int) (net.Listener, error) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	return ln, nil
}

// Serve serves on ln until ctx is canceled, then shuts down gracefully. It
// returns nil on a clean shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ln)
	}()
	s.log.Info("http server listening", "addr", ln.Addr().String())

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve http: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve http: %w", err)
	}

	s.log.Info("http server stopped")
	return nil
}
