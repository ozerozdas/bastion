package httpapi

import (
	"bytes"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// uiAssetsPrefix is where Vite writes hashed bundles.
const uiAssetsPrefix = "/assets/"

// uiContentTypes pins the content types the bundle ships. Go's mime package
// answers the common ones, but the UI must not depend on the host's
// /etc/mime.types being installed.
var uiContentTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".html":  "text/html; charset=utf-8",
	".ico":   "image/x-icon",
	".js":    "text/javascript; charset=utf-8",
	".json":  "application/json",
	".map":   "application/json",
	".mjs":   "text/javascript; charset=utf-8",
	".png":   "image/png",
	".svg":   "image/svg+xml",
	".txt":   "text/plain; charset=utf-8",
	".webp":  "image/webp",
	".woff":  "font/woff",
	".woff2": "font/woff2",
}

// uiHandler serves the embedded SPA: real files first, index.html for any
// other path so client-side routes survive a reload.
//
// The server's CSP is `default-src 'self'` (PROJECT_SPEC.md §4.3), so the
// bundle it serves may not contain inline script or style, and this handler
// adds no inline anything.
type uiHandler struct {
	fsys  fs.FS
	index []byte
	log   *slog.Logger
}

// newUIHandler serves fsys. When fsys has no index.html (the UI has not been
// built) it falls back to the placeholder page instead of a bare 404, so a
// bare `go run ./cmd/bastion serve` still explains itself.
func newUIHandler(fsys fs.FS, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	index, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		index = placeholderHTML
	}
	return &uiHandler{fsys: fsys, index: index, log: log}
}

func (u *uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeProblem(w, http.StatusMethodNotAllowed, "Method Not Allowed",
			"the UI is only served over GET")
		return
	}

	// path.Clean after prefixing "/" collapses ".." so no request can climb
	// out of the embedded tree.
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name != "" {
		if file, err := fs.ReadFile(u.fsys, name); err == nil {
			u.serveFile(w, r, name, file)
			return
		}
	}

	// A missing hashed bundle is a build problem, not a client route: say so
	// instead of answering with HTML that the browser cannot execute.
	// The same holds for any missing file-like path (favicon.svg, robots.txt):
	// client routes never carry an extension.
	if strings.HasPrefix(r.URL.Path, uiAssetsPrefix) || path.Ext(name) != "" {
		writeProblem(w, http.StatusNotFound, "Not Found", "no such asset: "+Redact(r.URL.Path))
		return
	}

	u.serveIndex(w, r)
}

// serveIndex answers with the SPA shell, which is also the fallback for
// unknown client-side routes such as /projects.
func (u *uiHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Content-Security-Policy", "default-src 'self'")
	header.Set("Cache-Control", "no-cache")
	if r.Method == http.MethodHead {
		header.Set("Content-Length", strconv.Itoa(len(u.index)))
		w.WriteHeader(http.StatusOK)
		return
	}
	if _, err := w.Write(u.index); err != nil {
		u.log.Debug("write UI response", "error", err)
	}
}

// serveFile answers with one embedded file, with the content type the bundle
// needs and long-lived caching for hashed assets.
func (u *uiHandler) serveFile(w http.ResponseWriter, r *http.Request, name string, file []byte) {
	header := w.Header()
	header.Set("Content-Type", contentTypeFor(name))
	if strings.HasPrefix(name, strings.TrimPrefix(uiAssetsPrefix, "/")) {
		header.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		header.Set("Cache-Control", "no-cache")
	}
	// ServeContent handles HEAD and byte ranges; the zero modtime makes it
	// skip conditional requests, which is what an embedded file wants.
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(file))
}

// contentTypeFor maps a file name to the type the browser expects.
func contentTypeFor(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if contentType, ok := uiContentTypes[ext]; ok {
		return contentType
	}
	if contentType := mime.TypeByExtension(ext); contentType != "" {
		return contentType
	}
	return "application/octet-stream"
}
