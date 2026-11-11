package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	crand "crypto/rand"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/sources"
)

const (
	testSHA = "0123456789abcdef0123456789abcdef01234567"
	testTop = "octo-hello-" + testSHA
)

func TestKind(t *testing.T) {
	src, err := New(&fakeDownloader{}, Options{WorkspacesDir: t.TempDir(), Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := src.Kind(); got != sources.KindRepo {
		t.Fatalf("Kind() = %q, want %q", got, sources.KindRepo)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	tests := []struct {
		name string
		dl   Downloader
		opts Options
	}{
		{name: "nil downloader", opts: Options{WorkspacesDir: t.TempDir()}},
		{name: "empty workspaces dir", dl: &fakeDownloader{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.dl, tt.opts); err == nil {
				t.Fatal("New accepted invalid options")
			}
		})
	}
}

func TestFetchExtractsAndStripsTopDirectory(t *testing.T) {
	body := tarball(t,
		entry{name: testTop + "/", typ: tar.TypeDir, mode: 0o755},
		entry{name: testTop + "/go.mod", body: "module example.com/hello\n"},
		entry{name: testTop + "/README.md", body: "hello\n"},
		entry{name: testTop + "/cmd/hello/main.go", mode: 0o755, body: "package main\n"},
	)
	dl := &fakeDownloader{body: body}
	base := filepath.Join(t.TempDir(), "workspaces")
	src, err := New(dl, Options{WorkspacesDir: base, Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ws, err := src.Fetch(context.Background(), target("octo/hello@"+testSHA))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	if dl.calls != 1 {
		t.Fatalf("Tarball calls = %d, want 1", dl.calls)
	}
	if dl.owner != "octo" || dl.name != "hello" || dl.sha != testSHA {
		t.Fatalf("Tarball args = %s/%s@%s", dl.owner, dl.name, dl.sha)
	}
	if !filepath.IsAbs(ws.Dir) {
		t.Fatalf("Dir = %q, want an absolute path", ws.Dir)
	}
	if !strings.HasPrefix(ws.Dir, base+string(filepath.Separator)) {
		t.Fatalf("Dir = %q, want a directory under %q", ws.Dir, base)
	}
	if _, err := os.Stat(filepath.Join(ws.Dir, testTop)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("top-level directory survived extraction: %v", err)
	}

	if got := readFile(t, filepath.Join(ws.Dir, "go.mod")); got != "module example.com/hello\n" {
		t.Errorf("go.mod = %q", got)
	}
	if got := readFile(t, filepath.Join(ws.Dir, "README.md")); got != "hello\n" {
		t.Errorf("README.md = %q", got)
	}
	if got := readFile(t, filepath.Join(ws.Dir, "cmd", "hello", "main.go")); got != "package main\n" {
		t.Errorf("main.go = %q", got)
	}
	assertMode(t, filepath.Join(ws.Dir, "go.mod"), 0o644)
	assertMode(t, filepath.Join(ws.Dir, "cmd", "hello", "main.go"), 0o755)
	assertMode(t, filepath.Join(ws.Dir, "cmd"), 0o755)

	if err := ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(ws.Dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("workspace survived Close: %v", err)
	}
	assertEmptyDir(t, base)
}

func TestFetchRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name  string
		entry entry
	}{
		{name: "parent", entry: entry{name: "../x", body: "x"}},
		{name: "climbs out", entry: entry{name: testTop + "/../../x", body: "x"}},
		{name: "absolute", entry: entry{name: "/etc/x", body: "x"}},
		{name: "absolute in top", entry: entry{name: "/" + testTop + "/x", body: "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := t.TempDir()
			src, err := New(&fakeDownloader{body: tarball(t, tt.entry)}, Options{
				WorkspacesDir: base,
				Logger:        testLogger(),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := src.Fetch(context.Background(), target("octo/hello@"+testSHA)); err == nil {
				t.Fatal("Fetch accepted an unsafe archive entry")
			}
			assertEmptyDir(t, base)
		})
	}
}

func TestFetchSkipsLinksAndSpecialFiles(t *testing.T) {
	body := tarball(t,
		entry{name: testTop + "/", typ: tar.TypeDir, mode: 0o755},
		entry{name: testTop + "/README.md", body: "hello\n"},
		entry{name: testTop + "/link-out", typ: tar.TypeSymlink, link: "../../../etc/passwd"},
		entry{name: testTop + "/link-in", typ: tar.TypeSymlink, link: "README.md"},
		entry{name: testTop + "/hard", typ: tar.TypeLink, link: testTop + "/README.md"},
		entry{name: testTop + "/char", typ: tar.TypeChar, mode: 0o666},
		entry{name: testTop + "/fifo", typ: tar.TypeFifo, mode: 0o666},
	)
	var logs bytes.Buffer
	src, err := New(&fakeDownloader{body: body}, Options{
		WorkspacesDir: t.TempDir(),
		Logger:        slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ws, err := src.Fetch(context.Background(), target("octo/hello@"+testSHA))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	for _, name := range []string{"link-out", "link-in", "hard", "char", "fifo"} {
		if _, err := os.Lstat(filepath.Join(ws.Dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s was created: %v", name, err)
		}
	}
	if got := readFile(t, filepath.Join(ws.Dir, "README.md")); got != "hello\n" {
		t.Errorf("README.md = %q", got)
	}

	// The skip must be reported: the warning names each category.
	out := logs.String()
	for _, want := range []string{"skipped archive entries", "symlinks=2", "hardlinks=1", "special=2"} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %q:\n%s", want, out)
		}
	}
}

func TestFetchEnforcesBudgets(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		body []byte
		want string
	}{
		{
			name: "bytes",
			opts: Options{MaxExtractBytes: 8},
			body: tarball(t, entry{name: testTop + "/big", body: strings.Repeat("x", 16)}),
			want: "extracts to more than 8 bytes",
		},
		{
			name: "files",
			opts: Options{MaxFiles: 2},
			body: tarball(t,
				entry{name: testTop + "/a", body: "a"},
				entry{name: testTop + "/b", body: "b"},
				entry{name: testTop + "/c", body: "c"},
			),
			want: "more than 2 files",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := t.TempDir()
			tt.opts.WorkspacesDir = base
			tt.opts.Logger = testLogger()
			src, err := New(&fakeDownloader{body: tt.body}, tt.opts)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = src.Fetch(context.Background(), target("octo/hello@"+testSHA))
			if err == nil {
				t.Fatal("Fetch accepted an archive over budget")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
			assertEmptyDir(t, base)
		})
	}
}

func TestFetchCanceledMidReadRemovesWorkspace(t *testing.T) {
	// Random bytes do not compress, so the reader's block point is well before
	// the end of the gzip stream.
	blob := make([]byte, 64<<10)
	if _, err := crand.Read(blob); err != nil {
		t.Fatal(err)
	}
	body := tarball(t,
		entry{name: testTop + "/a.bin", body: string(blob)},
		entry{name: testTop + "/b.txt", body: "b"},
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reached := make(chan struct{})
	rc := &blockingReader{data: body, limit: len(body) / 2, ctx: ctx, reached: reached}

	base := t.TempDir()
	src, err := New(&fakeDownloader{rc: rc}, Options{WorkspacesDir: base, Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := src.Fetch(ctx, target("octo/hello@"+testSHA))
		done <- err
	}()

	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the download reader never blocked; cannot cancel mid-extract")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Fetch error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Fetch did not return after cancel")
	}
	assertEmptyDir(t, base)
}

func TestFetchRejectsInvalidRefs(t *testing.T) {
	refs := []string{
		"",
		"octo/hello",
		"octo/hello@",
		"octo/hello@abc",
		"octo/hello@" + strings.Repeat("g", 40),
		"octo/hello@" + testSHA + "0",
		"octo/hello@" + testSHA[:39],
		"octo@hello@" + testSHA,
		"octo/hello/extra@" + testSHA,
		"/hello@" + testSHA,
		"octo/@" + testSHA,
		"../hello@" + testSHA,
		"oc to/hello@" + testSHA,
	}
	for _, ref := range refs {
		t.Run(ref, func(t *testing.T) {
			dl := &fakeDownloader{}
			base := t.TempDir()
			src, err := New(dl, Options{WorkspacesDir: base, Logger: testLogger()})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := src.Fetch(context.Background(), target(ref)); err == nil {
				t.Fatalf("Fetch accepted ref %q", ref)
			}
			if dl.calls != 0 {
				t.Errorf("Tarball called %d times for an invalid ref", dl.calls)
			}
			assertEmptyDir(t, base)
		})
	}
}

func TestFetchRejectsWrongKindAndCanceledContext(t *testing.T) {
	src, err := New(&fakeDownloader{}, Options{WorkspacesDir: t.TempDir(), Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := src.Fetch(context.Background(), sources.Target{Kind: sources.KindPath, Ref: "octo/hello@" + testSHA}); err == nil {
		t.Fatal("Fetch accepted a path target")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Fetch(canceled, target("octo/hello@"+testSHA)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Fetch error = %v, want context.Canceled", err)
	}
}

func TestFetchRemovesWorkspaceOnDownloadError(t *testing.T) {
	base := t.TempDir()
	dlErr := errors.New("could not reach GitHub")
	src, err := New(&fakeDownloader{err: dlErr}, Options{WorkspacesDir: base, Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := src.Fetch(context.Background(), target("octo/hello@"+testSHA)); !errors.Is(err, dlErr) {
		t.Fatalf("Fetch error = %v, want the download error", err)
	}
	assertEmptyDir(t, base)
}

func TestKeepWorkspace(t *testing.T) {
	body := tarball(t, entry{name: testTop + "/README.md", body: "hello\n"})
	src, err := New(&fakeDownloader{body: body}, Options{
		WorkspacesDir: t.TempDir(),
		KeepWorkspace: true,
		Logger:        testLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ws, err := src.Fetch(context.Background(), target("octo/hello@"+testSHA))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if err := ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(ws.Dir); err != nil {
		t.Fatalf("workspace removed despite KeepWorkspace: %v", err)
	}
}

// entry describes one tar entry for tarball.
type entry struct {
	name string
	typ  byte
	mode int64
	link string
	body string
}

// tarball builds a gzipped tar archive from entries.
func tarball(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
			if typ == tar.TypeDir {
				mode = 0o755
			}
		}
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: typ,
			Mode:     mode,
			Linkname: e.link,
		}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// fakeDownloader returns crafted bytes and records the call.
type fakeDownloader struct {
	body []byte
	rc   io.ReadCloser
	err  error

	calls            int
	owner, name, sha string
}

func (f *fakeDownloader) Tarball(_ context.Context, owner, name, sha string) (io.ReadCloser, error) {
	f.calls++
	f.owner, f.name, f.sha = owner, name, sha
	if f.err != nil {
		return nil, f.err
	}
	if f.rc != nil {
		return f.rc, nil
	}
	return io.NopCloser(bytes.NewReader(f.body)), nil
}

// blockingReader serves data up to limit bytes and then blocks until ctx is
// done, simulating a download that stalls half-way through extraction.
type blockingReader struct {
	data    []byte
	pos     int
	limit   int
	ctx     context.Context
	reached chan struct{}
	once    sync.Once
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if r.pos >= r.limit {
		r.once.Do(func() { close(r.reached) })
		<-r.ctx.Done()
		return 0, r.ctx.Err()
	}
	n := copy(p, r.data[r.pos:r.limit])
	r.pos += n
	return n, nil
}

func (r *blockingReader) Close() error { return nil }

func target(ref string) sources.Target {
	return sources.Target{Kind: sources.KindRepo, Ref: ref}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // G304: paths come from t.TempDir in tests.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func assertMode(t *testing.T, name string, want fs.FileMode) {
	t.Helper()
	info, err := os.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", name, got, want)
	}
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("%s is not empty after the failed fetch: %s", dir, strings.Join(names, ", "))
	}
}
