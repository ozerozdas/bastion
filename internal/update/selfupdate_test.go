package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testLatest = "v0.3.0"
	testAsset  = "bastion_0.3.0_darwin_arm64.tar.gz"
)

// releaseServer serves the release lookup redirect, one archive and its
// checksums over TLS, the way GitHub does.
type releaseServer struct {
	*httptest.Server
	downloads atomic.Int32
}

func newReleaseServer(t *testing.T, archive []byte, checksum string) *releaseServer {
	t.Helper()

	server := &releaseServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/ozerozdas/bastion/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ozerozdas/bastion/releases/tag/"+testLatest, http.StatusFound)
	})
	mux.HandleFunc("/dl/"+testLatest+"/"+testAsset, func(w http.ResponseWriter, _ *http.Request) {
		server.downloads.Add(1)
		_, _ = w.Write(archive)
	})
	mux.HandleFunc("/dl/"+testLatest+"/checksums.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "%s  %s\n", checksum, testAsset)
	})
	server.Server = httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return server
}

func archiveWith(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()

	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(gz)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     0o755,
			Size:     int64(len(entry.data)),
			Typeflag: tar.TypeReg,
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := writer.Write(entry.data); err != nil {
			t.Fatalf("write tar entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buffer.Bytes()
}

type archiveEntry struct {
	name string
	data []byte
}

func sumOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// newTarget writes an old "binary" and returns its path.
func newTarget(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: test fixture directory
		t.Fatalf("create target dir: %v", err)
	}
	target := filepath.Join(dir, "bastion")
	if err := os.WriteFile(target, []byte("old binary"), 0o755); err != nil { //nolint:gosec // G306: fixture must be executable
		t.Fatalf("write target: %v", err)
	}
	return target
}

func selfUpdateConfig(t *testing.T, server *releaseServer, target string, out *bytes.Buffer) SelfUpdateConfig {
	t.Helper()
	return SelfUpdateConfig{
		CurrentVersion:  "v0.2.0",
		GOOS:            "darwin",
		GOARCH:          "arm64",
		BaseURL:         server.URL,
		DownloadBaseURL: server.URL + "/dl",
		HTTPClient:      server.Client(),
		Executable:      func() (string, error) { return target, nil },
		Out:             out,
	}
}

func TestSelfUpdateReplacesBinary(t *testing.T) {
	target := newTarget(t)
	archive := archiveWith(t,
		archiveEntry{name: "README.md", data: []byte("readme")},
		archiveEntry{name: "bastion", data: []byte("new binary")},
	)
	server := newReleaseServer(t, archive, sumOf(archive))

	var out bytes.Buffer
	if err := SelfUpdate(context.Background(), selfUpdateConfig(t, server, target, &out)); err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}

	data, err := os.ReadFile(target) //nolint:gosec // G304: the test's own temporary target
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(data) != "new binary" {
		t.Fatalf("target = %q, want the archive's binary", data)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %o, want 755", info.Mode().Perm())
	}
	if !strings.Contains(out.String(), "updated v0.2.0 → v0.3.0") {
		t.Errorf("output missing the update line:\n%s", out.String())
	}
	assertNoTempFiles(t, filepath.Dir(target))
}

func TestSelfUpdateChecksumMismatchLeavesBinary(t *testing.T) {
	target := newTarget(t)
	archive := archiveWith(t, archiveEntry{name: "bastion", data: []byte("new binary")})
	server := newReleaseServer(t, archive, strings.Repeat("0", 64))

	var out bytes.Buffer
	err := SelfUpdate(context.Background(), selfUpdateConfig(t, server, target, &out))
	if err == nil {
		t.Fatal("SelfUpdate succeeded, want a checksum error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v, want a checksum mismatch", err)
	}
	assertFileContents(t, target, "old binary")
	assertNoTempFiles(t, filepath.Dir(target))
}

func TestSelfUpdateUpToDateIsNoOp(t *testing.T) {
	target := newTarget(t)
	archive := archiveWith(t, archiveEntry{name: "bastion", data: []byte("new binary")})
	server := newReleaseServer(t, archive, sumOf(archive))

	cfg := selfUpdateConfig(t, server, target, &bytes.Buffer{})
	cfg.CurrentVersion = testLatest
	var out bytes.Buffer
	cfg.Out = &out

	if err := SelfUpdate(context.Background(), cfg); err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	if !strings.Contains(out.String(), "bastion v0.3.0 is up to date") {
		t.Errorf("output = %q, want the up-to-date line", out.String())
	}
	if got := server.downloads.Load(); got != 0 {
		t.Errorf("downloads = %d, want 0", got)
	}
	assertFileContents(t, target, "old binary")
}

func TestSelfUpdateHomebrewPrintsCommand(t *testing.T) {
	archive := archiveWith(t, archiveEntry{name: "bastion", data: []byte("new binary")})
	server := newReleaseServer(t, archive, sumOf(archive))

	// The path is never touched, so it does not need to exist.
	target := "/opt/homebrew/Caskroom/bastion/0.3.0/bastion"
	var out bytes.Buffer
	cfg := selfUpdateConfig(t, server, target, &out)

	if err := SelfUpdate(context.Background(), cfg); err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	if !strings.Contains(out.String(), brewCommand) {
		t.Errorf("output = %q, want the brew command", out.String())
	}
	if got := server.downloads.Load(); got != 0 {
		t.Errorf("downloads = %d, want 0", got)
	}
}

func TestSelfUpdateWindowsPrintsReleaseURL(t *testing.T) {
	archive := archiveWith(t, archiveEntry{name: "bastion", data: []byte("new binary")})
	server := newReleaseServer(t, archive, sumOf(archive))

	target := newTarget(t)
	var out bytes.Buffer
	cfg := selfUpdateConfig(t, server, target, &out)
	cfg.GOOS = "windows"
	cfg.GOARCH = "amd64"

	if err := SelfUpdate(context.Background(), cfg); err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	if !strings.Contains(out.String(), releasesTagBase+testLatest) {
		t.Errorf("output = %q, want the release URL", out.String())
	}
	if got := server.downloads.Load(); got != 0 {
		t.Errorf("downloads = %d, want 0", got)
	}
	assertFileContents(t, target, "old binary")
}

func TestSelfUpdateDevBuild(t *testing.T) {
	archive := archiveWith(t, archiveEntry{name: "bastion", data: []byte("new binary")})
	server := newReleaseServer(t, archive, sumOf(archive))
	target := newTarget(t)

	t.Run("refused without force", func(t *testing.T) {
		var out bytes.Buffer
		cfg := selfUpdateConfig(t, server, target, &out)
		cfg.CurrentVersion = "dev"

		err := SelfUpdate(context.Background(), cfg)
		if err == nil {
			t.Fatal("SelfUpdate succeeded, want a refusal")
		}
		if !strings.Contains(err.Error(), "development build") {
			t.Fatalf("error = %v, want a development-build message", err)
		}
		if got := server.downloads.Load(); got != 0 {
			t.Errorf("downloads = %d, want 0", got)
		}
		assertFileContents(t, target, "old binary")
	})

	t.Run("forced", func(t *testing.T) {
		var out bytes.Buffer
		cfg := selfUpdateConfig(t, server, target, &out)
		cfg.CurrentVersion = "dev"
		cfg.Force = true

		if err := SelfUpdate(context.Background(), cfg); err != nil {
			t.Fatalf("SelfUpdate: %v", err)
		}
		if !strings.Contains(out.String(), "updated dev → v0.3.0") {
			t.Errorf("output = %q, want the update line", out.String())
		}
		assertFileContents(t, target, "new binary")
	})
}

func TestSelfUpdateCheckOnly(t *testing.T) {
	archive := archiveWith(t, archiveEntry{name: "bastion", data: []byte("new binary")})
	server := newReleaseServer(t, archive, sumOf(archive))
	target := newTarget(t)

	var out bytes.Buffer
	cfg := selfUpdateConfig(t, server, target, &out)
	cfg.Check = true

	if err := SelfUpdate(context.Background(), cfg); err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	for _, want := range []string{"current: v0.2.0", "latest:  v0.3.0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	if got := server.downloads.Load(); got != 0 {
		t.Errorf("downloads = %d, want 0", got)
	}
	assertFileContents(t, target, "old binary")
}

func TestSelfUpdateRejectsUnsafeArchive(t *testing.T) {
	tests := []struct {
		name    string
		archive func(t *testing.T) []byte
		cfg     func(*SelfUpdateConfig)
		want    string
	}{
		{
			name: "path traversal",
			archive: func(t *testing.T) []byte {
				return archiveWith(t, archiveEntry{name: "../bastion", data: []byte("evil")})
			},
			want: "unsafe path",
		},
		{
			name: "oversized binary",
			archive: func(t *testing.T) []byte {
				return archiveWith(t, archiveEntry{name: "bastion", data: bytes.Repeat([]byte("x"), 64)})
			},
			cfg:  func(cfg *SelfUpdateConfig) { cfg.MaxBinaryBytes = 16 },
			want: "limit",
		},
		{
			name: "oversized archive",
			archive: func(t *testing.T) []byte {
				return archiveWith(t, archiveEntry{name: "bastion", data: []byte("new binary")})
			},
			cfg:  func(cfg *SelfUpdateConfig) { cfg.MaxArchiveBytes = 16 },
			want: "limit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := newTarget(t)
			archive := tc.archive(t)
			server := newReleaseServer(t, archive, sumOf(archive))

			var out bytes.Buffer
			cfg := selfUpdateConfig(t, server, target, &out)
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}

			err := SelfUpdate(context.Background(), cfg)
			if err == nil {
				t.Fatal("SelfUpdate succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			assertFileContents(t, target, "old binary")
			assertNoTempFiles(t, filepath.Dir(target))

			// The traversal entry must not appear next to the target directory.
			if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(target)), "bastion")); err == nil {
				t.Error("archive wrote outside the target directory")
			}
		})
	}
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary target
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", path, data, want)
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	leftovers, err := filepath.Glob(filepath.Join(dir, ".bastion-update-*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}
