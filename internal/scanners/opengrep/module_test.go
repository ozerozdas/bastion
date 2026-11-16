package opengrep

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testBinary = "#!/bin/sh\necho opengrep\n"

// tarEntry is one file or link in a test archive.
type tarEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

// tarGz builds an in-memory gzipped tar archive.
func tarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     entry.name,
			Mode:     0o644,
			Size:     int64(len(entry.body)),
			Typeflag: typeflag,
			Linkname: entry.linkname,
		}
		if typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write tar header %s: %v", entry.name, err)
		}
		if typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(entry.body)); err != nil {
				t.Fatalf("write tar body %s: %v", entry.name, err)
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

// rulesArchive is a valid pinned-shape archive with rule and non-rule files.
func rulesArchive(t *testing.T) []byte {
	t.Helper()
	return tarGz(t, []tarEntry{
		{name: rulesTopDir + "/", typeflag: tar.TypeDir},
		{name: rulesTopDir + "/python/lang/security/eval.yaml", body: "rules:\n- id: eval\n"},
		{name: rulesTopDir + "/.github/workflows/lint.yml", body: "name: lint\n"},
		{name: rulesTopDir + "/stats/table.yml", body: "rows: []\n"},
		{name: rulesTopDir + "/python/lang/security/tests/eval.yaml", body: "test: true\n"},
		{name: rulesTopDir + "/README.md", body: "not a rule\n"},
	})
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// testServer serves a binary and a rules archive at the pinned asset paths.
func testServer(t *testing.T, binary, rules []byte) *httptest.Server {
	t.Helper()
	handler := http.NewServeMux()
	handler.HandleFunc("/opengrep_osx_arm64", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(binary)
	})
	handler.HandleFunc("/rules.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(rules)
	})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}

// testService wires a service against the test server with test digests.
func testService(t *testing.T, server *httptest.Server, binary, rules []byte) *Service {
	t.Helper()
	return New(Config{
		ModulesDir:      t.TempDir(),
		GOOS:            "darwin",
		GOARCH:          "arm64",
		DownloadBaseURL: server.URL,
		RulesURL:        server.URL + "/rules.tar.gz",
		HTTPClient:      server.Client(),
		BinarySHA256:    sha256Hex(binary),
		RulesSHA256:     sha256Hex(rules),
	})
}

func TestInstallDownloadsBinaryAndRules(t *testing.T) {
	binary := []byte(testBinary)
	rules := rulesArchive(t)
	service := testService(t, testServer(t, binary, rules), binary, rules)

	if err := service.Install(t.Context()); err != nil {
		t.Fatalf("Install: %v", err)
	}

	status := service.Status()
	if status.State != StateInstalled {
		t.Fatalf("status = %+v, want installed", status)
	}
	if status.Version != Version {
		t.Fatalf("version = %q, want %q", status.Version, Version)
	}

	got, err := os.ReadFile(service.BinaryPath())
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if string(got) != string(binary) {
		t.Fatalf("binary = %q, want %q", got, binary)
	}
	info, err := os.Stat(service.BinaryPath())
	if err != nil {
		t.Fatalf("stat binary: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("binary mode = %o, want 755", info.Mode().Perm())
	}

	if _, err := os.Stat(filepath.Join(service.RulesDir(), "python", "lang", "security", "eval.yaml")); err != nil {
		t.Fatalf("rule file missing: %v", err)
	}
	for _, excluded := range []string{
		filepath.Join(service.RulesDir(), ".github", "workflows", "lint.yml"),
		filepath.Join(service.RulesDir(), "stats", "table.yml"),
		filepath.Join(service.RulesDir(), "python", "lang", "security", "tests", "eval.yaml"),
		filepath.Join(service.RulesDir(), "README.md"),
	} {
		if _, err := os.Stat(excluded); !os.IsNotExist(err) {
			t.Errorf("%s was extracted, want it skipped", excluded)
		}
	}

	entries, err := os.ReadDir(service.Dir())
	if err != nil {
		t.Fatalf("read module dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			t.Errorf("temporary file %q was left behind", entry.Name())
		}
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	binary := []byte(testBinary)
	rules := rulesArchive(t)
	server := testServer(t, binary, rules)
	service := testService(t, server, binary, rules)

	if err := service.Install(t.Context()); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	if err := service.Install(t.Context()); err != nil {
		t.Fatalf("second Install: %v", err)
	}
}

func TestInstallRefusesCorruptedBinary(t *testing.T) {
	binary := []byte(testBinary)
	rules := rulesArchive(t)
	service := testService(t, testServer(t, binary, rules), binary, rules)
	service.binarySHA = strings.Repeat("0", 64)

	err := service.Install(t.Context())
	if err == nil {
		t.Fatal("Install succeeded with a corrupted binary")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v, want a checksum mismatch", err)
	}
	if _, statErr := os.Stat(service.BinaryPath()); !os.IsNotExist(statErr) {
		t.Fatalf("corrupted binary was kept: %v", statErr)
	}
	if _, statErr := os.Stat(service.RulesDir()); !os.IsNotExist(statErr) {
		t.Fatalf("rules were installed despite the failed binary: %v", statErr)
	}
	if status := service.Status(); status.State != StateNotInstalled {
		t.Fatalf("status = %+v, want not installed", status)
	}
}

func TestInstallRefusesCorruptedRules(t *testing.T) {
	binary := []byte(testBinary)
	rules := rulesArchive(t)
	service := testService(t, testServer(t, binary, rules), binary, rules)
	service.rulesSHA = strings.Repeat("0", 64)

	err := service.Install(t.Context())
	if err == nil {
		t.Fatal("Install succeeded with corrupted rules")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v, want a checksum mismatch", err)
	}
	if _, statErr := os.Stat(service.BinaryPath()); !os.IsNotExist(statErr) {
		t.Fatalf("binary was installed despite the failed rules: %v", statErr)
	}
}

func TestInstallUnsupportedPlatform(t *testing.T) {
	service := New(Config{ModulesDir: t.TempDir(), GOOS: "plan9", GOARCH: "mips"})
	err := service.Install(t.Context())
	if err == nil {
		t.Fatal("Install succeeded on an unsupported platform")
	}
	if !strings.Contains(err.Error(), "no pinned binary for plan9/mips") {
		t.Fatalf("error = %v, want an unsupported-platform message", err)
	}
}

func TestExtractRulesRejectsTraversal(t *testing.T) {
	archive := tarGz(t, []tarEntry{
		{name: rulesTopDir + "/../../evil.yaml", body: "rules: []\n"},
	})
	path := filepath.Join(t.TempDir(), "rules.tar.gz")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	dst := t.TempDir()
	err := extractRules(path, dst)
	if err == nil {
		t.Fatal("extractRules accepted a traversal entry")
	}
	if !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("error = %v, want an unsafe-path error", err)
	}
}

func TestExtractRulesRejectsSymlink(t *testing.T) {
	archive := tarGz(t, []tarEntry{
		{name: rulesTopDir + "/link.yaml", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
	})
	path := filepath.Join(t.TempDir(), "rules.tar.gz")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	dst := t.TempDir()
	err := extractRules(path, dst)
	if err == nil {
		t.Fatal("extractRules accepted a symlink")
	}
	if !strings.Contains(err.Error(), "link") {
		t.Fatalf("error = %v, want a link error", err)
	}
}

func TestExtractRulesRejectsHardlink(t *testing.T) {
	archive := tarGz(t, []tarEntry{
		{name: rulesTopDir + "/link.yaml", typeflag: tar.TypeLink, linkname: rulesTopDir + "/python/eval.yaml"},
	})
	path := filepath.Join(t.TempDir(), "rules.tar.gz")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	if err := extractRules(path, t.TempDir()); err == nil {
		t.Fatal("extractRules accepted a hardlink")
	}
}

func TestStatusChecksumBad(t *testing.T) {
	binary := []byte(testBinary)
	rules := rulesArchive(t)
	service := testService(t, testServer(t, binary, rules), binary, rules)
	if err := service.Install(t.Context()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := os.WriteFile(service.BinaryPath(), []byte("tampered"), 0o600); err != nil {
		t.Fatalf("tamper binary: %v", err)
	}

	status := service.Status()
	if status.State != StateChecksumBad {
		t.Fatalf("status = %+v, want checksum bad", status)
	}
	if status.Error == "" {
		t.Fatal("checksum-bad status carries no error")
	}
}

func TestEnabledDefaultsOff(t *testing.T) {
	service := New(Config{DataDir: t.TempDir(), ModulesDir: t.TempDir()})
	if service.Enabled() {
		t.Fatal("SAST is enabled on a fresh data directory")
	}
	status := service.Status()
	if status.Enabled {
		t.Fatal("status reports enabled on a fresh data directory")
	}
	if status.State != StateNotInstalled {
		t.Fatalf("state = %q, want not_installed", status.State)
	}
}

func TestSetEnabledStartsOneInstall(t *testing.T) {
	var calls int
	service := New(Config{
		DataDir:    t.TempDir(),
		ModulesDir: t.TempDir(),
		Spawn:      func(f func()) { f() },
		Install: func(context.Context) error {
			calls++
			return nil
		},
	})
	if err := service.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if calls != 1 {
		t.Fatalf("install calls = %d, want 1", calls)
	}
	if !service.Enabled() {
		t.Fatal("setting was not stored")
	}
}

func TestSetEnabledRecordsInstallFailure(t *testing.T) {
	want := errors.New("download refused")
	service := New(Config{
		DataDir:    t.TempDir(),
		ModulesDir: t.TempDir(),
		Spawn:      func(f func()) { f() },
		Install:    func(context.Context) error { return want },
	})
	if err := service.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	status := service.Status()
	if status.InstallError != want.Error() {
		t.Fatalf("install error = %q, want %q", status.InstallError, want)
	}
	if status.Installing {
		t.Fatal("status still reports installing")
	}
	if status.State != StateNotInstalled {
		t.Fatalf("state = %q, want not_installed", status.State)
	}
}

func TestSetEnabledOffDoesNotInstall(t *testing.T) {
	var calls int
	service := New(Config{
		DataDir:    t.TempDir(),
		ModulesDir: t.TempDir(),
		Spawn:      func(f func()) { f() },
		Install: func(context.Context) error {
			calls++
			return nil
		},
	})
	if err := service.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if calls != 0 {
		t.Fatalf("install calls = %d, want 0", calls)
	}
}

func TestStatusHashesBinaryEveryCall(t *testing.T) {
	binary := []byte(testBinary)
	rules := rulesArchive(t)
	service := testService(t, testServer(t, binary, rules), binary, rules)
	if err := service.Install(t.Context()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	info, err := os.Stat(service.BinaryPath())
	if err != nil {
		t.Fatalf("stat binary: %v", err)
	}
	// Same size and mtime as the installed file: only the contents differ, so
	// a size-and-mtime marker would call this installed.
	tampered := []byte("#!/bin/sh\necho hacked!!\n")
	if len(tampered) != len(binary) {
		t.Fatalf("test binary is %d bytes, tampered copy is %d", len(binary), len(tampered))
	}
	if err := os.WriteFile(service.BinaryPath(), tampered, 0o600); err != nil {
		t.Fatalf("tamper binary: %v", err)
	}
	if err := os.Chtimes(service.BinaryPath(), info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("restore mtime: %v", err)
	}

	if status := service.Status(); status.State != StateChecksumBad {
		t.Fatalf("status = %+v, want checksum bad", status)
	}
}

func TestDownloadRefusesNonHTTPSRedirect(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("downgraded"))
	}))
	t.Cleanup(plain.Close)

	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // the redirect target is the test server's own URL.
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	service := New(Config{
		ModulesDir:      t.TempDir(),
		GOOS:            "darwin",
		GOARCH:          "arm64",
		DownloadBaseURL: redirect.URL,
		RulesURL:        redirect.URL + "/rules.tar.gz",
		HTTPClient:      redirect.Client(),
		BinarySHA256:    strings.Repeat("0", 64),
		RulesSHA256:     strings.Repeat("0", 64),
	})
	err := service.Install(t.Context())
	if err == nil {
		t.Fatal("Install followed a non-HTTPS redirect")
	}
	if !strings.Contains(err.Error(), "non-HTTPS") {
		t.Fatalf("error = %v, want a non-HTTPS refusal", err)
	}
}

func TestEnsureInstalledStopsWaitingOnContext(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	service := New(Config{
		DataDir:    t.TempDir(),
		ModulesDir: t.TempDir(),
		Install: func(context.Context) error {
			close(started)
			<-release
			return nil
		},
	})

	first := make(chan error, 1)
	go func() { first <- service.EnsureInstalled(context.Background()) }()
	<-started
	if !service.Status().Installing {
		t.Fatal("status does not report the in-flight download")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.EnsureInstalled(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}

	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first EnsureInstalled: %v", err)
	}
}
