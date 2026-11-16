package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// defaultDownloadBaseURL is the GitHub release download host.
	defaultDownloadBaseURL = "https://github.com/ozerozdas/bastion/releases/download"
	// maxChecksumsBytes caps checksums.txt; the real file is a few kilobytes.
	maxChecksumsBytes = 1 << 20
	// defaultMaxArchiveBytes caps the release archive. A bastion archive is
	// roughly 50 MB; the cap leaves room for growth without letting a hostile
	// response fill the disk.
	defaultMaxArchiveBytes = 256 << 20
	// defaultMaxBinaryBytes caps the extracted binary, independent of the
	// archive cap so a small archive cannot expand without bound. The binary is
	// large (~165 MB) because the web UI is embedded.
	defaultMaxBinaryBytes = 512 << 20
	// downloadTimeout bounds a whole archive download. It is longer than the
	// release check's timeout because the archive is tens of megabytes.
	downloadTimeout = 2 * time.Minute
)

// SelfUpdateConfig configures SelfUpdate. Every zero value has a production
// default, so callers normally set only CurrentVersion and Out; tests override
// the rest.
type SelfUpdateConfig struct {
	CurrentVersion string
	// GOOS and GOARCH select the release asset; empty means the build target.
	GOOS   string
	GOARCH string

	// BaseURL overrides https://github.com, the release lookup host.
	BaseURL string
	// DownloadBaseURL overrides the release asset host, up to the tag:
	// <DownloadBaseURL>/<tag>/<asset>.
	DownloadBaseURL string
	// HTTPClient lets tests point at an httptest TLS server. Timeout and the
	// redirect policy are always replaced by this package.
	HTTPClient *http.Client
	// Executable resolves the running binary, the file that gets replaced.
	Executable func() (string, error)
	// MaxArchiveBytes and MaxBinaryBytes override the download caps; tests use
	// small values instead of building a 128 MiB archive.
	MaxArchiveBytes int64
	MaxBinaryBytes  int64

	// Check reports the current and latest version without installing.
	Check bool
	// Force allows updating from a development build, whose version has no
	// semver comparison to the latest release.
	Force bool
	// Out receives the command's messages.
	Out io.Writer
}

// SelfUpdate installs the latest release over the running binary. It never
// modifies a Homebrew install and never writes on Windows; both print the
// command or link the user needs. A failed download, checksum or write leaves
// the old binary untouched.
func SelfUpdate(ctx context.Context, cfg SelfUpdateConfig) error {
	out := cfg.Out
	if out == nil {
		out = os.Stdout
	}
	goos := cfg.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := cfg.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	exe := cfg.Executable
	if exe == nil {
		exe = os.Executable
	}
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	downloadBase := strings.TrimRight(cfg.DownloadBaseURL, "/")
	if downloadBase == "" {
		downloadBase = defaultDownloadBaseURL
	}
	archiveLimit := cfg.MaxArchiveBytes
	if archiveLimit <= 0 {
		archiveLimit = defaultMaxArchiveBytes
	}
	binaryLimit := cfg.MaxBinaryBytes
	if binaryLimit <= 0 {
		binaryLimit = defaultMaxBinaryBytes
	}

	current := cfg.CurrentVersion
	target, exeErr := resolveExecutable(exe)

	// A dev build has no release version to compare against, so it is not
	// replaced unless the user explicitly forces it. --check changes nothing
	// and stays available.
	if !cfg.Check {
		if !isReleaseVersion(current) && !cfg.Force {
			return fmt.Errorf(
				"bastion %s is a development build, not a release; self-update is disabled (rebuild from source, or pass --force)",
				displayVersion(current))
		}
		if exeErr == nil && installCommandFor(target, goos) == brewCommand {
			_, err := fmt.Fprintf(out, "Homebrew install detected; update with:\n  %s\n", brewCommand)
			return err
		}
		if goos != "windows" && exeErr != nil {
			return fmt.Errorf("resolve executable path: %w", exeErr)
		}
	}

	if err := requireHTTPS(baseURL); err != nil {
		return err
	}

	client := &http.Client{}
	if cfg.HTTPClient != nil {
		*client = *cfg.HTTPClient
	}
	client.Timeout = downloadTimeout
	latestClient := *client
	latestClient.Timeout = requestTimeout
	latestClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		// The Location header carries the tag; following the redirect would
		// download a page for no benefit.
		return http.ErrUseLastResponse
	}

	latest, err := fetchLatestTag(ctx, &latestClient, baseURL, current)
	if err != nil {
		return fmt.Errorf("check the latest release: %w", err)
	}

	if cfg.Check {
		_, err := fmt.Fprintf(out, "current: %s\nlatest:  %s\n", displayVersion(current), displayVersion(latest))
		return err
	}

	if goos == "windows" {
		_, err := fmt.Fprintf(out, "Windows builds are not replaced in place; download the release:\n  %s\n",
			releasesTagBase+latest)
		return err
	}

	if validVersion(current) && !newerThan(current, latest) {
		_, err := fmt.Fprintf(out, "bastion %s is up to date\n", displayVersion(current))
		return err
	}

	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat %s: %w", target, err)
	}

	plain := strings.TrimPrefix(normalizeVersion(latest), "v")
	asset := fmt.Sprintf("bastion_%s_%s_%s.tar.gz", plain, goos, goarch)
	releaseBase := downloadBase + "/" + latest
	archiveURL := releaseBase + "/" + asset
	checksumsURL := releaseBase + "/checksums.txt"
	for _, rawURL := range []string{downloadBase, archiveURL, checksumsURL} {
		if err := requireHTTPS(rawURL); err != nil {
			return err
		}
	}

	userAgent := "bastion/" + current
	archivePath, archiveSum, err := downloadToTemp(ctx, client, archiveURL, userAgent, archiveLimit)
	if err != nil {
		return fmt.Errorf("download %s: %w", asset, err)
	}
	defer func() { _ = os.Remove(archivePath) }()

	checksums, err := fetchBytes(ctx, client, checksumsURL, userAgent, maxChecksumsBytes)
	if err != nil {
		return fmt.Errorf("download checksums.txt: %w", err)
	}
	expected, ok := checksumFor(checksums, asset)
	if !ok {
		return fmt.Errorf("%s is not listed in checksums.txt", asset)
	}
	if !strings.EqualFold(expected, archiveSum) {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", asset, expected, archiveSum)
	}

	// The temporary file lives next to the target, so the rename that replaces
	// the binary stays on one filesystem and is atomic.
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".bastion-update-*")
	if err != nil {
		return permissionHint(fmt.Errorf("create a temporary file in %s: %w", dir, err))
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	mode := info.Mode().Perm()
	if mode == 0 {
		mode = 0o755
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return permissionHint(fmt.Errorf("set mode on %s: %w", tmpPath, err))
	}
	if err := extractBinary(archivePath, tmp, binaryLimit); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("flush %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return permissionHint(fmt.Errorf("replace %s: %w", target, err))
	}

	_, err = fmt.Fprintf(out, "updated %s → %s\n", displayVersion(current), displayVersion(latest))
	return err
}

// displayVersion gives a release its "v" prefix and leaves a non-semver build
// label (`dev`) as it is.
func displayVersion(v string) string {
	if validVersion(v) {
		return normalizeVersion(v)
	}
	return strings.TrimSpace(v)
}

// resolveExecutable returns the running binary with symlinks resolved, so the
// update replaces the real file and not a link in a Homebrew or package
// manager's directory.
func resolveExecutable(exe func() (string, error)) (string, error) {
	path, err := exe()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return path, nil
}

// requireHTTPS rejects any non-HTTPS download URL. The production defaults are
// HTTPS; the check keeps an injected or tampered base URL from downgrading the
// archive download.
func requireHTTPS(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse %q: %w", rawURL, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("refusing non-HTTPS update URL %q", rawURL)
	}
	return nil
}

// downloadToTemp streams a response into a temporary file and returns its path
// and SHA-256. The file is the caller's to remove.
func downloadToTemp(ctx context.Context, client *http.Client, rawURL, userAgent string, limit int64) (string, string, error) {
	body, err := get(ctx, client, rawURL, userAgent)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = body.Close() }()

	file, err := os.CreateTemp("", "bastion-update-*.tar.gz")
	if err != nil {
		return "", "", err
	}
	name := file.Name()

	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(body, limit+1))
	closeErr := file.Close()
	switch {
	case copyErr != nil:
		_ = os.Remove(name)
		return "", "", copyErr
	case written > limit:
		_ = os.Remove(name)
		return "", "", fmt.Errorf("archive exceeds the %d byte limit", limit)
	case closeErr != nil:
		_ = os.Remove(name)
		return "", "", closeErr
	}
	return name, hex.EncodeToString(hasher.Sum(nil)), nil
}

// fetchBytes reads a small response into memory, refusing anything over limit.
func fetchBytes(ctx context.Context, client *http.Client, rawURL, userAgent string, limit int64) ([]byte, error) {
	body, err := get(ctx, client, rawURL, userAgent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()

	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds the %d byte limit", limit)
	}
	return data, nil
}

// get performs one GET and returns the body on a 200. The caller closes it.
func get(ctx context.Context, client *http.Client, rawURL, userAgent string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("answered %s", resp.Status)
	}
	return resp.Body, nil
}

// checksumFor finds the SHA-256 for name in a goreleaser checksums.txt, whose
// lines are "<sha256>  <name>" (a binary-mode "*name" is accepted too).
func checksumFor(data []byte, name string) (string, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.TrimPrefix(fields[1], "*") == name {
			return fields[0], true
		}
	}
	return "", false
}

// extractBinary writes the archive's `bastion` entry to dst. Other entries are
// ignored and a path that escapes the archive root is rejected, so a crafted
// archive cannot write outside the target directory.
func extractBinary(archivePath string, dst *os.File, limit int64) error {
	file, err := os.Open(archivePath) //nolint:gosec // path comes from os.CreateTemp, not user input
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer func() { _ = file.Close() }()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("read archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}

		name := path.Clean(strings.ReplaceAll(header.Name, `\`, "/"))
		if name == "." {
			continue
		}
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("archive contains an unsafe path %q", header.Name)
		}
		if name != "bastion" {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return fmt.Errorf("archive entry %q is not a regular file", header.Name)
		}
		if header.Size > limit {
			return fmt.Errorf("binary in archive is %d bytes, limit is %d", header.Size, limit)
		}

		written, err := io.Copy(dst, io.LimitReader(reader, limit+1))
		if err != nil {
			return fmt.Errorf("extract binary: %w", err)
		}
		if written > limit {
			return fmt.Errorf("binary in archive exceeds the %d byte limit", limit)
		}
		return nil
	}
	return fmt.Errorf("bastion not found in archive")
}

// permissionHint adds the two ways out of a read-only install directory.
func permissionHint(err error) error {
	if !errors.Is(err, fs.ErrPermission) {
		return err
	}
	return fmt.Errorf("%w\nhint: retry with 'sudo bastion update', or reinstall with:\n  %s", err, installCommand)
}
