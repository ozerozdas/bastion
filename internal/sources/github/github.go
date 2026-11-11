// Package github provides a Source for GitHub repositories. A target ref is
// "owner/repo@sha": the commit is downloaded as a gzipped tarball (ADR-005) and
// unpacked into a temporary workspace whose top-level "owner-repo-sha/"
// directory is stripped.
//
// Downloads carry the connection's token, so neither the source nor its errors
// ever name a URL: messages and log lines mention owner/repo@sha only.
package github

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/ozerozdas/bastion/internal/sources"
)

const (
	// DefaultMaxExtractBytes caps the bytes one workspace may hold (ADR-005).
	DefaultMaxExtractBytes int64 = 2 << 30
	// DefaultMaxFiles caps the number of regular files one workspace may hold
	// (ADR-005).
	DefaultMaxFiles = 200_000
)

// Downloader fetches the compressed tarball of one commit, the way
// internal/connections/github's Client does. Tests inject a fake so no unit
// test reaches the network (§9.5).
type Downloader interface {
	Tarball(ctx context.Context, owner, name, sha string) (io.ReadCloser, error)
}

// Options configure a Source.
type Options struct {
	// WorkspacesDir is the base directory for extracted workspaces, normally
	// <cache>/workspaces. Fetch creates it when it is missing.
	WorkspacesDir string
	// KeepWorkspace leaves the extracted directory on disk after Close. It
	// backs the --keep-workspace flag (spec §4.4).
	KeepWorkspace bool
	// MaxExtractBytes caps the bytes written to one workspace. Zero means
	// DefaultMaxExtractBytes.
	MaxExtractBytes int64
	// MaxFiles caps the number of regular files written to one workspace.
	// Zero means DefaultMaxFiles.
	MaxFiles int
	// Logger receives one extraction summary per fetch and a warning when the
	// archive held entries that cannot be unpacked. Nil means slog.Default().
	Logger *slog.Logger
}

// Source fetches repository targets from GitHub. It is safe for concurrent
// use.
type Source struct {
	dl       Downloader
	base     string
	keep     bool
	maxBytes int64
	maxFiles int
	log      *slog.Logger
}

// New returns a Source that downloads through dl and unpacks into
// opts.WorkspacesDir.
func New(dl Downloader, opts Options) (*Source, error) {
	if dl == nil {
		return nil, errors.New("github: downloader is required")
	}
	if strings.TrimSpace(opts.WorkspacesDir) == "" {
		return nil, errors.New("github: workspaces directory is required")
	}
	maxBytes := opts.MaxExtractBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxExtractBytes
	}
	maxFiles := opts.MaxFiles
	if maxFiles <= 0 {
		maxFiles = DefaultMaxFiles
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Source{
		dl:       dl,
		base:     opts.WorkspacesDir,
		keep:     opts.KeepWorkspace,
		maxBytes: maxBytes,
		maxFiles: maxFiles,
		log:      logger,
	}, nil
}

// Kind reports that this source handles repository targets.
func (*Source) Kind() sources.TargetKind { return sources.KindRepo }

// Fetch downloads and extracts t.Ref into a new directory under the workspaces
// base. On any error the partial directory is removed, so a failed fetch leaves
// nothing behind.
func (s *Source) Fetch(ctx context.Context, t sources.Target) (*sources.Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.Kind != sources.KindRepo {
		return nil, fmt.Errorf("github: unsupported target kind %q", t.Kind)
	}
	owner, name, sha, err := parseRef(t.Ref)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(s.base, 0o700); err != nil {
		return nil, fmt.Errorf("github: create workspaces directory: %w", err)
	}
	dir, err := os.MkdirTemp(s.base, "repo-")
	if err != nil {
		return nil, fmt.Errorf("github: create workspace: %w", err)
	}
	fail := func(err error) (*sources.Workspace, error) {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("github: fetch %s: %w", t.Ref, err)
	}

	body, err := s.dl.Tarball(ctx, owner, name, sha)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = body.Close() }()

	stats, err := extract(ctx, dir, body, s.maxBytes, s.maxFiles)
	if err != nil {
		return fail(err)
	}

	s.log.Debug("github: extracted workspace", "repo", t.Ref, "files", stats.Files, "bytes", stats.Bytes)
	if stats.Symlinks > 0 || stats.Hardlinks > 0 || stats.Special > 0 {
		s.log.Warn("github: skipped archive entries that are not regular files or directories",
			"repo", t.Ref,
			"symlinks", stats.Symlinks,
			"hardlinks", stats.Hardlinks,
			"special", stats.Special,
		)
	}

	cleanup := func() error {
		if s.keep {
			return nil
		}
		return os.RemoveAll(dir)
	}
	return &sources.Workspace{Dir: dir, Cleanup: cleanup}, nil
}

// extractStats counts what one extraction materialized and skipped.
type extractStats struct {
	Files     int
	Bytes     int64
	Symlinks  int
	Hardlinks int
	Special   int
}

// extract unpacks the gzipped tarball in r into dir. Only regular files and
// directories are written; every other entry type is skipped and counted.
func extract(ctx context.Context, dir string, r io.Reader, maxBytes int64, maxFiles int) (extractStats, error) {
	var stats extractStats

	// Wrapping the stream, not just the entry loop, makes a cancel interrupt a
	// large file copy and a stalled download alike.
	gz, err := gzip.NewReader(contextReader{ctx: ctx, r: r})
	if err != nil {
		return stats, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	// os.Root keeps every write inside dir even if a name slips past
	// archivePath.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return stats, fmt.Errorf("open workspace: %w", err)
	}
	defer func() { _ = root.Close() }()

	tr := tar.NewReader(gz)
	for {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return stats, nil
		}
		if err != nil {
			return stats, fmt.Errorf("read tar entry: %w", err)
		}

		rel, err := archivePath(hdr.Name)
		if err != nil {
			return stats, err
		}
		if rel == "" {
			continue // GitHub's single top-level directory.
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(rel, 0o755); err != nil {
				return stats, fmt.Errorf("create directory %s: %w", rel, err)
			}
		case tar.TypeReg:
			if stats.Files >= maxFiles {
				return stats, fmt.Errorf("archive holds more than %d files", maxFiles)
			}
			if hdr.Size > maxBytes-stats.Bytes {
				return stats, fmt.Errorf("archive extracts to more than %s", limitLabel(maxBytes))
			}
			if err := writeFile(root, rel, tr, fileMode(hdr.Mode)); err != nil {
				return stats, err
			}
			stats.Files++
			stats.Bytes += hdr.Size
		case tar.TypeSymlink:
			stats.Symlinks++
		case tar.TypeLink:
			stats.Hardlinks++
		default:
			stats.Special++
		}
	}
}

// writeFile writes one regular file, creating its parent directories.
func writeFile(root *os.Root, rel string, r io.Reader, mode fs.FileMode) error {
	if parent := path.Dir(rel); parent != "." {
		if err := root.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", parent, err)
		}
	}
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create file %s: %w", rel, err)
	}
	// Chmod makes the mode independent of the process umask and of the mode of
	// a file an earlier entry already created.
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("set mode on %s: %w", rel, err)
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return fmt.Errorf("write file %s: %w", rel, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write file %s: %w", rel, err)
	}
	return nil
}

// archivePath turns a tar entry name into a path relative to the workspace.
// GitHub tarballs wrap everything in one "owner-repo-sha/" directory, which is
// stripped; the result is empty for that directory itself.
//
// Absolute names and names that climb out of the workspace are rejected after
// Clean, so the error can name the offending entry.
func archivePath(name string) (string, error) {
	cleaned := path.Clean(name)
	if cleaned == "." {
		return "", nil
	}
	if path.IsAbs(cleaned) {
		return "", fmt.Errorf("archive entry %q is an absolute path", name)
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("archive entry %q escapes the workspace", name)
	}
	_, rel, ok := strings.Cut(cleaned, "/")
	if !ok {
		return "", nil
	}
	return rel, nil
}

// fileMode maps an archive mode onto a safe workspace mode: 0o755 when any
// execute bit is set, 0o644 otherwise.
func fileMode(archiveMode int64) fs.FileMode {
	if archiveMode&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

// contextReader fails a read once ctx is done.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

// Read implements io.Reader.
func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// limitLabel formats a byte budget for an error message.
func limitLabel(n int64) string {
	const mib = 1 << 20
	if n >= mib && n%mib == 0 {
		return fmt.Sprintf("%d MiB", n/mib)
	}
	return fmt.Sprintf("%d bytes", n)
}

// parseRef splits and validates a repo target ref, "owner/repo@sha".
func parseRef(ref string) (owner, name, sha string, err error) {
	repo, sha, ok := strings.Cut(ref, "@")
	switch {
	case !ok:
		return "", "", "", refError(ref, "missing @sha")
	case strings.Contains(repo, "@") || strings.Contains(sha, "@"):
		return "", "", "", refError(ref, "more than one @")
	}

	owner, name, ok = strings.Cut(repo, "/")
	switch {
	case !ok:
		return "", "", "", refError(ref, "missing repository name")
	case strings.Contains(name, "/"):
		return "", "", "", refError(ref, "repository name contains /")
	}
	if err := validRepoPart("owner", owner); err != nil {
		return "", "", "", fmt.Errorf("github: invalid ref %q: %w", ref, err)
	}
	if err := validRepoPart("repository", name); err != nil {
		return "", "", "", fmt.Errorf("github: invalid ref %q: %w", ref, err)
	}
	if !isSHA(sha) {
		return "", "", "", refError(ref, "commit must be 40 hex characters")
	}
	return owner, name, strings.ToLower(sha), nil
}

// refError is the shared shape of a malformed-ref error.
func refError(ref, why string) error {
	return fmt.Errorf("github: invalid ref %q: %s (want owner/repo@sha)", ref, why)
}

// validRepoPart rejects owner and repository names that are empty or contain a
// character GitHub does not allow in them.
func validRepoPart(kind, value string) error {
	if value == "" || value == "." || value == ".." {
		return fmt.Errorf("invalid %s %q", kind, value)
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("invalid %s %q", kind, value)
		}
	}
	return nil
}

// isSHA reports whether s is a 40-character hexadecimal commit SHA.
func isSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
