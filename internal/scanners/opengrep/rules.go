package opengrep

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// rulesTopDir is the single top-level directory in the pinned tarball.
const rulesTopDir = "opengrep-rules-" + rulesCommit

// skipRuleDir names directories that hold no rules bastion should load:
// upstream tests and fixtures, and the stats scripts' YAML data.
var skipRuleDir = map[string]bool{
	"test":     true,
	"tests":    true,
	"testdata": true,
	"fixture":  true,
	"fixtures": true,
	"stats":    true,
}

// extractRules unpacks the rule files of a pinned rules tarball into dst.
//
// The archive is untrusted: absolute paths, parent segments, symlinks and hard
// links are rejected; every entry must sit below the pinned top directory; and
// only .yaml/.yml files are written, so a crafted archive cannot write outside
// dst or install arbitrary content. Dot-directories (such as .github) and
// upstream test, fixture and stats directories are skipped because their YAML
// is not a rule set.
func extractRules(archivePath, dst string) error {
	file, err := os.Open(archivePath) //nolint:gosec // path comes from the module download.
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("read archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	reader := tar.NewReader(gz)
	var total int64
	files := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}

		// PAX metadata headers (the codeload archive carries a
		// pax_global_header) are not files and are skipped before any path
		// check.
		if header.Typeflag == tar.TypeXHeader || header.Typeflag == tar.TypeXGlobalHeader {
			continue
		}

		name := path.Clean(strings.ReplaceAll(header.Name, `\`, "/"))
		if name == "." {
			continue
		}
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("archive contains an unsafe path %q", header.Name)
		}
		if name != rulesTopDir && !strings.HasPrefix(name, rulesTopDir+"/") {
			return fmt.Errorf("archive entry %q is outside %s", header.Name, rulesTopDir)
		}
		rel := strings.TrimPrefix(name, rulesTopDir)
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			// Continue below.
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("archive entry %q is a link, which is not allowed", header.Name)
		default:
			return fmt.Errorf("archive entry %q has unsupported type %q", header.Name, header.Typeflag)
		}

		if !isRuleFile(rel) {
			continue
		}
		if header.Size < 0 || header.Size > maxRuleFileBytes {
			return fmt.Errorf("rule %q is %d bytes, limit is %d", header.Name, header.Size, maxRuleFileBytes)
		}
		total += header.Size
		if total > maxRulesTotalBytes {
			return fmt.Errorf("rule set exceeds the %d byte limit", maxRulesTotalBytes)
		}
		if !filepath.IsLocal(filepath.FromSlash(rel)) {
			return fmt.Errorf("archive entry %q is not a local path", header.Name)
		}

		target := filepath.Join(dst, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return fmt.Errorf("create rule directory: %w", err)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) //nolint:gosec // target is below dst.
		if err != nil {
			return fmt.Errorf("create rule file: %w", err)
		}
		written, copyErr := io.Copy(out, io.LimitReader(reader, header.Size))
		closeErr := out.Close()
		switch {
		case copyErr != nil:
			return fmt.Errorf("write rule file: %w", copyErr)
		case written != header.Size:
			return fmt.Errorf("rule file %q is truncated", header.Name)
		case closeErr != nil:
			return fmt.Errorf("close rule file: %w", closeErr)
		}
		files++
	}
	if files == 0 {
		return errors.New("archive contains no rule files")
	}
	return nil
}

// isRuleFile reports whether a relative archive path is a rule file bastion
// should extract: a .yaml/.yml file outside dot-directories, test/fixture
// directories and the stats directory.
func isRuleFile(rel string) bool {
	ext := strings.ToLower(path.Ext(rel))
	if ext != ".yaml" && ext != ".yml" {
		return false
	}
	segments := strings.Split(rel, "/")
	for i, segment := range segments {
		if strings.HasPrefix(segment, ".") {
			return false
		}
		// stats sits at the archive root.
		if i == 0 && skipRuleDir[segment] {
			return false
		}
		if i < len(segments)-1 && skipRuleDir[segment] {
			return false
		}
	}
	return true
}
