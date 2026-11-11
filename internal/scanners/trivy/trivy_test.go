package trivy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func TestResolveTarget(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		dir     string
		wantErr string
	}{
		{name: "empty", dir: "", wantErr: "target dir is required"},
		{name: "missing", dir: filepath.Join(dir, "nope"), wantErr: "stat target"},
		{name: "file", dir: file, wantErr: "is not a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveTarget(tt.dir)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got error %v, want one containing %q", err, tt.wantErr)
			}
		})
	}

	got, err := resolveTarget(dir)
	if err != nil {
		t.Fatalf("resolveTarget(%q): %v", dir, err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("resolveTarget returned %q, want an absolute path", got)
	}
}

// TestScanArgs pins the scanner set: secrets belong to Gitleaks, not Trivy.
func TestScanArgs(t *testing.T) {
	args := scanArgs("/tmp/cache", []string{"/scan/testdata", "/scan/other/fixtures"})

	valueOf := func(name string) (string, bool) {
		i := slices.Index(args, name)
		if i < 0 || i+1 >= len(args) {
			return "", false
		}
		return args[i+1], true
	}

	valuesOf := func(name string) []string {
		var values []string
		for i, arg := range args {
			if arg == name && i+1 < len(args) {
				values = append(values, args[i+1])
			}
		}
		return values
	}

	cacheDir, ok := valueOf("--cache-dir")
	if !ok || cacheDir != "/tmp/cache" {
		t.Fatalf("--cache-dir = %q (found %v), want /tmp/cache", cacheDir, ok)
	}
	scanners, ok := valueOf("--scanners")
	if !ok {
		t.Fatal("--scanners missing")
	}
	for _, want := range []string{"vuln", "misconfig", "license"} {
		if !slices.Contains(strings.Split(scanners, ","), want) {
			t.Fatalf("--scanners %q does not enable %q", scanners, want)
		}
	}
	if slices.Contains(strings.Split(scanners, ","), "secret") {
		t.Fatalf("--scanners %q must not enable Trivy's secret scanner", scanners)
	}
	if format, _ := valueOf("--format"); format != "json" {
		t.Fatalf("--format = %q, want json", format)
	}
	if got, want := valuesOf("--skip-dirs"), []string{"/scan/testdata", "/scan/other/fixtures"}; !slices.Equal(got, want) {
		t.Fatalf("--skip-dirs = %v, want %v", got, want)
	}
}

// TestSkipPatterns pins the semantics of --skip-dirs for Trivy: an entry
// relative to the scan root becomes an absolute path under that root, which
// Trivy's walker turns back into the root-relative path it matches on. Passing
// the bare relative entry would make Trivy resolve it against the process
// working directory instead.
func TestSkipPatterns(t *testing.T) {
	target := t.TempDir()

	got, err := skipPatterns(target, []string{"testdata", "**/node_modules/"})
	if err != nil {
		t.Fatalf("skipPatterns: %v", err)
	}
	want := []string{
		filepath.Join(target, "testdata"),
		filepath.Join(target, "**", "node_modules"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("skipPatterns = %v, want %v", got, want)
	}
	if rel := walker.NewFS().BuildSkipPaths(target, got); !slices.Equal(rel, []string{"testdata", "**/node_modules"}) {
		t.Fatalf("Trivy walk paths = %v, want the paths relative to the scan root", rel)
	}

	if patterns, err := skipPatterns(target, nil); err != nil || patterns != nil {
		t.Fatalf("skipPatterns(nil) = %v, %v, want no patterns", patterns, err)
	}
	for _, dir := range []string{"", ".", "/abs", "../up", "testdata/../.."} {
		if _, err := skipPatterns(target, []string{dir}); err == nil {
			t.Errorf("skipPatterns accepted %q", dir)
		}
	}
}
