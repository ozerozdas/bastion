package opengrep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/testutil"
)

// goldenAsset is the asset the golden fixture was produced for.
func goldenAsset() findings.Asset {
	return findings.Asset{
		ID:          1,
		Kind:        findings.AssetKindPath,
		DisplayName: "fixture",
		Ref:         "/repo",
	}
}

func TestNormalizeGolden(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("testdata", "opengrep", "input.json"))
	if err != nil {
		t.Fatalf("read input: %v", err)
	}

	raw := &scanners.RawResult{
		Scanner:      Name,
		Version:      Version,
		WorkspaceDir: "/repo",
		Raw:          input,
	}
	fs, pkgs, err := NewScanner(nil).Normalize(raw, goldenAsset())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	testutil.AssertJSON(t, filepath.Join("testdata", "opengrep", "expected.json"), struct {
		Findings []findings.Finding `json:"findings"`
		Packages []findings.Package `json:"packages"`
	}{Findings: fs, Packages: pkgs})

	if len(raw.Warnings) != 1 || !strings.Contains(raw.Warnings[0], "skipped 1 result") {
		t.Fatalf("warnings = %v, want one skipped-result warning", raw.Warnings)
	}
}

func TestFingerprintStableAcrossLineShift(t *testing.T) {
	const first = `{"results":[{"check_id":"rules.python.eval","path":"/repo/app.py",
		"start":{"line":4},"extra":{"message":"eval","severity":"WARNING","lines":"return eval(x)"}}]}`
	const shifted = `{"results":[{"check_id":"rules.python.eval","path":"/repo/app.py",
		"start":{"line":40},"extra":{"message":"eval","severity":"WARNING","lines":"  return   eval(x) "}}]}`
	const changed = `{"results":[{"check_id":"rules.python.eval","path":"/repo/app.py",
		"start":{"line":4},"extra":{"message":"eval","severity":"WARNING","lines":"return eval(y)"}}]}`

	fingerprintOf := func(document string) string {
		t.Helper()
		fs, _, err := parse([]byte(document), "/repo", goldenAsset())
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(fs) != 1 {
			t.Fatalf("findings = %d, want 1", len(fs))
		}
		return fs[0].Fingerprint
	}

	if got, want := fingerprintOf(shifted), fingerprintOf(first); got != want {
		t.Errorf("fingerprint changed after a line shift: %s != %s", got, want)
	}
	if got, want := fingerprintOf(changed), fingerprintOf(first); got == want {
		t.Errorf("fingerprint did not change with the matched snippet: %s", got)
	}
}

func TestTitleIsTruncated(t *testing.T) {
	message := strings.Repeat("a", 500)
	document := fmt.Sprintf(`{"results":[{"check_id":"rules.python.eval","path":"/repo/app.py",
		"start":{"line":1},"extra":{"message":%q,"severity":"WARNING","lines":"eval(x)"}}]}`, message)
	fs, _, err := parse([]byte(document), "/repo", goldenAsset())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	runes := []rune(fs[0].Title)
	if len(runes) != maxTitleRunes+1 || !strings.HasSuffix(fs[0].Title, "…") {
		t.Fatalf("title length = %d, want %d plus an ellipsis", len(runes), maxTitleRunes+1)
	}
}

func TestParseCWE(t *testing.T) {
	tests := []struct {
		name     string
		metadata string
		want     []string
	}{
		{
			name:     "one string with its title",
			metadata: `"cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation"`,
			want:     []string{"CWE-79"},
		},
		{
			name:     "a list of strings",
			metadata: `"cwe": ["CWE-89: Improper Neutralization of Special Elements", "CWE-20: Improper Input Validation"]`,
			want:     []string{"CWE-20", "CWE-89"},
		},
		{
			name:     "no cwe metadata",
			metadata: `"category": "security"`,
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document := fmt.Sprintf(`{"results":[{"check_id":"rules.python.eval","path":"/repo/app.py",
				"start":{"line":1},"extra":{"message":"eval","severity":"WARNING","lines":"eval(x)",
				"metadata":{%s}}}]}`, tt.metadata)
			fs, _, err := parse([]byte(document), "/repo", goldenAsset())
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(fs) != 1 {
				t.Fatalf("findings = %d, want 1", len(fs))
			}
			if !slices.Equal(fs[0].CWE, tt.want) {
				t.Fatalf("cwe = %v, want %v", fs[0].CWE, tt.want)
			}
		})
	}
}

func TestParseSkipsEscapingPaths(t *testing.T) {
	document := `{"results":[
		{"check_id":"rules.a","path":"/repo/../outside.py","start":{"line":1},"extra":{"severity":"ERROR"}},
		{"check_id":"rules.b","path":"/etc/passwd","start":{"line":1},"extra":{"severity":"ERROR"}},
		{"check_id":"rules.c","path":"/repo/inside.py","start":{"line":1},"extra":{"severity":"ERROR"}}
	]}`
	fs, warnings, err := parse([]byte(document), "/repo", goldenAsset())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 1 || fs[0].Location != "inside.py:1" {
		t.Fatalf("findings = %+v, want only inside.py:1", fs)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "skipped 2 result") {
		t.Fatalf("warnings = %v, want two skipped results", warnings)
	}
}

func TestParseSeverity(t *testing.T) {
	tests := map[string]findings.Severity{
		"ERROR":    findings.SeverityHigh,
		"error":    findings.SeverityHigh,
		"WARNING":  findings.SeverityMedium,
		"INFO":     findings.SeverityLow,
		"CRITICAL": findings.SeverityUnknown,
		"":         findings.SeverityUnknown,
	}
	for input, want := range tests {
		if got := severityFromString(input); got != want {
			t.Errorf("severityFromString(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeEmptyRawWithWarning(t *testing.T) {
	fs, pkgs, err := NewScanner(nil).Normalize(&scanners.RawResult{
		Scanner:  Name,
		Warnings: []string{"opengrep timed out; results are partial"},
	}, goldenAsset())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(fs) != 0 || len(pkgs) != 0 {
		t.Fatalf("findings = %v, packages = %v, want none", fs, pkgs)
	}
}

func TestNormalizeRejectsMalformedJSON(t *testing.T) {
	_, _, err := NewScanner(nil).Normalize(&scanners.RawResult{
		Scanner:      Name,
		WorkspaceDir: "/repo",
		Raw:          []byte("{not json"),
	}, goldenAsset())
	if err == nil {
		t.Fatal("Normalize accepted malformed JSON")
	}
}

func TestChildEnvDropsSecrets(t *testing.T) {
	env := childEnv([]string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"TMPDIR=/tmp",
		"GITHUB_TOKEN=secret",
		"AWS_SECRET_ACCESS_KEY=secret",
		"BASTION_HMAC_KEY=secret",
		"HTTPS_PROXY=http://proxy",
	})
	joined := strings.Join(env, "\n")
	for _, allowed := range []string{"PATH=/usr/bin", "HOME=/home/user", "TMPDIR=/tmp"} {
		if !strings.Contains(joined, allowed) {
			t.Errorf("environment is missing %q", allowed)
		}
	}
	for _, secret := range []string{"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "BASTION_HMAC_KEY", "HTTPS_PROXY"} {
		if strings.Contains(joined, secret) {
			t.Errorf("environment leaked %s", secret)
		}
	}
}

// fakeModule stubs the downloaded module for the enabled/disabled tests.
type fakeModule struct {
	enabled bool
	raw     []byte
	err     error
}

func (f *fakeModule) Enabled() bool { return f.enabled }
func (f *fakeModule) Status() Status {
	return Status{Enabled: f.enabled, State: StateInstalled, Version: Version}
}
func (f *fakeModule) EnsureInstalled(context.Context) error { return f.err }
func (f *fakeModule) run(context.Context, string) (runOutput, error) {
	return runOutput{stdout: f.raw}, nil
}

func TestScannerSupportsOnlyEnabledSourceScans(t *testing.T) {
	document := []byte(`{"results":[{"check_id":"rules.python.eval","path":"/repo/app.py",
		"start":{"line":1},"extra":{"message":"eval","severity":"WARNING","lines":"eval(x)"}}]}`)

	disabled := &Scanner{module: &fakeModule{enabled: false, raw: document}}
	if disabled.Supports(sources.KindRepo) || disabled.Supports(sources.KindPath) {
		t.Fatal("disabled SAST supports source scans")
	}

	enabled := &Scanner{module: &fakeModule{enabled: true, raw: document}}
	if !enabled.Supports(sources.KindRepo) || !enabled.Supports(sources.KindPath) {
		t.Fatal("enabled SAST does not support source scans")
	}
	if enabled.Supports(sources.KindImage) {
		t.Fatal("SAST supports image scans")
	}
}

func TestEnabledScanIncludesSASTFindings(t *testing.T) {
	document := []byte(`{"results":[{"check_id":"rules.python.eval","path":"/repo/app.py",
		"start":{"line":1},"extra":{"message":"eval","severity":"WARNING","lines":"eval(x)"}}]}`)
	scanner := &Scanner{module: &fakeModule{enabled: true, raw: document}}

	raw, err := scanner.Scan(t.Context(), &sources.Workspace{Dir: "/repo"}, scanners.Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	fs, _, err := scanner.Normalize(raw, goldenAsset())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(fs) != 1 || fs[0].Type != findings.TypeSAST {
		t.Fatalf("findings = %+v, want one sast finding", fs)
	}
}

func TestDisabledScanExcludesSASTFindings(t *testing.T) {
	scanner := &Scanner{module: &fakeModule{enabled: false}}
	if scanner.Supports(sources.KindRepo) {
		t.Fatal("disabled SAST was included in a repository scan")
	}
}
