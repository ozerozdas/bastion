// Package gitleaks runs Gitleaks as a library against a local working tree.
//
// It is the only package in bastion allowed to import
// github.com/zricethezav/gitleaks/v8 (PROJECT_SPEC.md §4.2). Findings leave
// this package already redacted: a caller never sees Gitleaks' raw Secret or
// Match fields, only the redacted match and an HMAC (§4.3).
package gitleaks

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
	glregexp "github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Version is the Gitleaks release this adapter is built against. It must match
// the github.com/zricethezav/gitleaks/v8 version pinned in go.mod.
const Version = "8.30.1"

func init() {
	// Gitleaks logs through a package-level zerolog logger that writes to
	// stderr (its logging package init). Bastion owns its own logging, and a
	// verbose gitleaks log could echo fragments of scanned content, so silence
	// it for the whole process. This runs after gitleaks' init, so it wins.
	logging.Logger = zerolog.Nop()

	// Parse the default config once, at program start, before any scan can
	// run: Config.Translate reads the process-global Viper, which Trivy resets
	// during its scans (ADR-001). Doing it here removes that data race.
	defaultCfg, defaultCfgErr = defaultConfig()
}

var (
	defaultCfg    config.Config
	defaultCfgErr error
)

// Finding is one secret finding, safe to log, return or persist.
type Finding struct {
	RuleID string `json:"rule_id"`
	// File is the path relative to the scanned directory, slash-separated.
	File string `json:"file"`
	Line int    `json:"line"`
	// Match is the redacted secret: its first four characters plus "****", or
	// just "****" for short secrets. The raw secret never appears here.
	Match string `json:"match"`
	// SecretHMAC is hex(HMAC-SHA256(key, secret)). It identifies the same
	// secret across scans without storing it.
	SecretHMAC string `json:"secret_hmac"`
}

// ScanDir scans the working tree under dir (no git history) with Gitleaks'
// default configuration. Results are sorted by file, line and rule id.
//
// skipDirs are directories to leave out, each relative to dir. They become an
// extra global allowlist (see skipAllowlist), so Gitleaks never reads files
// under them.
//
// key is bastion's local HMAC key (secrets.LocalKey); it must be non-empty.
func ScanDir(ctx context.Context, dir string, key []byte, skipDirs []string) ([]Finding, error) {
	if len(key) == 0 {
		return nil, errors.New("gitleaks: HMAC key is required")
	}
	target, err := resolveDir(dir)
	if err != nil {
		return nil, err
	}

	if defaultCfgErr != nil {
		return nil, defaultCfgErr
	}
	cfg := defaultCfg
	if len(skipDirs) > 0 {
		allowlist, err := skipAllowlist(target, skipDirs)
		if err != nil {
			return nil, err
		}
		// cfg is a copy, but its Allowlists slice shares a backing array with
		// the package-level config. Clone before appending so concurrent scans
		// never write into that shared array.
		cfg.Allowlists = append(slices.Clone(cfg.Allowlists), allowlist)
	}

	detector := detect.NewDetector(cfg)
	raw, err := detector.DetectSource(ctx, &sources.Files{
		Config: &cfg,
		Path:   target,
		Sema:   detector.Sema,
	})
	if err != nil {
		return nil, fmt.Errorf("gitleaks: scan %q: %w", target, err)
	}

	findings := make([]Finding, 0, len(raw))
	for _, f := range raw {
		findings = append(findings, Finding{
			RuleID:     f.RuleID,
			File:       relativePath(target, f.File),
			Line:       f.StartLine,
			Match:      redactMatch(f.Secret),
			SecretHMAC: secretHMAC(key, f.Secret),
		})
	}
	slices.SortFunc(findings, func(a, b Finding) int {
		if c := strings.Compare(a.File, b.File); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Line, b.Line); c != 0 {
			return c
		}
		if c := strings.Compare(a.RuleID, b.RuleID); c != 0 {
			return c
		}
		return strings.Compare(a.Match, b.Match)
	})
	return findings, nil
}

// defaultConfig parses Gitleaks' embedded default config into a Config.
//
// It deliberately does not use detect.NewDetectorDefaultConfig: that helper
// reads through the process-global Viper instance, which Trivy also owns
// (ADR-001). A local Viper keeps Gitleaks' configuration independent of
// Trivy's. Config.Translate still reads viper.ConfigFileUsed() for a
// cosmetic Path field, so this must only run from init (see above).
func defaultConfig() (config.Config, error) {
	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(config.DefaultConfig)); err != nil {
		return config.Config{}, fmt.Errorf("gitleaks: read default config: %w", err)
	}
	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return config.Config{}, fmt.Errorf("gitleaks: decode default config: %w", err)
	}
	cfg, err := vc.Translate()
	if err != nil {
		return config.Config{}, fmt.Errorf("gitleaks: translate default config: %w", err)
	}
	return cfg, nil
}

// skipAllowlist builds the global allowlist that leaves skipDirs (relative to
// root) and everything under them out of the scan. Gitleaks allowlists match
// paths with regexes, not globs, so each entry becomes an anchored path regex;
// sources.Files then returns filepath.SkipDir before a skipped directory is
// walked, so its files are never read.
func skipAllowlist(root string, skipDirs []string) (*config.Allowlist, error) {
	paths := make([]*glregexp.Regexp, 0, len(skipDirs))
	for _, dir := range skipDirs {
		re, err := skipRegexp(root, dir)
		if err != nil {
			return nil, fmt.Errorf("gitleaks: %w", err)
		}
		paths = append(paths, re)
	}
	allowlist := &config.Allowlist{Description: "bastion --skip-dirs", Paths: paths}
	if err := allowlist.Validate(); err != nil {
		return nil, fmt.Errorf("gitleaks: skip dirs: %w", err)
	}
	return allowlist, nil
}

// skipRegexp turns dir, relative to root, into an anchored path regex. Both
// separators are accepted so a Windows path matches as well as a slash path.
func skipRegexp(root, dir string) (*glregexp.Regexp, error) {
	rel := filepath.FromSlash(dir)
	if rel == "." || !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("skip dir %q must be a path relative to the scan root", dir)
	}
	parts := strings.Split(filepath.ToSlash(filepath.Join(root, rel)), "/")
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	// QuoteMeta leaves no metacharacters, so MustCompile cannot panic here.
	return glregexp.MustCompile(`^` + strings.Join(parts, `[\\/]`) + `([\\/]|$)`), nil
}

// resolveDir validates dir and returns its absolute path so reported file names
// do not depend on the caller's working directory.
func resolveDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("gitleaks: target dir is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("gitleaks: resolve target %q: %w", dir, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("gitleaks: stat target %q: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("gitleaks: target %q is not a directory", dir)
	}
	return abs, nil
}

// relativePath makes file relative to dir with forward slashes. Paths outside
// dir are returned unchanged rather than silently truncated.
func relativePath(dir, file string) string {
	rel, err := filepath.Rel(dir, file)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(file)
	}
	return filepath.ToSlash(rel)
}

// redactMatch returns the safe form of a secret: the first four runes plus
// "****", or just "****" when the secret is too short to reveal any characters.
func redactMatch(secret string) string {
	r := []rune(secret)
	if len(r) <= 4 {
		return "****"
	}
	return string(r[:4]) + "****"
}

// secretHMAC returns hex(HMAC-SHA256(key, secret)).
func secretHMAC(key []byte, secret string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}
