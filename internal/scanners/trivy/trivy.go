// Package trivy runs Trivy as a library against a local directory.
//
// It is the only package in bastion allowed to import github.com/aquasecurity/trivy
// (PROJECT_SPEC.md §4.2). Callers receive Trivy's JSON report as raw bytes, so
// Trivy's Go types never leak outside this package; the normalizer in
// internal/findings owns the mapping into bastion's finding model.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ozerozdas/bastion/internal/sources"
)

// Version is the Trivy release this adapter is built against. It must match the
// github.com/aquasecurity/trivy version pinned in go.mod.
const Version = "0.76.2"

// enabledScanners is the scanner set bastion uses. Secrets are owned by
// Gitleaks (PROJECT_SPEC.md §3), so Trivy's secret scanner stays off.
const enabledScanners = "vuln,misconfig,license"

// scanMu serializes scans. Trivy's library surface is process-global: Viper
// holds the flag/config state, the vulnerability DB is a package-level handle,
// the Java DB updater is a singleton and Trivy logs through slog.Default().
// Concurrent ScanFS calls would race on that state, so they are serialized
// here; the worker pool in BST-010/P1 must either accept this lock or run each
// scan in its own process.
var scanMu sync.Mutex

// ScanFS scans dir for vulnerabilities, misconfigurations and licenses and
// returns Trivy's JSON report (schema version 2) unchanged.
//
// All Trivy state (vulnerability DB, misconfiguration checks bundle, Java DB)
// lives under cacheDir; no other directory is written to.
//
// skipDirs are directories to leave out, each relative to dir. Trivy receives
// them as its --skip-dirs patterns (doublestar globs, see skipPatterns), so a
// plain directory name excludes that subtree while "**/node_modules" works too.
func ScanFS(ctx context.Context, dir, cacheDir string, skipDirs []string) (out json.RawMessage, err error) {
	scanMu.Lock()
	defer scanMu.Unlock()

	target, err := resolveTarget(dir)
	if err != nil {
		return nil, err
	}
	if cacheDir == "" {
		return nil, errors.New("trivy: cache dir is required")
	}
	if err = os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("trivy: create cache dir %q: %w", cacheDir, err)
	}

	skip, err := skipPatterns(target, skipDirs)
	if err != nil {
		return nil, err
	}
	opts, err := newOptions(target, scanArgs(cacheDir, skip))
	if err != nil {
		return nil, err
	}

	return scanReport(ctx, opts, artifact.TargetFilesystem, target,
		func(ctx context.Context, opts flag.Options, runner artifact.Runner) (types.Report, error) {
			return runner.ScanFilesystem(ctx, opts)
		})
}

// ScanImage scans an image the local Docker daemon holds and returns Trivy's
// JSON report unchanged. Only the docker image source is enabled: bastion must
// not pull from a registry behind the user's back.
//
// dockerHost is the daemon socket ("unix:///var/run/docker.sock"); empty lets
// Trivy resolve it from its own environment.
func ScanImage(ctx context.Context, ref, cacheDir, dockerHost string) (out json.RawMessage, err error) {
	scanMu.Lock()
	defer scanMu.Unlock()

	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("trivy: image reference is required")
	}
	if cacheDir == "" {
		return nil, errors.New("trivy: cache dir is required")
	}
	if err = os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("trivy: create cache dir %q: %w", cacheDir, err)
	}

	opts, err := newOptions(ref, imageScanArgs(cacheDir, dockerHost))
	if err != nil {
		return nil, err
	}
	return scanReport(ctx, opts, artifact.TargetContainerImage, ref,
		func(ctx context.Context, opts flag.Options, runner artifact.Runner) (types.Report, error) {
			return runner.ScanImage(ctx, opts)
		})
}

// ScanRemoteImage pulls an image from a registry with a short-lived login and
// returns Trivy's JSON report unchanged. Only the remote image source is
// enabled; the credentials are set on the parsed options, never on the argv and
// never logged, so they cannot leak through a flag dump.
func ScanRemoteImage(ctx context.Context, ref, cacheDir string, auth sources.RegistryAuth) (out json.RawMessage, err error) {
	scanMu.Lock()
	defer scanMu.Unlock()

	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("trivy: image reference is required")
	}
	if cacheDir == "" {
		return nil, errors.New("trivy: cache dir is required")
	}
	if auth.Username == "" || auth.Password == "" {
		return nil, errors.New("trivy: registry credentials are required")
	}
	if err = os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("trivy: create cache dir %q: %w", cacheDir, err)
	}

	scan := func(opts flag.Options) (json.RawMessage, error) {
		return scanReport(ctx, opts, artifact.TargetContainerImage, ref,
			func(ctx context.Context, opts flag.Options, runner artifact.Runner) (types.Report, error) {
				return runner.ScanImage(ctx, opts)
			})
	}

	opts, err := remoteImageOptions(ref, cacheDir, "", auth)
	if err != nil {
		return nil, err
	}
	out, err = scan(opts)
	if err == nil || !arm64PlatformMissing(err) {
		return out, err
	}

	// Trivy defaults to linux/amd64. An arm64-only image has no amd64 child;
	// retry once for the platform it does have. The first attempt stays the
	// default so an amd64 image is never pulled twice.
	opts, err = remoteImageOptions(ref, cacheDir, "linux/arm64", auth)
	if err != nil {
		return nil, err
	}
	return scan(opts)
}

// remoteImageOptions builds the remote-scan options with the registry login
// set in memory. The password never reaches argv or a log line.
func remoteImageOptions(ref, cacheDir, platform string, auth sources.RegistryAuth) (flag.Options, error) {
	opts, err := newOptions(ref, remoteImageScanArgs(cacheDir, platform))
	if err != nil {
		return flag.Options{}, err
	}
	opts.Credentials = []ftypes.Credential{{
		Username: auth.Username,
		Password: auth.Password,
	}}
	return opts, nil
}

// arm64PlatformMissing reports Trivy's "no child with platform" error, which
// means the image index has no linux/amd64 manifest.
func arm64PlatformMissing(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no child with platform")
}

// scanFunc runs one Trivy artifact scan. The runner is passed in because
// artifact.NewRunner must be closed on every path.
type scanFunc func(context.Context, flag.Options, artifact.Runner) (types.Report, error)

// scanReport initializes a runner for targetKind, runs scan, applies
// bastion's filtering and encodes the report as JSON.
func scanReport(ctx context.Context, opts flag.Options, targetKind artifact.TargetKind, label string, scan scanFunc) (out json.RawMessage, err error) {
	runner, err := artifact.NewRunner(ctx, opts, targetKind)
	if err != nil {
		return nil, fmt.Errorf("trivy: initialize runner: %w", err)
	}
	defer func() {
		if closeErr := runner.Close(ctx); closeErr != nil && err == nil {
			err = fmt.Errorf("trivy: close runner: %w", closeErr)
		}
	}()

	report, err := scan(ctx, opts, runner)
	if err != nil {
		return nil, fmt.Errorf("trivy: scan %q: %w", label, err)
	}
	// Filtering applies severity and ignore-file policy. Severities default to
	// all levels, which is what bastion stores.
	report, err = runner.Filter(ctx, opts, report)
	if err != nil {
		return nil, fmt.Errorf("trivy: filter %q: %w", label, err)
	}

	var buf bytes.Buffer
	opts.SetOutputWriter(&buf)
	if err = runner.Report(ctx, opts, report); err != nil {
		return nil, fmt.Errorf("trivy: encode report: %w", err)
	}
	return json.RawMessage(buf.Bytes()), nil
}

// resolveTarget validates dir and returns its absolute path so Trivy's report
// locations do not depend on the caller's working directory.
func resolveTarget(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("trivy: target dir is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("trivy: resolve target %q: %w", dir, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("trivy: stat target %q: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("trivy: target %q is not a directory", dir)
	}
	return abs, nil
}

// skipPatterns resolves skipDirs against target, the scan root.
//
// Trivy interprets its --skip-dirs values relative to the process working
// directory (fanal/walker.FS.BuildSkipPaths takes filepath.Abs of each value
// and makes it relative to the scan root), so a caller's "testdata" would
// silently mean nothing when bastion is not started from the scan root. Handing
// Trivy the absolute path of "target/skipDir" is the only form that means
// "relative to the scan root" from any working directory. Glob metacharacters
// survive filepath.Join, so Trivy's doublestar matching still applies.
func skipPatterns(target string, skipDirs []string) ([]string, error) {
	if len(skipDirs) == 0 {
		return nil, nil
	}
	patterns := make([]string, 0, len(skipDirs))
	for _, dir := range skipDirs {
		rel := filepath.FromSlash(dir)
		if rel == "." || !filepath.IsLocal(rel) {
			return nil, fmt.Errorf("trivy: skip dir %q must be a path relative to the scan root", dir)
		}
		patterns = append(patterns, filepath.Join(target, rel))
	}
	return patterns, nil
}

// newOptions builds Trivy's flag.Options the same way the Trivy CLI does:
// register its flag groups on a throwaway command, bind them to Viper, parse
// our fixed argument list, then convert to Options.
func newOptions(target string, args []string) (flag.Options, error) {
	// Trivy's Flags.AddFlags/Bind deliberately skip the "Global" group; its CLI
	// registers those on the root command itself. Do the same here, while
	// keeping the group in the list because ToOptions walks every entry.
	globalGroup := flag.NewGlobalFlagGroup()
	groups := flag.Flags{
		globalGroup,
		flag.NewCacheFlagGroup(),
		flag.NewDBFlagGroup(),
		flag.NewImageFlagGroup(),
		flag.NewLicenseFlagGroup(),
		flag.NewMisconfFlagGroup(),
		flag.NewModuleFlagGroup(),
		flag.NewPackageFlagGroup(),
		flag.NewRegistryFlagGroup(),
		flag.NewRegoFlagGroup(),
		flag.NewReportFlagGroup(),
		flag.NewScanFlagGroup(),
		flag.NewVulnerabilityFlagGroup(),
	}

	// Trivy reads every flag through the global Viper instance. Reset it so a
	// long-running bastion process does not inherit a previous scan's state.
	viper.Reset()

	cmd := &cobra.Command{Use: "trivy"}
	globalGroup.AddFlags(cmd)
	groups.AddFlags(cmd)
	if err := globalGroup.Bind(cmd); err != nil {
		return flag.Options{}, fmt.Errorf("trivy: bind global flags: %w", err)
	}
	if err := groups.Bind(cmd); err != nil {
		return flag.Options{}, fmt.Errorf("trivy: bind flags: %w", err)
	}
	// ParseFlags merges persistent flags (e.g. --cache-dir) into the local set.
	if err := cmd.ParseFlags(args); err != nil {
		return flag.Options{}, fmt.Errorf("trivy: parse flags: %w", err)
	}
	// ToOptions takes the positional arguments; a single argument becomes the
	// scan target.
	opts, err := groups.ToOptions([]string{target})
	if err != nil {
		return flag.Options{}, fmt.Errorf("trivy: build options: %w", err)
	}
	return opts, nil
}

// scanArgs is the fixed Trivy CLI surface bastion uses for a filesystem scan.
// skipDirs are absolute paths under the scan root (see skipPatterns); Trivy's
// flag is a string slice, so repeating --skip-dirs accumulates.
func scanArgs(cacheDir string, skipDirs []string) []string {
	args := baseScanArgs(cacheDir)
	for _, dir := range skipDirs {
		args = append(args, "--skip-dirs", dir)
	}
	return args
}

// imageScanArgs is the Trivy CLI surface for a local image scan. The docker
// source is the only one enabled, so Trivy never pulls from a registry.
func imageScanArgs(cacheDir, dockerHost string) []string {
	args := append(baseScanArgs(cacheDir), "--image-src", "docker")
	if dockerHost != "" {
		args = append(args, "--docker-host", dockerHost)
	}
	return args
}

// remoteImageScanArgs is the Trivy CLI surface for an image pulled from a
// registry. Only the remote source is enabled, so Trivy never looks for the
// image on the local daemon. platform is empty for Trivy's default
// (linux/amd64) and set only for the arm64 retry.
func remoteImageScanArgs(cacheDir, platform string) []string {
	args := append(baseScanArgs(cacheDir), "--image-src", "remote")
	if platform != "" {
		args = append(args, "--platform", platform)
	}
	return args
}

// baseScanArgs are the flags every bastion scan passes.
func baseScanArgs(cacheDir string) []string {
	return []string{
		"--cache-dir", cacheDir,
		"--scanners", enabledScanners,
		"--format", "json",
		"--quiet",
		"--no-progress",
		// No update/telemetry callbacks: bastion only talks to the DB and
		// checks-bundle registries it documents.
		"--skip-version-check",
		"--disable-telemetry",
	}
}
