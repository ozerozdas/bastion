package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/scanners/gitleaks"
	"github.com/ozerozdas/bastion/internal/scanners/trivy"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/sources/localpath"
)

// scanFormatJSON is the only output format until the report UI needs others.
const scanFormatJSON = "json"

// adapter is a scanner that also normalizes its own output. Keeping both
// halves in the scanner package keeps the library import behind §4.2's
// boundary.
type adapter interface {
	scanners.Scanner
	findings.Normalizer
}

type scanOptions struct {
	path   string
	format string
}

// scanOutput is the `bastion scan --format json` document.
type scanOutput struct {
	Asset       findings.Asset     `json:"asset"`
	Findings    []findings.Finding `json:"findings"`
	Packages    []findings.Package `json:"packages"`
	ScannerRuns []scannerRun       `json:"scanner_runs"`
}

// scannerRun records one scanner execution within a scan (§5 scanner_runs).
type scannerRun struct {
	Scanner        string `json:"scanner"`
	ScannerVersion string `json:"scanner_version"`
	Status         string `json:"status"`
	DurationMS     int64  `json:"duration_ms"`
	Error          string `json:"error,omitempty"`
}

func newScanCmd(root *rootOptions) *cobra.Command {
	opts := &scanOptions{format: scanFormatJSON}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a local path and print normalized findings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return opts.run(cmd, root)
		},
	}
	cmd.Flags().StringVar(&opts.path, "path", "", "directory to scan (required)")
	cmd.Flags().StringVar(&opts.format, "format", scanFormatJSON, "output format: "+scanFormatJSON)
	_ = cmd.MarkFlagRequired("path")
	return cmd
}

func (o *scanOptions) run(cmd *cobra.Command, root *rootOptions) error {
	if o.format != scanFormatJSON {
		return fmt.Errorf("scan: unsupported format %q (supported: %s)", o.format, scanFormatJSON)
	}
	ctx := cmd.Context()

	ws, err := localpath.New().Fetch(ctx, sources.Target{Kind: sources.KindPath, Ref: o.path})
	if err != nil {
		return err
	}
	defer func() { _ = ws.Close() }()

	// The HMAC key makes secret fingerprints stable across scans. It comes
	// from the OS keyring or BASTION_HMAC_KEY and is never logged.
	key, err := secrets.LocalKey(secrets.NewStore())
	if err != nil {
		return err
	}

	asset := findings.Asset{
		Kind:        findings.AssetKindPath,
		DisplayName: filepath.Base(ws.Dir),
		Ref:         ws.Dir,
	}
	// Trivy serializes itself (ADR-001); running adapters one after another
	// also keeps Gitleaks independent of that lock.
	out, scanErr := scanTarget(ctx, sources.KindPath, []scanners.Scanner{trivy.New(), gitleaks.New()}, ws, asset, scanners.Options{
		CacheDir: root.paths.TrivyCacheDir(),
		HMACKey:  key,
	})

	// Partial results are still printed: one broken scanner must not hide the
	// findings of the others. The returned error keeps the exit code non-zero.
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("write scan output: %w", err)
	}
	return scanErr
}

// scanTarget runs every scanner that supports kind, normalizes the output and
// merges duplicate fingerprints (PROJECT_SPEC.md §5). A failing scanner is
// recorded in its scanner_run and the remaining scanners still contribute
// findings; the returned error names every failed scanner.
func scanTarget(ctx context.Context, kind sources.TargetKind, scs []scanners.Scanner, ws *sources.Workspace, asset findings.Asset, opts scanners.Options) (scanOutput, error) {
	out := scanOutput{
		Asset:       asset,
		Findings:    []findings.Finding{},
		Packages:    []findings.Package{},
		ScannerRuns: []scannerRun{},
	}
	var failed []string
	for _, s := range scs {
		if !s.Supports(kind) {
			continue
		}
		start := time.Now()
		fs, pkgs, err := runScanner(ctx, s, ws, asset, opts)
		duration := time.Since(start).Milliseconds()
		run := scannerRun{
			Scanner:        s.Name(),
			ScannerVersion: s.Version(),
			Status:         "succeeded",
			DurationMS:     duration,
		}
		if err != nil {
			run.Status = "failed"
			run.Error = err.Error()
			failed = append(failed, s.Name())
		} else {
			out.Findings = append(out.Findings, fs...)
			out.Packages = append(out.Packages, pkgs...)
		}
		out.ScannerRuns = append(out.ScannerRuns, run)
	}

	// One finding per fingerprint per scan, before sorting and printing.
	out.Findings = findings.Merge(out.Findings)
	findings.SortFindings(out.Findings)
	findings.SortPackages(out.Packages)

	if len(failed) > 0 {
		return out, fmt.Errorf("scan: scanner failed: %s", strings.Join(failed, ", "))
	}
	return out, nil
}

// runScanner scans and normalizes one scanner's output.
func runScanner(ctx context.Context, s scanners.Scanner, ws *sources.Workspace, asset findings.Asset, opts scanners.Options) ([]findings.Finding, []findings.Package, error) {
	a, ok := s.(adapter)
	if !ok {
		return nil, nil, fmt.Errorf("%s: scanner does not normalize its own output", s.Name())
	}
	raw, err := a.Scan(ctx, ws, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", a.Name(), err)
	}
	fs, pkgs, err := a.Normalize(raw, asset)
	if err != nil {
		return nil, nil, fmt.Errorf("normalize %s: %w", a.Name(), err)
	}
	return fs, pkgs, nil
}
