package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
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
	out := scanOutput{
		Asset:       asset,
		Findings:    []findings.Finding{},
		Packages:    []findings.Package{},
		ScannerRuns: []scannerRun{},
	}

	// Trivy serializes itself (ADR-001); running adapters one after another
	// also keeps Gitleaks independent of that lock.
	adapters := []adapter{trivy.New(), gitleaks.New()}
	for _, a := range adapters {
		if !a.Supports(sources.KindPath) {
			continue
		}
		start := time.Now()
		raw, err := a.Scan(ctx, ws, scanners.Options{
			CacheDir: root.paths.TrivyCacheDir(),
			HMACKey:  key,
		})
		if err != nil {
			return fmt.Errorf("scan: %s: %w", a.Name(), err)
		}
		fs, pkgs, err := a.Normalize(raw, asset)
		if err != nil {
			return fmt.Errorf("scan: normalize %s: %w", a.Name(), err)
		}
		out.Findings = append(out.Findings, fs...)
		out.Packages = append(out.Packages, pkgs...)
		out.ScannerRuns = append(out.ScannerRuns, scannerRun{
			Scanner:        a.Name(),
			ScannerVersion: a.Version(),
			Status:         "succeeded",
			DurationMS:     time.Since(start).Milliseconds(),
		})
	}

	findings.SortFindings(out.Findings)
	findings.SortPackages(out.Packages)

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("write scan output: %w", err)
	}
	return nil
}
