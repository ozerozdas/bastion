package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/scanners/gitleaks"
	"github.com/ozerozdas/bastion/internal/scanners/trivy"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/sources/localpath"
	"github.com/ozerozdas/bastion/internal/store"
)

// scanFormatJSON is the only output format until the report UI needs others.
const scanFormatJSON = "json"

// scanSaveTimeout bounds the final write. It has its own context because
// Ctrl-C cancels the scan context the scanners ran under.
const scanSaveTimeout = 10 * time.Second

// adapter is a scanner that also normalizes its own output. Keeping both
// halves in the scanner package keeps the library import behind §4.2's
// boundary.
type adapter interface {
	scanners.Scanner
	findings.Normalizer
}

type scanOptions struct {
	path    string
	format  string
	noStore bool
}

// scanOutput is the `bastion scan --format json` document.
type scanOutput struct {
	Asset       findings.Asset     `json:"asset"`
	ScanID      int64              `json:"scan_id,omitempty"`
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

// scanDeps isolates the side effects of `bastion scan` so tests can run the
// pipeline with fake scanners and a temporary database, without touching the
// real keyring.
type scanDeps struct {
	paths         app.Paths
	openDB        func(ctx context.Context, path string) (*sql.DB, error)
	closeDB       func(db *sql.DB) error
	notifyContext func(parent context.Context) (context.Context, context.CancelFunc)
	newScanners   func() []scanners.Scanner
	hmacKey       func() ([]byte, error)
}

func newScanCmd(root *rootOptions) *cobra.Command {
	opts := &scanOptions{format: scanFormatJSON}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a local path and print normalized findings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), cmd.OutOrStdout(), opts, newScanDeps(root))
		},
	}
	cmd.Flags().StringVar(&opts.path, "path", "", "directory to scan (required)")
	cmd.Flags().StringVar(&opts.format, "format", scanFormatJSON, "output format: "+scanFormatJSON)
	cmd.Flags().BoolVar(&opts.noStore, "no-store", false, "print findings without writing to the database")
	_ = cmd.MarkFlagRequired("path")
	return cmd
}

// newScanDeps wires the production implementations.
func newScanDeps(root *rootOptions) scanDeps {
	return scanDeps{
		paths:   root.paths,
		openDB:  store.Open,
		closeDB: (*sql.DB).Close,
		notifyContext: func(parent context.Context) (context.Context, context.CancelFunc) {
			return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
		},
		newScanners: func() []scanners.Scanner {
			// Trivy serializes itself (ADR-001); running adapters one after
			// another also keeps Gitleaks independent of that lock.
			return []scanners.Scanner{trivy.New(), gitleaks.New()}
		},
		hmacKey: func() ([]byte, error) { return secrets.LocalKey(secrets.NewStore()) },
	}
}

// runScan resolves the target, scans it, persists the result and prints the
// JSON document. Persistence is the default: a finding's fingerprint includes
// the asset id (PROJECT_SPEC.md §5), so a scan against a throwaway id could
// never be diffed against the next one. --no-store keeps the P0 stdout-only
// behaviour and does not even open the database file.
func runScan(ctx context.Context, out io.Writer, opts *scanOptions, deps scanDeps) error {
	if opts.format != scanFormatJSON {
		return fmt.Errorf("scan: unsupported format %q (supported: %s)", opts.format, scanFormatJSON)
	}

	// Ctrl-C cancels the scan instead of killing the process, so the result
	// can still be stored as canceled.
	ctx, stop := deps.notifyContext(ctx)
	defer stop()

	ws, err := localpath.New().Fetch(ctx, sources.Target{Kind: sources.KindPath, Ref: opts.path})
	if err != nil {
		return err
	}
	defer func() { _ = ws.Close() }()

	// The HMAC key makes secret fingerprints stable across scans. It comes
	// from the OS keyring or BASTION_HMAC_KEY and is never logged.
	key, err := deps.hmacKey()
	if err != nil {
		return err
	}

	asset, err := pathAsset(ws.Dir)
	if err != nil {
		return err
	}

	var (
		db     *sql.DB
		scanID int64
	)
	if !opts.noStore {
		db, err = deps.openDB(ctx, deps.paths.DBPath())
		if err != nil {
			return fmt.Errorf("scan: open database: %w", err)
		}
		defer func() { _ = deps.closeDB(db) }()

		// Scanners normalize against the stored asset, so their fingerprints
		// use the id the next scan of this path resolves to as well.
		asset, err = store.GetOrCreateAsset(ctx, db, asset)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		scanID, err = store.StartScan(ctx, db, asset.ID, store.ScanTriggerCLI)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		if err := store.MarkScanRunning(ctx, db, scanID); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
	}

	result, scanErr := scanTarget(ctx, sources.KindPath, deps.newScanners(), ws, asset, scanners.Options{
		CacheDir: deps.paths.TrivyCacheDir(),
		HMACKey:  key,
	})
	result.ScanID = scanID

	var saveErr error
	if db != nil {
		saveErr = saveScan(ctx, db, scanID, result, scanErr)
	}

	// Partial results are still printed: one broken scanner must not hide the
	// findings of the others. The returned error keeps the exit code non-zero.
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return errors.Join(fmt.Errorf("write scan output: %w", err), saveErr)
	}
	if ctx.Err() != nil {
		return errors.Join(ctx.Err(), saveErr)
	}
	return errors.Join(scanErr, saveErr)
}

// pathAsset builds the asset a local-path scan belongs to. The ref is the
// absolute cleaned path: the (kind, ref) key keeps repeated scans of one
// directory on the same row, and the row's id feeds the fingerprints.
func pathAsset(dir string) (findings.Asset, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return findings.Asset{}, fmt.Errorf("scan: resolve path %q: %w", dir, err)
	}
	ref := filepath.Clean(abs)
	return findings.Asset{
		Kind:        findings.AssetKindPath,
		DisplayName: filepath.Base(ref),
		Ref:         ref,
	}, nil
}

// saveScan persists one finished scan with its final status. A failure names
// the failed scanners and keeps the partial results, matching what was printed;
// a canceled scan is stored as canceled with the interrupted output.
func saveScan(ctx context.Context, db *sql.DB, scanID int64, result scanOutput, scanErr error) error {
	status, errText := store.ScanStatusSucceeded, ""
	switch {
	case ctx.Err() != nil:
		status, errText = store.ScanStatusCanceled, ctx.Err().Error()
	case scanErr != nil:
		status, errText = store.ScanStatusFailed, scanErr.Error()
	}

	runs := make([]store.ScannerRun, 0, len(result.ScannerRuns))
	for _, run := range result.ScannerRuns {
		duration := run.DurationMS
		runs = append(runs, store.ScannerRun{
			Scanner:        run.Scanner,
			ScannerVersion: run.ScannerVersion,
			Status:         run.Status,
			DurationMS:     &duration,
			Error:          run.Error,
		})
	}

	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), scanSaveTimeout)
	defer cancel()

	if err := store.SaveScanResult(saveCtx, db, scanID, store.ScanResult{
		Status:      status,
		Error:       errText,
		ScannerRuns: runs,
		Packages:    result.Packages,
		Findings:    result.Findings,
	}); err != nil {
		return fmt.Errorf("save scan %d: %w", scanID, err)
	}
	return nil
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
