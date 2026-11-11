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
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/connections"
	githubclient "github.com/ozerozdas/bastion/internal/connections/github"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/report/sarif"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/scanners/gitleaks"
	"github.com/ozerozdas/bastion/internal/scanners/trivy"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/sources"
	githubsource "github.com/ozerozdas/bastion/internal/sources/github"
	"github.com/ozerozdas/bastion/internal/sources/localpath"
	"github.com/ozerozdas/bastion/internal/store"
)

// Output formats of `bastion scan`.
const (
	scanFormatJSON  = "json"
	scanFormatTable = "table"
	scanFormatSARIF = "sarif"
)

// scanLoadTimeout bounds reading a finished scan back for output. It has its
// own context because Ctrl-C cancels the scan context the job ran under.
const scanLoadTimeout = 10 * time.Second

// errFailOn reports a --fail-on threshold breach. main maps it to exit code 2,
// so a CI job can tell "findings found" from "the scan broke" (exit 1).
var errFailOn = errors.New("scan: open findings at or above the --fail-on severity")

// adapter is a scanner that also normalizes its own output. Keeping both
// halves in the scanner package keeps the library import behind §4.2's
// boundary.
type adapter interface {
	scanners.Scanner
	findings.Normalizer
}

type scanOptions struct {
	path     string
	repo     string
	format   string
	failOn   string
	noStore  bool
	skipDirs []string
}

// scanOutput is the `bastion scan --format json` document.
type scanOutput struct {
	Asset       findings.Asset     `json:"asset"`
	ScanID      int64              `json:"scan_id,omitempty"`
	Findings    []findings.Finding `json:"findings"`
	Packages    []findings.Package `json:"packages"`
	ScannerRuns []scannerRun       `json:"scanner_runs"`

	// open are the findings a severity gate considers: ignored findings are
	// excluded. It is never printed, so the document keeps its shape.
	open []findings.Finding
}

// scannerRun records one scanner execution within a scan (§5 scanner_runs).
type scannerRun struct {
	Scanner        string `json:"scanner"`
	ScannerVersion string `json:"scanner_version"`
	Status         string `json:"status"`
	DurationMS     int64  `json:"duration_ms"`
	Error          string `json:"error,omitempty"`
}

// gitHubClient is the part of internal/connections/github a repo scan uses.
// Tests inject an httptest-backed client through scanDeps.
type gitHubClient interface {
	Repo(ctx context.Context, owner, name string) (githubclient.Repo, error)
	ResolveSHA(ctx context.Context, owner, name, ref string) (string, error)
	Tarball(ctx context.Context, owner, name, sha string) (io.ReadCloser, error)
}

// scanDeps isolates the side effects of `bastion scan` so tests can run the
// pipeline with fake scanners, a fake GitHub and a temporary database, without
// touching the real keyring or the network.
type scanDeps struct {
	paths         app.Paths
	openDB        func(ctx context.Context, path string) (*sql.DB, error)
	closeDB       func(db *sql.DB) error
	notifyContext func(parent context.Context) (context.Context, context.CancelFunc)
	newScanners   func() []scanners.Scanner
	hmacKey       func() ([]byte, error)
	// githubToken resolves the --repo credential. db is nil for --no-store,
	// which never opens the database and therefore only honours the
	// environment fallback.
	githubToken func(ctx context.Context, db *sql.DB) (string, error)
	newGitHub   func(token string) (gitHubClient, error)
	// version is the bastion build version reported in SARIF.
	version string
}

func newScanCmd(root *rootOptions) *cobra.Command {
	opts := &scanOptions{format: scanFormatJSON}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a local path or GitHub repository and print normalized findings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), cmd.OutOrStdout(), opts, newScanDeps(root))
		},
	}
	cmd.Flags().StringVar(&opts.path, "path", "", "directory to scan")
	cmd.Flags().StringVar(&opts.repo, "repo", "",
		"GitHub repository to scan as owner/name[@ref]; requires a token from a saved connection or BASTION_GITHUB_TOKEN")
	cmd.Flags().StringVar(&opts.format, "format", scanFormatJSON,
		"output format: "+scanFormatJSON+", "+scanFormatTable+" or "+scanFormatSARIF)
	cmd.Flags().BoolVar(&opts.noStore, "no-store", false, "print findings without writing to the database")
	cmd.Flags().StringArrayVar(&opts.skipDirs, "skip-dirs", nil,
		"directory to leave out of the scan, relative to the scan root (e.g. testdata); repeat for more")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", "",
		"exit with status 2 when an open finding is at or above this severity: critical, high, medium or low")
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
		githubToken: func(ctx context.Context, db *sql.DB) (string, error) {
			if db == nil {
				return connections.EnvToken()
			}
			service, err := connections.NewService(db, secrets.NewStore())
			if err != nil {
				return "", err
			}
			return service.Token(ctx)
		},
		newGitHub: func(token string) (gitHubClient, error) {
			return githubclient.New(githubclient.Config{Token: token, Version: version})
		},
		version: version,
	}
}

// validate rejects flag combinations before any work starts: cobra only knows
// the flags, not that exactly one target is required.
func (o *scanOptions) validate() error {
	switch {
	case o.path == "" && o.repo == "":
		return errors.New("scan: one of --path or --repo is required")
	case o.path != "" && o.repo != "":
		return errors.New("scan: --path and --repo are mutually exclusive")
	}
	switch o.format {
	case scanFormatJSON, scanFormatTable, scanFormatSARIF:
	default:
		return fmt.Errorf("scan: unsupported format %q (supported: %s, %s, %s)",
			o.format, scanFormatJSON, scanFormatTable, scanFormatSARIF)
	}
	if o.failOn != "" && severityOrder(findings.Severity(o.failOn)) == severityUnknownOrder {
		return fmt.Errorf("scan: unsupported --fail-on severity %q (supported: critical, high, medium, low)", o.failOn)
	}
	// Scanning is rooted at the target (a local path or a downloaded repo
	// checkout), so a skip dir is only meaningful relative to that root.
	for _, dir := range o.skipDirs {
		rel := filepath.FromSlash(dir)
		if rel == "." || !filepath.IsLocal(rel) {
			return fmt.Errorf("scan: --skip-dirs %q must be a path relative to the scan root", dir)
		}
	}
	return nil
}

// runScan resolves the target, scans it and prints the result in the selected
// format. Persistence is the default: a finding's fingerprint includes the
// asset id (PROJECT_SPEC.md §5), so a scan against a throwaway id could never
// be diffed against the next one.
//
// A stored scan runs through jobs.Manager, the same pipeline the server uses:
// the CLI must not carry a second persisting implementation. --no-store keeps
// the P0 stdout-only behaviour, does not open the database and therefore runs
// the scanners directly.
func runScan(ctx context.Context, out io.Writer, opts *scanOptions, deps scanDeps) error {
	if err := opts.validate(); err != nil {
		return err
	}

	// Ctrl-C cancels the scan instead of killing the process, so the result
	// can still be stored as canceled.
	ctx, stop := deps.notifyContext(ctx)
	defer stop()

	var (
		db  *sql.DB
		err error
	)
	if !opts.noStore {
		db, err = deps.openDB(ctx, deps.paths.DBPath())
		if err != nil {
			return fmt.Errorf("scan: open database: %w", err)
		}
		defer func() { _ = deps.closeDB(db) }()
	}

	kind := sources.KindPath
	var (
		asset findings.Asset
		repo  *repoTarget
	)
	if opts.repo != "" {
		resolved, err := resolveRepo(ctx, opts.repo, db, deps)
		if err != nil {
			return err
		}
		repo = &resolved
		kind = sources.KindRepo
		asset = findings.Asset{
			Kind:        findings.AssetKindRepo,
			DisplayName: repo.fullName,
			Ref:         repo.fullName,
		}
	} else {
		asset, err = pathAsset(opts.path)
		if err != nil {
			return err
		}
	}

	// The HMAC key makes secret fingerprints stable across scans. It comes
	// from the OS keyring or BASTION_HMAC_KEY and is never logged.
	key, err := deps.hmacKey()
	if err != nil {
		return err
	}
	scanOpts := scanners.Options{
		CacheDir: deps.paths.TrivyCacheDir(),
		HMACKey:  key,
		SkipDirs: opts.skipDirs,
	}

	var (
		result  scanOutput
		scanErr error
	)
	if db != nil {
		result, scanErr = runStoredScan(ctx, db, kind, asset, repo, scanOpts, deps)
	} else {
		result, scanErr = runDirectScan(ctx, kind, asset, repo, scanOpts, deps)
	}

	// Partial results are still printed: one broken scanner must not hide the
	// findings of the others. The returned error keeps the exit code non-zero.
	if err := writeScanOutput(out, opts.format, result, deps.version); err != nil {
		return errors.Join(err, scanErr)
	}
	if scanErr != nil {
		return scanErr
	}
	return checkFailOn(opts.failOn, result.open)
}

// repoTarget is a resolved --repo target: the parsed spec, the repository's
// default branch, the commit SHA the scan reads, and the client that fetches
// it.
type repoTarget struct {
	repoSpec
	defaultBranch string
	sha           string
	client        gitHubClient
}

// repoSpec is a --repo value: owner/name with an optional @ref.
type repoSpec struct {
	fullName string
	owner    string
	name     string
	ref      string
}

// resolveRepo parses --repo, resolves it to a commit SHA and returns the
// client the source downloads with. Without a ref it uses the repository's
// default branch, so the asset records the branch the project tracks.
func resolveRepo(ctx context.Context, value string, db *sql.DB, deps scanDeps) (repoTarget, error) {
	spec, err := parseRepoSpec(value)
	if err != nil {
		return repoTarget{}, err
	}
	token, err := deps.githubToken(ctx, db)
	if err != nil {
		return repoTarget{}, fmt.Errorf("scan: --repo %s: %w", spec.fullName, err)
	}
	client, err := deps.newGitHub(token)
	if err != nil {
		return repoTarget{}, fmt.Errorf("scan: create GitHub client: %w", err)
	}
	repo, err := client.Repo(ctx, spec.owner, spec.name)
	if err != nil {
		return repoTarget{}, fmt.Errorf("scan: get repo %s: %w", spec.fullName, err)
	}
	ref := spec.ref
	if ref == "" {
		ref = repo.DefaultBranch
	}
	if ref == "" {
		return repoTarget{}, fmt.Errorf("scan: %s reports no default branch; pass --repo %s@ref",
			spec.fullName, spec.fullName)
	}
	sha, err := client.ResolveSHA(ctx, spec.owner, spec.name, ref)
	if err != nil {
		return repoTarget{}, fmt.Errorf("scan: resolve %s@%s: %w", spec.fullName, ref, err)
	}
	return repoTarget{repoSpec: spec, defaultBranch: repo.DefaultBranch, sha: sha, client: client}, nil
}

// parseRepoSpec splits owner/name[@ref]. Names are GitHub's own character set;
// the ref is passed through to GitHub, which is the only authority on what a
// branch, tag or SHA may look like.
func parseRepoSpec(value string) (repoSpec, error) {
	spec := strings.TrimSpace(value)
	ref := ""
	if i := strings.LastIndex(spec, "@"); i >= 0 {
		spec, ref = spec[:i], strings.TrimSpace(spec[i+1:])
		if ref == "" {
			return repoSpec{}, fmt.Errorf("scan: --repo %q has an empty ref", value)
		}
	}
	owner, name, ok := strings.Cut(spec, "/")
	switch {
	case !ok || strings.Contains(name, "/"):
		return repoSpec{}, fmt.Errorf("scan: --repo %q is not owner/name[@ref]", value)
	case !validRepoSegment(owner) || !validRepoSegment(name):
		return repoSpec{}, fmt.Errorf("scan: --repo %q has an invalid owner or repository name", value)
	}
	return repoSpec{fullName: owner + "/" + name, owner: owner, name: name, ref: ref}, nil
}

// validRepoSegment reports whether s can be a GitHub owner or repository name:
// letters, digits, ".", "_" and "-", at most 100 characters (GitHub's limit).
func validRepoSegment(s string) bool {
	if s == "" || len(s) > 100 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// runStoredScan persists one scan through jobs.Manager and reads the result
// back from the database, so the printed document and the stored state can
// never disagree. Concurrency is 1: the CLI runs exactly one scan.
func runStoredScan(ctx context.Context, db *sql.DB, kind sources.TargetKind, asset findings.Asset, repo *repoTarget, scanOpts scanners.Options, deps scanDeps) (scanOutput, error) {
	stored, err := storedAsset(ctx, db, kind, asset, repo)
	if err != nil {
		return scanOutput{}, err
	}
	asset = stored

	scannerList := deps.newScanners()

	srcs := map[sources.TargetKind]sources.Source{sources.KindPath: localpath.New()}
	if repo != nil {
		src, err := newGitHubSource(repo, deps)
		if err != nil {
			return scanOutput{}, err
		}
		srcs[sources.KindRepo] = src
	}

	resolve := func(_ context.Context, a jobs.Asset) (sources.Target, string, error) {
		if a.Kind != sources.KindRepo {
			return sources.Target{Kind: a.Kind, AssetID: a.ID, Ref: a.Ref}, "", nil
		}
		if repo == nil {
			return sources.Target{}, "", errors.New("scan: repo target was not resolved")
		}
		return sources.Target{Kind: sources.KindRepo, AssetID: a.ID, Ref: a.Ref + "@" + repo.sha}, repo.sha, nil
	}

	waiter := newFinishWaiter()
	manager, err := newScanManager(pipelineConfig{
		DB:          db,
		ScannerList: scannerList,
		Sources:     srcs,
		Options:     scanOpts,
		Concurrency: 1,
		Events:      waiter,
		Resolve:     resolve,
	})
	if err != nil {
		return scanOutput{}, err
	}
	defer func() { _ = manager.Close() }()

	scanID, err := manager.Enqueue(ctx, asset.ID, store.ScanTriggerCLI)
	if err != nil {
		return scanOutput{}, fmt.Errorf("scan: enqueue scan: %w", err)
	}

	// The job runs on the manager's context, not the caller's, so Ctrl-C has
	// to cancel it explicitly; the worker then persists "canceled" and
	// publishes scan.finished.
	canceled := make(chan struct{})
	go func() {
		defer close(canceled)
		select {
		case <-ctx.Done():
			_ = manager.Cancel(scanID)
		case <-waiter.done:
		}
	}()
	<-waiter.done
	<-canceled

	loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), scanLoadTimeout)
	defer cancel()
	report, err := store.LoadScanReport(loadCtx, db, scanID)
	if err != nil {
		return scanOutput{}, err
	}

	result := scanOutput{
		Asset:       asset,
		ScanID:      scanID,
		Findings:    report.Findings,
		Packages:    report.Packages,
		ScannerRuns: make([]scannerRun, 0, len(report.ScannerRuns)),
	}
	if result.Findings == nil {
		result.Findings = []findings.Finding{}
	}
	if result.Packages == nil {
		result.Packages = []findings.Package{}
	}
	for _, run := range report.ScannerRuns {
		item := scannerRun{
			Scanner:        run.Scanner,
			ScannerVersion: run.ScannerVersion,
			Status:         run.Status,
			Error:          run.Error,
		}
		if run.DurationMS != nil {
			item.DurationMS = *run.DurationMS
		}
		result.ScannerRuns = append(result.ScannerRuns, item)
	}
	result.open = report.Open
	if result.open == nil {
		result.open = []findings.Finding{}
	}

	switch report.Status {
	case store.ScanStatusSucceeded:
		return result, nil
	case store.ScanStatusCanceled:
		return result, context.Canceled
	case store.ScanStatusFailed:
		if report.Error == "" {
			return result, errors.New("scan: scanner failed")
		}
		return result, errors.New("scan: " + report.Error)
	default:
		return result, fmt.Errorf("scan: scan %d did not finish (status %q)", scanID, report.Status)
	}
}

// storedAsset resolves the asset row a scan belongs to, creating it the first
// time the target is seen.
func storedAsset(ctx context.Context, db *sql.DB, kind sources.TargetKind, asset findings.Asset, repo *repoTarget) (findings.Asset, error) {
	if kind == sources.KindRepo && repo != nil {
		return store.GetOrCreateRepoAsset(ctx, db, asset.Ref, repo.defaultBranch)
	}
	stored, err := store.GetOrCreateAsset(ctx, db, asset)
	if err != nil {
		return findings.Asset{}, fmt.Errorf("scan: %w", err)
	}
	return stored, nil
}

// runDirectScan fetches the target and scans it without touching the
// database. It backs --no-store only: a stored scan goes through
// jobs.Manager, so there is exactly one persisting pipeline.
func runDirectScan(ctx context.Context, kind sources.TargetKind, asset findings.Asset, repo *repoTarget, scanOpts scanners.Options, deps scanDeps) (scanOutput, error) {
	src := sources.Source(localpath.New())
	target := sources.Target{Kind: sources.KindPath, Ref: asset.Ref}
	if kind == sources.KindRepo {
		if repo == nil {
			return scanOutput{}, errors.New("scan: repo target was not resolved")
		}
		s, err := newGitHubSource(repo, deps)
		if err != nil {
			return scanOutput{}, err
		}
		src = s
		target = sources.Target{Kind: sources.KindRepo, AssetID: asset.ID, Ref: asset.Ref + "@" + repo.sha}
	}

	ws, err := src.Fetch(ctx, target)
	if err != nil {
		return scanOutput{}, err
	}
	defer func() { _ = ws.Close() }()

	result, scanErr := scanTarget(ctx, kind, deps.newScanners(), ws, asset, scanOpts)
	// Without a database there are no ignore decisions: every finding is open.
	result.open = result.Findings
	return result, scanErr
}

// newGitHubSource builds the source that downloads and extracts the resolved
// commit.
func newGitHubSource(repo *repoTarget, deps scanDeps) (sources.Source, error) {
	src, err := githubsource.New(repo.client, githubsource.Options{
		WorkspacesDir: deps.paths.WorkspacesDir(),
	})
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return src, nil
}

// finishWaiter is a jobs.Publisher that waits for one scan's final event. It
// ignores progress events and never blocks: Publish is called synchronously
// from the worker.
type finishWaiter struct {
	mu    sync.Mutex
	fired bool
	done  chan struct{}
}

func newFinishWaiter() *finishWaiter {
	return &finishWaiter{done: make(chan struct{})}
}

// Publish closes done once the first scan.finished event arrives.
func (w *finishWaiter) Publish(ev jobs.Event) {
	if ev.Type != jobs.EventFinished {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired {
		return
	}
	w.fired = true
	close(w.done)
}

// writeScanOutput prints the result in format.
func writeScanOutput(out io.Writer, format string, result scanOutput, toolVersion string) error {
	switch format {
	case scanFormatJSON:
		return writeJSON(out, result)
	case scanFormatSARIF:
		return writeJSON(out, sarif.Build(toolVersion, result.Findings))
	case scanFormatTable:
		return writeTable(out, result)
	default:
		return fmt.Errorf("scan: unsupported format %q", format)
	}
}

// writeJSON prints value as indented JSON, the shape every format reuses.
func writeJSON(out io.Writer, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

// writeTable prints one row per finding, most severe first, then a one-line
// summary. It is the format a human reads in a terminal.
func writeTable(out io.Writer, result scanOutput) error {
	list := slices.Clone(result.Findings)
	slices.SortStableFunc(list, func(a, b findings.Finding) int {
		if c := severityOrder(a.Severity) - severityOrder(b.Severity); c != 0 {
			return c
		}
		return strings.Compare(a.Title, b.Title)
	})

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SEVERITY\tTYPE\tRULE\tPACKAGE/LOCATION\tTITLE"); err != nil {
		return err
	}
	for _, f := range list {
		rule := f.RuleID
		if rule == "" {
			rule = "-"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			f.Severity, f.Type, rule, packageOrLocation(f), f.Title); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "\n%s\n", tableSummary(list))
	return err
}

// packageOrLocation is the PACKAGE/LOCATION cell: the affected package when
// the scanner named one, else the finding's location.
func packageOrLocation(f findings.Finding) string {
	switch {
	case f.PackageName == "":
		return f.Location
	case f.PackageVersion == "":
		return f.PackageName
	default:
		return f.PackageName + "@" + f.PackageVersion
	}
}

// tableSummary counts the findings per severity in one line.
func tableSummary(list []findings.Finding) string {
	counts := make(map[findings.Severity]int, 5)
	for _, f := range list {
		counts[f.Severity]++
	}
	if len(list) == 0 {
		return "0 findings"
	}
	parts := make([]string, 0, 5)
	for _, severity := range []findings.Severity{
		findings.SeverityCritical,
		findings.SeverityHigh,
		findings.SeverityMedium,
		findings.SeverityLow,
		findings.SeverityUnknown,
	} {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], severity))
		}
	}
	return fmt.Sprintf("%d findings: %s", len(list), strings.Join(parts, ", "))
}

// severityUnknownOrder sorts and ranks a severity outside the known scale.
const severityUnknownOrder = 4

// severityOrder ranks a severity, most severe first; unknown sorts last and is
// therefore never "at or above" a threshold.
func severityOrder(severity findings.Severity) int {
	switch severity {
	case findings.SeverityCritical:
		return 0
	case findings.SeverityHigh:
		return 1
	case findings.SeverityMedium:
		return 2
	case findings.SeverityLow:
		return 3
	default:
		return severityUnknownOrder
	}
}

// checkFailOn returns an error wrapping errFailOn when an open finding is at
// or above threshold. An empty threshold never fails.
func checkFailOn(threshold string, list []findings.Finding) error {
	if threshold == "" {
		return nil
	}
	limit := severityOrder(findings.Severity(threshold))
	if limit == severityUnknownOrder {
		return nil
	}
	breaches := 0
	for _, f := range list {
		if severityOrder(f.Severity) <= limit {
			breaches++
		}
	}
	if breaches == 0 {
		return nil
	}
	return fmt.Errorf("%w: %d finding(s) at or above %s", errFailOn, breaches, threshold)
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

// scanTarget runs every scanner that supports kind, normalizes the output and
// merges duplicate fingerprints (PROJECT_SPEC.md §5). A failing scanner is
// recorded in its scanner_run and the remaining scanners still contribute
// findings; the returned error names every failed scanner.
//
// It backs --no-store; a stored scan runs the same steps inside jobs.Manager.
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
