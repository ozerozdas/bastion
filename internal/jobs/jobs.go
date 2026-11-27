// Package jobs owns the scan queue and its worker pool (PROJECT_SPEC.md §4).
//
// Enqueue records a scan as queued and hands it to a small pool of workers. A
// worker marks the scan running, fetches the target into a workspace, runs
// every scanner that supports the target kind, normalizes and merges the
// output, and persists one final store.ScanResult.
//
// Scans are cancelable at any point. A scan canceled while queued never
// fetches anything; one canceled while running stops at the next context
// check. Either way the final status is canceled, findings produced before the
// cancellation are kept, and the workspace is removed before the result is
// persisted.
package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// DefaultConcurrency is the worker count used when Config.Concurrency is zero.
// Two workers let a Gitleaks scan run beside a Trivy scan (PROJECT_SPEC.md §4,
// ADR-001).
const DefaultConcurrency = 2

// Scan statuses the worker sets itself. Final statuses come from store.
const (
	statusQueued  = "queued"
	statusRunning = "running"
)

// handoffPollInterval is how often the server looks for scans `bastion mcp`
// queued for it. Two seconds keeps a tool call responsive without polling the
// database in a tight loop.
const handoffPollInterval = 2 * time.Second

// RecoveryError is stored on scans that were left unfinished by a process
// that stopped mid-scan.
const RecoveryError = "bastion stopped during scan"

var (
	// ErrScanNotActive is returned by Cancel for a scan that is unknown,
	// already finished or already canceled by a concurrent caller.
	ErrScanNotActive = errors.New("jobs: scan is not active")
	// ErrShutdown is returned by Enqueue once the manager stopped accepting
	// scans.
	ErrShutdown = errors.New("jobs: manager is shut down")
)

// EventType identifies an event published on the scan bus.
type EventType string

// Event types consumed by the SSE endpoint (BST-023).
const (
	// EventQueued is published when a scan row is created.
	EventQueued EventType = "scan.queued"
	// EventProgress is published for each pipeline stage and scanner.
	EventProgress EventType = "scan.progress"
	// EventFinished is published once the final state is persisted.
	EventFinished EventType = "scan.finished"
)

// Pipeline stages reported in Event.Stage.
const (
	StageResolve   = "resolve"
	StageFetch     = "fetch"
	StageScan      = "scan"
	StageNormalize = "normalize"
)

// Event is one scan lifecycle notification. Stage and Scanner are set on
// progress events; Error is set on failed and finished events.
type Event struct {
	Type    EventType
	ScanID  int64
	AssetID int64
	// Status is the scan status the event refers to (queued, running, or a
	// final status).
	Status string
	// Stage is the pipeline stage of a progress event.
	Stage string
	// Scanner names the scanner a progress event belongs to, when any.
	Scanner string
	// Error is the failure message for a failed scan.
	Error string
}

// Publisher receives scan events. Publish is called synchronously from the
// worker, so implementations must not block. A nil Publisher is replaced by a
// no-op publisher.
type Publisher interface {
	Publish(Event)
}

// CompletionListener is told about a scan that succeeded, after its result is
// persisted. The manager calls it on its own goroutine with no scan context, so
// a slow external service can never delay a worker or be canceled by the job.
type CompletionListener interface {
	ScanSucceeded(scanID, assetID int64)
}

type nopPublisher struct{}

func (nopPublisher) Publish(Event) {}

// AdvisoryMatcher enriches a scan's package inventory with advisories from an
// external database. It is not a Scanner: it reads the packages other scanners
// produced rather than the workspace, so it runs once after they finish.
type AdvisoryMatcher interface {
	// Name is the stable scanner id stored in scanner_runs.
	Name() string
	// Version identifies the advisory source's API surface.
	Version() string
	// Match returns findings for the inventory. An error means the lookup
	// failed; the scan's own findings are unaffected.
	Match(ctx context.Context, packages []findings.Package, asset findings.Asset) ([]findings.Finding, error)
}

// enabledMatcher is the optional half of an AdvisoryMatcher that is opt-in.
// A matcher without it is always on, which keeps the OSV lookup's default.
type enabledMatcher interface {
	// Enabled reports the stored opt-in setting.
	Enabled() bool
}

// matcherEnabled reports whether matcher should run. An advisory matcher that
// does not implement Enabled is always on.
func matcherEnabled(matcher AdvisoryMatcher) bool {
	if toggle, ok := matcher.(enabledMatcher); ok {
		return toggle.Enabled()
	}
	return true
}

// OutdatedMatcher enriches a scan's package inventory with latest-version
// findings from deps.dev (#38). Like an AdvisoryMatcher it reads the packages
// other scanners produced rather than the workspace. It is opt-in: Enabled is
// false by default and then no request is made.
type OutdatedMatcher interface {
	// Name is the stable scanner id stored in scanner_runs.
	Name() string
	// Version identifies the API surface the lookup speaks.
	Version() string
	// Enabled reports the stored opt-in setting.
	Enabled() bool
	// Match returns outdated findings for the inventory and warnings for
	// partial coverage. An error means the lookup could not run (for example
	// the scan was canceled); it never fails the scan.
	Match(ctx context.Context, packages []findings.Package, asset findings.Asset) ([]findings.Finding, []string, error)
}

// EOLMatcher reports end-of-life operating systems and runtimes (#55). It is
// opt-in: Enabled is false by default and then no request is made.
type EOLMatcher interface {
	// Name is the stable scanner id stored in scanner_runs.
	Name() string
	// Version identifies the API surface the lookup speaks.
	Version() string
	// Enabled reports the stored opt-in setting.
	Enabled() bool
	// Match returns findings and warnings for partial coverage. An error
	// means the lookup could not run; it never fails the scan.
	Match(ctx context.Context, osFamily, osName string, packages []findings.Package, asset findings.Asset) ([]findings.Finding, []string, error)
}

// ReachabilityEnricher classifies Go vulnerability findings as reachable,
// unreachable or unknown (#37). It reads the workspace rather than the package
// inventory, so it runs once after the scanners finish. A failure is recorded
// and logged but never fails the scan.
type ReachabilityEnricher interface {
	// Name is the stable scanner id stored in scanner_runs.
	Name() string
	// Version identifies the analyzer's release.
	Version() string
	// Enabled reports the stored opt-in setting.
	Enabled() bool
	// Enrich marks the Go vulnerability findings of the workspace in place.
	// ran is false when nothing was attempted: the setting is off or the
	// workspace holds no Go module.
	Enrich(ctx context.Context, dir string, findings []findings.Finding) (ran bool, err error)
}

// Asset is the target a scan was enqueued for, copied from the store at
// enqueue time so a worker does not depend on the asset row still existing.
type Asset struct {
	ID          int64
	Kind        sources.TargetKind
	Ref         string
	DisplayName string
}

// ResolveFunc turns an asset into a fetchable target and the resolved ref that
// belongs in scans.target_ref (a git SHA or image digest).
//
// Repo assets need a SHA, which requires a connection token and therefore
// internal/connections; wiring that resolver is BST-024's job. The default
// resolver uses the asset ref unchanged and leaves the resolved ref empty.
type ResolveFunc func(ctx context.Context, asset Asset) (sources.Target, string, error)

// Config wires a Manager. DB is required; a Manager without sources or
// scanners still accepts scans and fails them with a clear message.
type Config struct {
	// DB is the SQLite handle scans are written to.
	DB *sql.DB
	// Sources resolves a target kind to its fetcher.
	Sources map[sources.TargetKind]sources.Source
	// Scanners are run for every scan that they support.
	Scanners []scanners.Scanner
	// Normalizers maps a scanner name to the normalizer for its output. A
	// scanner without one fails its scanner_run instead of running unnormalized.
	Normalizers map[string]findings.Normalizer
	// Advisories enriches the merged package inventory with external
	// advisories. Nil disables the lookup; a failure never fails the scan.
	Advisories AdvisoryMatcher
	// MalwareIndex enriches the merged package inventory with malicious-package
	// advisories matched locally (#203). Nil disables the lookup; a failure
	// never fails the scan.
	MalwareIndex AdvisoryMatcher
	// Outdated enriches the merged package inventory with latest-version
	// findings. Nil disables the lookup; a failure never fails the scan.
	Outdated OutdatedMatcher
	// EOL reports end-of-life operating systems and runtimes; nil disables it.
	EOL EOLMatcher
	// Reachability classifies Go vulnerabilities as reachable, unreachable or
	// unknown. Nil disables the enrichment; a failure never fails the scan.
	Reachability ReachabilityEnricher
	// Options is called once at construction; the result is passed to every
	// scanner (cache dir, HMAC key).
	Options func() scanners.Options
	// Concurrency is the number of workers. Zero means DefaultConcurrency.
	Concurrency int
	// Events receives lifecycle events. Nil means no events.
	Events Publisher
	// Notify is told after a scan succeeds, on its own goroutine. Nil means
	// no notification hook.
	Notify CompletionListener
	// Resolve resolves an asset's target. Nil means the asset ref is used
	// as-is.
	Resolve ResolveFunc
}

// Manager is the scan queue and its worker pool. It is safe for concurrent
// use. Call Shutdown (or Close) once; Enqueue rejects work afterwards.
type Manager struct {
	db           *sql.DB
	queries      *sqlcdb.Queries
	sources      map[sources.TargetKind]sources.Source
	scanners     []scanners.Scanner
	normalizers  map[string]findings.Normalizer
	options      scanners.Options
	events       Publisher
	resolve      ResolveFunc
	notify       CompletionListener
	advisories   AdvisoryMatcher
	malwareIndex AdvisoryMatcher
	outdated     OutdatedMatcher
	eol          EOLMatcher
	reachability ReachabilityEnricher

	runCtx  context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup
	done    chan struct{}

	mu     sync.Mutex
	cond   *sync.Cond
	queue  []*scanJob
	jobs   map[int64]*scanJob
	serial map[string]chan struct{}
	// handoff holds the scan ids the poller already pushed, so a row that is
	// still queued when the next poll runs is not queued twice.
	handoff        map[int64]struct{}
	handoffStarted bool
	closed         bool
}

// scanJob is one queued or running scan. state, jobs and queue are guarded by
// Manager.mu; ctx and cancel belong to the job alone.
type scanJob struct {
	scanID int64
	asset  Asset
	ctx    context.Context
	cancel context.CancelFunc
	state  jobState
}

type jobState int

const (
	stateQueued jobState = iota
	stateRunning
	stateFinished
)

// New validates cfg and starts the worker pool. Workers live until Shutdown.
func New(cfg Config) (*Manager, error) {
	if cfg.DB == nil {
		return nil, errors.New("jobs: database is required")
	}
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	events := cfg.Events
	if events == nil {
		events = nopPublisher{}
	}
	resolve := cfg.Resolve
	if resolve == nil {
		resolve = defaultResolve
	}
	var options scanners.Options
	if cfg.Options != nil {
		options = cfg.Options()
	}

	runCtx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		db:           cfg.DB,
		queries:      sqlcdb.New(cfg.DB),
		sources:      cfg.Sources,
		scanners:     cfg.Scanners,
		normalizers:  cfg.Normalizers,
		options:      options,
		events:       events,
		resolve:      resolve,
		notify:       cfg.Notify,
		advisories:   cfg.Advisories,
		malwareIndex: cfg.MalwareIndex,
		outdated:     cfg.Outdated,
		eol:          cfg.EOL,
		reachability: cfg.Reachability,
		runCtx:       runCtx,
		cancel:       cancel,
		done:         make(chan struct{}),
		jobs:         make(map[int64]*scanJob),
		serial:       make(map[string]chan struct{}),
		handoff:      make(map[int64]struct{}),
	}
	m.cond = sync.NewCond(&m.mu)

	m.workers.Add(concurrency)
	for range concurrency {
		go m.worker()
	}
	// One watcher instead of a goroutine per Shutdown call.
	go func() {
		m.workers.Wait()
		close(m.done)
	}()
	return m, nil
}

// defaultResolve uses the asset ref as the source ref and leaves the resolved
// ref empty.
func defaultResolve(_ context.Context, asset Asset) (sources.Target, string, error) {
	return sources.Target{Kind: asset.Kind, AssetID: asset.ID, Ref: asset.Ref}, "", nil
}

// Enqueue creates a queued scan row for assetID and hands it to the pool. The
// returned scan id is the one the UI and cancel endpoint use.
//
// ctx only bounds the database calls; the scan itself runs on the manager's
// context so it survives the request that started it.
func (m *Manager) Enqueue(ctx context.Context, assetID int64, trigger string) (int64, error) {
	if trigger == "" {
		return 0, errors.New("jobs: enqueue: trigger is required")
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return 0, ErrShutdown
	}

	asset, err := m.queries.GetAsset(ctx, assetID)
	if err != nil {
		return 0, fmt.Errorf("jobs: enqueue asset %d: %w", assetID, err)
	}
	scan, err := m.queries.CreateScan(ctx, sqlcdb.CreateScanParams{
		AssetID: assetID,
		Status:  statusQueued,
		Trigger: trigger,
	})
	if err != nil {
		return 0, fmt.Errorf("jobs: enqueue asset %d: create scan: %w", assetID, err)
	}

	// Publish before handing the job to the pool so subscribers see queued
	// first; the worker may publish progress immediately afterwards.
	m.publish(Event{Type: EventQueued, ScanID: scan.ID, AssetID: assetID, Status: statusQueued})

	job := newScanJob(m.runCtx, scan.ID, Asset{
		ID:          asset.ID,
		Kind:        sources.TargetKind(asset.Kind),
		Ref:         asset.Ref,
		DisplayName: asset.DisplayName,
	})
	if err := m.startJob(job); err != nil {
		// Shutdown started between the check above and here. Record the row
		// as canceled rather than leaving a queued scan nobody will run.
		job.state = stateFinished
		m.finishCanceled(ctx, job)
		return 0, err
	}

	return scan.ID, nil
}

// newScanJob builds the in-memory job for an existing scan row. Its context
// derives from the manager's run context, so Shutdown cancels it.
func newScanJob(runCtx context.Context, scanID int64, asset Asset) *scanJob {
	jobCtx, cancel := context.WithCancel(runCtx)
	return &scanJob{scanID: scanID, asset: asset, ctx: jobCtx, cancel: cancel, state: stateQueued}
}

// startJob hands job to the pool. ErrShutdown means the manager stopped before
// accepting it; the caller decides what the scan row becomes.
func (m *Manager) startJob(job *scanJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		job.cancel()
		return ErrShutdown
	}
	m.jobs[job.scanID] = job
	m.queue = append(m.queue, job)
	m.cond.Signal()
	return nil
}

// Cancel stops a queued or running scan. A queued scan never touches the
// source and is persisted as canceled before Cancel returns. A running scan is
// signaled and ends in canceled once its worker observes the context; the
// worker publishes EventFinished after persisting.
//
// Unknown, finished and already-canceled scans return ErrScanNotActive.
func (m *Manager) Cancel(scanID int64) error {
	m.mu.Lock()
	job, ok := m.jobs[scanID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: %d", ErrScanNotActive, scanID)
	}
	job.cancel()
	if job.state != stateQueued {
		m.mu.Unlock()
		return nil
	}
	m.removeLocked(scanID)
	m.mu.Unlock()

	job.state = stateFinished
	m.finishCanceled(context.Background(), job)
	return nil
}

// Recover marks scans left running by an earlier process as failed, and so
// queued scans that only that process's worker pool could have picked up.
// Queued scans written by the MCP handoff (trigger 'api') stay queued: the
// poller started after Recover claims them, so a handoff row survives a serve
// restart. Recover must therefore run before StartHandoff.
func (m *Manager) Recover(ctx context.Context) error {
	finishedAt := time.Now().UTC().Format(time.RFC3339)
	if err := m.queries.FailUnfinishedScans(ctx, sqlcdb.FailUnfinishedScansParams{
		FinishedAt: sql.NullString{String: finishedAt, Valid: true},
		Error:      sql.NullString{String: RecoveryError, Valid: true},
	}); err != nil {
		return fmt.Errorf("jobs: recover unfinished scans: %w", err)
	}
	return nil
}

// StartHandoff starts the poller that picks up scans `bastion mcp` queued in
// the database. It is called by `bastion serve` once, after Recover: Recover
// leaves those rows queued, and the poller claims them.
//
// The CLI and tests that never call StartHandoff never poll.
func (m *Manager) StartHandoff() {
	m.mu.Lock()
	if m.closed || m.handoffStarted {
		m.mu.Unlock()
		return
	}
	m.handoffStarted = true
	// Counted before the goroutine starts, under the same lock Shutdown takes,
	// so its Wait sees the poller.
	m.workers.Add(1)
	m.mu.Unlock()

	go m.pollHandoff()
}

// pollHandoff claims handed-off scans once immediately and then every
// handoffPollInterval until the manager stops.
func (m *Manager) pollHandoff() {
	defer m.workers.Done()

	m.claimHandoff(m.runCtx)
	ticker := time.NewTicker(handoffPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.runCtx.Done():
			return
		case <-ticker.C:
			m.claimHandoff(m.runCtx)
		}
	}
}

// claimHandoff pushes every queued handoff scan (trigger 'api') this manager
// has not accepted yet into the pool under its own scan id. The accepted set
// makes a poll idempotent: the row stays 'queued' until a worker marks it
// running, so the next poll can still see it.
func (m *Manager) claimHandoff(ctx context.Context) {
	rows, err := m.queries.ListQueuedScansByTrigger(ctx, store.ScanTriggerAPI)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("jobs: list handed-off scans", "error", err)
		}
		return
	}
	for _, row := range rows {
		m.claimHandoffScan(ctx, row)
	}
}

// claimHandoffScan accepts one handed-off scan, unless it was accepted before
// or the manager is shutting down.
func (m *Manager) claimHandoffScan(ctx context.Context, row sqlcdb.Scan) {
	asset, err := m.queries.GetAsset(ctx, row.AssetID)
	if errors.Is(err, sql.ErrNoRows) {
		// The asset went away and the scan row with it.
		return
	}
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("jobs: read asset of handed-off scan", "scan_id", row.ID, "error", err)
		}
		return
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if _, ok := m.handoff[row.ID]; ok {
		m.mu.Unlock()
		return
	}
	m.handoff[row.ID] = struct{}{}
	m.mu.Unlock()

	// The row was created by another process, so this process never published
	// its queued event; subscribers should learn about the scan before the
	// worker reports progress for it.
	m.publish(Event{Type: EventQueued, ScanID: row.ID, AssetID: row.AssetID, Status: statusQueued})

	job := newScanJob(m.runCtx, row.ID, Asset{
		ID:          asset.ID,
		Kind:        sources.TargetKind(asset.Kind),
		Ref:         asset.Ref,
		DisplayName: asset.DisplayName,
	})
	if err := m.startJob(job); err != nil {
		// Shutdown won the race between the two locks. The row stays queued and
		// the next serve's Recover marks it failed.
		slog.Warn("jobs: handed-off scan left queued", "scan_id", row.ID)
	}
}

// Shutdown stops accepting scans, cancels every queued and running scan, and
// waits for the workers to finish. It returns ctx.Err() when ctx expires
// before the workers do; the workers still finish on their own.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		// Every job context derives from runCtx, so this cancels queued and
		// running scans alike.
		m.cancel()
		m.cond.Broadcast()
	}
	m.mu.Unlock()

	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close is Shutdown without a deadline.
func (m *Manager) Close() error {
	return m.Shutdown(context.Background())
}

// worker pops jobs until the manager is closed and the queue is drained. A
// job canceled while queued is picked up with an already-canceled context and
// records itself as canceled without fetching.
func (m *Manager) worker() {
	defer m.workers.Done()
	for {
		m.mu.Lock()
		for len(m.queue) == 0 && !m.closed {
			m.cond.Wait()
		}
		if len(m.queue) == 0 {
			m.mu.Unlock()
			return
		}
		job := m.queue[0]
		m.queue = m.queue[1:]
		job.state = stateRunning
		m.mu.Unlock()

		m.run(job)

		m.mu.Lock()
		job.state = stateFinished
		delete(m.jobs, job.scanID)
		// The scan is final, so the poller will never select it again; drop
		// the accepted entry instead of growing the set for the manager's life.
		delete(m.handoff, job.scanID)
		m.mu.Unlock()
		job.cancel()
	}
}

// removeLocked drops a still-queued job. The caller holds m.mu.
func (m *Manager) removeLocked(scanID int64) {
	for i, queued := range m.queue {
		if queued.scanID == scanID {
			m.queue = append(m.queue[:i], m.queue[i+1:]...)
			break
		}
	}
	delete(m.jobs, scanID)
}

// finishCanceled persists a scan that never entered the pipeline (canceled
// while queued, or enqueued while shutting down).
func (m *Manager) finishCanceled(ctx context.Context, job *scanJob) {
	res := store.ScanResult{
		Status:      store.ScanStatusCanceled,
		ScannerRuns: []store.ScannerRun{},
	}
	if err := store.SaveScanResult(context.WithoutCancel(ctx), m.db, job.scanID, res); err != nil {
		m.publish(Event{
			Type:    EventFinished,
			ScanID:  job.scanID,
			AssetID: job.asset.ID,
			Status:  store.ScanStatusCanceled,
			Error:   err.Error(),
		})
		return
	}
	m.publish(Event{
		Type:    EventFinished,
		ScanID:  job.scanID,
		AssetID: job.asset.ID,
		Status:  store.ScanStatusCanceled,
	})
}

// acquireScanner blocks until it is this scan's turn to run sc, for scanners
// that report they cannot run concurrently (ADR-001: Trivy). It returns a
// release function, or ctx.Err() when the scan is canceled while waiting.
//
// trivy.ScanFS also holds a process-wide lock; this one keeps a Trivy scan
// from occupying a worker while it waits for that lock, and states the
// requirement where the pool can see it.
func (m *Manager) acquireScanner(ctx context.Context, sc scanners.Scanner) (func(), error) {
	serial, ok := sc.(SerialScanner)
	if !ok || !serial.Serialized() {
		return func() {}, nil
	}

	m.mu.Lock()
	sem := m.serial[sc.Name()]
	if sem == nil {
		sem = make(chan struct{}, 1)
		m.serial[sc.Name()] = sem
	}
	m.mu.Unlock()

	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// publish delivers ev unless there is no subscriber.
func (m *Manager) publish(ev Event) {
	m.events.Publish(ev)
}

// progress publishes one pipeline-stage event.
func (m *Manager) progress(job *scanJob, stage, scanner string) {
	m.publish(Event{
		Type:    EventProgress,
		ScanID:  job.scanID,
		AssetID: job.asset.ID,
		Status:  statusRunning,
		Stage:   stage,
		Scanner: scanner,
	})
}

// SerialScanner is implemented by a scanner whose library state cannot run
// concurrently with another run of the same scanner in one process. The pool
// serializes those scanners by name (ADR-001).
type SerialScanner interface {
	Serialized() bool
}
