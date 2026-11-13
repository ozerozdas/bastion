package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// run executes one scan: resolve, fetch, scan, merge and persist. Every exit
// path ends in exactly one final status, so no scan can be left running.
func (m *Manager) run(job *scanJob) {
	ctx := job.ctx
	res := store.ScanResult{ScannerRuns: []store.ScannerRun{}}

	// A scan canceled while queued must not appear as running.
	if ctx.Err() != nil {
		m.finish(job, res, "", store.ScanStatusCanceled, "")
		return
	}

	startedAt := time.Now().UTC().Format(time.RFC3339)
	if err := m.queries.MarkScanRunning(ctx, sqlcdb.MarkScanRunningParams{
		StartedAt: sql.NullString{String: startedAt, Valid: true},
		ID:        job.scanID,
	}); err != nil {
		// A scan canceled at this instant never became running; canceling it
		// from here keeps the final status truthful.
		m.finishAfterError(ctx, job, res, "", fmt.Errorf("mark scan running: %w", err))
		return
	}

	m.progress(job, StageResolve, "")
	target, targetRef, err := m.resolve(ctx, job.asset)
	if err != nil {
		m.finishAfterError(ctx, job, res, targetRef, fmt.Errorf("resolve target: %w", err))
		return
	}

	m.progress(job, StageFetch, "")
	src, ok := m.sources[target.Kind]
	if !ok {
		m.finish(job, res, targetRef, store.ScanStatusFailed,
			fmt.Sprintf("no source for target kind %q", target.Kind))
		return
	}
	ws, err := src.Fetch(ctx, target)
	if err != nil {
		m.finishAfterError(ctx, job, res, targetRef, fmt.Errorf("fetch %s: %w", target.Ref, err))
		return
	}
	if ws == nil {
		m.finish(job, res, targetRef, store.ScanStatusFailed, "source returned no workspace")
		return
	}

	failures := m.collect(ctx, job, ws, target, &res)

	// The workspace is removed before the result is persisted: once a caller
	// sees the final status, nothing this scan created is still on disk.
	if err := ws.Close(); err != nil {
		slog.Warn("jobs: remove workspace", "scan_id", job.scanID, "error", err)
	}

	switch {
	case ctx.Err() != nil:
		m.finish(job, res, targetRef, store.ScanStatusCanceled, "")
	case len(failures) > 0:
		m.finish(job, res, targetRef, store.ScanStatusFailed,
			fmt.Sprintf("scanner failed: %s", strings.Join(failures, ", ")))
	default:
		m.finish(job, res, targetRef, store.ScanStatusSucceeded, "")
	}
}

// collect runs every scanner that supports the target kind, normalizes and
// merges the output, and returns the names of scanners that failed. A failing
// scanner never discards another scanner's findings.
func (m *Manager) collect(ctx context.Context, job *scanJob, ws *sources.Workspace, target sources.Target, res *store.ScanResult) []string {
	asset := findings.Asset{
		ID:          job.asset.ID,
		Kind:        findings.AssetKind(job.asset.Kind),
		DisplayName: job.asset.DisplayName,
		Ref:         target.Ref,
	}

	var failures []string
	for _, sc := range m.scanners {
		if !sc.Supports(target.Kind) {
			continue
		}
		if ctx.Err() != nil {
			break
		}

		run := store.ScannerRun{
			Scanner:        sc.Name(),
			ScannerVersion: sc.Version(),
			Status:         "succeeded",
		}
		release, err := m.acquireScanner(ctx, sc)
		if err != nil {
			// Canceled while waiting for a serialized scanner: the scanner
			// never ran, but the run is part of the scan's history.
			run.Status = "canceled"
			run.Error = err.Error()
			res.ScannerRuns = append(res.ScannerRuns, run)
			break
		}

		m.progress(job, StageScan, sc.Name())
		start := time.Now()
		// The options copy is per scanner: Progress publishes the stage the
		// adapter is waiting on as an ordinary progress event for this scan.
		scanOpts := m.options
		scanOpts.Progress = func(stage string) {
			m.progress(job, stage, sc.Name())
		}
		fs, pkgs, scanErr := m.runScanner(ctx, job, sc, ws, scanOpts, asset)
		duration := time.Since(start).Milliseconds()
		run.DurationMS = &duration
		release()

		switch {
		case scanErr != nil && ctx.Err() != nil:
			run.Status = "canceled"
			run.Error = scanErr.Error()
		case scanErr != nil:
			run.Status = "failed"
			run.Error = scanErr.Error()
			failures = append(failures, sc.Name())
		default:
			res.Findings = append(res.Findings, fs...)
			res.Packages = append(res.Packages, pkgs...)
		}
		res.ScannerRuns = append(res.ScannerRuns, run)
	}

	// OSV matches the inventory the scanners produced, not the workspace, so
	// it runs once over the merged packages. A failure is recorded and logged
	// but never added to failures: advisories are an enrichment, and a
	// network error must not fail a scan whose findings are complete.
	if m.advisories != nil && len(res.Packages) > 0 && ctx.Err() == nil {
		m.progress(job, StageScan, m.advisories.Name())
		run := store.ScannerRun{
			Scanner:        m.advisories.Name(),
			ScannerVersion: m.advisories.Version(),
			Status:         "succeeded",
		}
		start := time.Now()
		afs, advErr := m.advisories.Match(ctx, res.Packages, asset)
		duration := time.Since(start).Milliseconds()
		run.DurationMS = &duration
		switch {
		case advErr != nil && ctx.Err() != nil:
			run.Status = "canceled"
			run.Error = advErr.Error()
		case advErr != nil:
			slog.Warn("jobs: OSV advisory lookup failed", "scan_id", job.scanID, "error", advErr)
			run.Status = "failed"
			run.Error = advErr.Error()
		default:
			res.Findings = append(res.Findings, afs...)
		}
		res.ScannerRuns = append(res.ScannerRuns, run)
	}

	// One finding per fingerprint per scan (PROJECT_SPEC.md §5), in a stable
	// order so persistence and golden output do not depend on scanner order.
	res.Findings = findings.Merge(res.Findings)
	findings.SortFindings(res.Findings)
	findings.SortPackages(res.Packages)
	return failures
}

// runScanner scans one workspace and normalizes the raw output.
func (m *Manager) runScanner(ctx context.Context, job *scanJob, sc scanners.Scanner, ws *sources.Workspace, opts scanners.Options, asset findings.Asset) ([]findings.Finding, []findings.Package, error) {
	norm := m.normalizers[sc.Name()]
	if norm == nil {
		return nil, nil, fmt.Errorf("%s: no normalizer configured", sc.Name())
	}

	raw, err := sc.Scan(ctx, ws, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", sc.Name(), err)
	}
	m.progress(job, StageNormalize, sc.Name())
	fs, pkgs, err := norm.Normalize(raw, asset)
	if err != nil {
		return nil, nil, fmt.Errorf("normalize %s: %w", sc.Name(), err)
	}
	return fs, pkgs, nil
}

// finishAfterError records a failed stage, or canceled when the context ended
// while the stage was running.
func (m *Manager) finishAfterError(ctx context.Context, job *scanJob, res store.ScanResult, targetRef string, err error) {
	if ctx.Err() != nil {
		m.finish(job, res, targetRef, store.ScanStatusCanceled, "")
		return
	}
	m.finish(job, res, targetRef, store.ScanStatusFailed, err.Error())
}

// finish persists one final scan state and publishes it. Persistence ignores
// the job context: canceling a scan must not prevent its final row from
// landing.
func (m *Manager) finish(job *scanJob, res store.ScanResult, targetRef, status, errMsg string) {
	res.Status = status
	res.TargetRef = targetRef
	res.Error = errMsg
	res.FinishedAt = time.Now()
	if res.ScannerRuns == nil {
		res.ScannerRuns = []store.ScannerRun{}
	}

	if err := store.SaveScanResult(context.WithoutCancel(job.ctx), m.db, job.scanID, res); err != nil {
		slog.Error("jobs: persist scan result", "scan_id", job.scanID, "error", err)
		m.publish(Event{
			Type:    EventFinished,
			ScanID:  job.scanID,
			AssetID: job.asset.ID,
			Status:  status,
			Error:   fmt.Sprintf("persist scan result: %v", err),
		})
		return
	}
	m.publish(Event{
		Type:    EventFinished,
		ScanID:  job.scanID,
		AssetID: job.asset.ID,
		Status:  status,
		Error:   errMsg,
	})
}
