package assets

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

const (
	// ScheduleCheckInterval is how often the server looks for due scheduled
	// assets. It checks once at startup, then on this ticker.
	ScheduleCheckInterval = 5 * time.Minute
	// dailySchedule and weeklySchedule are the due intervals: a schedule is
	// due when its newest scan is at least this old.
	dailySchedule  = 24 * time.Hour
	weeklySchedule = 7 * 24 * time.Hour
)

// Scheduler queues scans for assets that carry a schedule. It runs only in
// `bastion serve`: the CLI and MCP server build no scheduler, so neither queues
// scans behind the user's back.
type Scheduler struct {
	service  *Service
	interval time.Duration
	// enqueue is service.Enqueue by default. Tests replace it to observe which
	// assets were queued and to fail one without a real scan pipeline.
	enqueue func(context.Context, []int64) ([]QueuedScan, error)

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	started bool
}

// NewScheduler builds a scheduler for one assets service. The clock comes from
// the service (WithClock in tests), so a pinned clock drives the due rule.
func NewScheduler(service *Service) (*Scheduler, error) {
	if service == nil {
		return nil, errors.New("assets: scheduler needs a service")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		service:  service,
		interval: ScheduleCheckInterval,
		enqueue:  service.Enqueue,
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}, nil
}

// Start launches the loop: one check immediately, then one per interval until
// Close. A second call is a no-op.
func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()

	go s.loop()
}

// Close stops the loop and waits for the current check to return, so no
// scheduler database call outlives the service graph it uses.
func (s *Scheduler) Close() {
	s.cancel()

	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if started {
		<-s.done
	}
}

// loop is the goroutine Close waits for.
func (s *Scheduler) loop() {
	defer close(s.done)

	s.runOnce(s.ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(s.ctx)
		}
	}
}

// runOnce enqueues one scan per due asset. A failure on one asset is logged
// and the loop continues with the rest; a shutdown in the middle stops it.
func (s *Scheduler) runOnce(ctx context.Context) {
	rows, err := sqlcdb.New(s.service.db).ListAssetScheduleTargets(ctx)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("scheduled scans: list due assets", "error", err)
		}
		return
	}

	queries := sqlcdb.New(s.service.db)
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		// An active scan already covers the asset; a second one would only
		// queue beside it. This is the same read the MCP handoff uses.
		if _, err := queries.GetActiveScanByAsset(ctx, row.ID); err == nil {
			continue
		} else if !errors.Is(err, sql.ErrNoRows) {
			slog.Warn("scheduled scans: read active scan", "asset", row.ID, "error", err)
			continue
		}

		last, err := parseTimestamp(row.LastScanAt)
		if err != nil {
			// An unreadable timestamp is treated as old, so the asset is
			// retried rather than silently skipped forever.
			last = nil
		}
		if !scheduleDue(row.ScanSchedule, last, s.service.now()) {
			continue
		}

		// ponytail: scheduled scans use the existing 'ui' trigger. scans.trigger
		// has no 'schedule' value and SQLite cannot widen that CHECK in place
		// without rebuilding a table findings reference, so this is the local
		// ceiling. The upgrade path is a table-rebuild migration that adds
		// 'schedule' to the CHECK, after which this call passes it. Never use
		// 'api': the MCP handoff poller claims those rows.
		if _, err := s.enqueue(ctx, []int64{row.ID}); err != nil {
			slog.Warn("scheduled scans: enqueue", "asset", row.ID, "error", err)
		}
	}
}

// scheduleDue reports whether a scheduled asset should be scanned now. An
// asset with no scan is always due; otherwise the newest scan (whatever its
// status, so a failed or canceled scan is retried only after the interval)
// must be at least the cadence old. An off or unknown cadence is never due.
func scheduleDue(schedule string, last *time.Time, now time.Time) bool {
	var interval time.Duration
	switch schedule {
	case ScheduleDaily:
		interval = dailySchedule
	case ScheduleWeekly:
		interval = weeklySchedule
	default:
		return false
	}
	if last == nil {
		return true
	}
	return !now.Before(last.Add(interval))
}
