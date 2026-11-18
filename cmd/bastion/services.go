package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/assets"
	awsclient "github.com/ozerozdas/bastion/internal/aws"
	"github.com/ozerozdas/bastion/internal/connections"
	"github.com/ozerozdas/bastion/internal/connections/github"
	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/events"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/licencepolicy"
	"github.com/ozerozdas/bastion/internal/localllm"
	"github.com/ozerozdas/bastion/internal/notifications"
	"github.com/ozerozdas/bastion/internal/preferences"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/scanners/depsdev"
	"github.com/ozerozdas/bastion/internal/scanners/eol"
	"github.com/ozerozdas/bastion/internal/scanners/govulncheck"
	"github.com/ozerozdas/bastion/internal/scanners/opengrep"
	"github.com/ozerozdas/bastion/internal/scanners/trivy"
	"github.com/ozerozdas/bastion/internal/servelock"
)

// serverServices is the service graph `bastion serve` and `bastion mcp` both
// build from the same database (PROJECT_SPEC.md §4): connections, the scan
// pipeline and the read models on top of it. Building it in one place keeps
// both entrypoints on the same behaviour instead of drifting apart.
type serverServices struct {
	db           *sql.DB
	releaseLock  func()
	events       *events.Broker
	connections  *connections.Service
	reports      *reports.Service
	assets       *assets.Service
	scheduler    *assets.Scheduler
	scanManager  *jobs.Manager
	trivyDB      *trivy.Manager
	epss         *epss.Service
	reachability *govulncheck.Service
	outdated     *depsdev.Service
	eol          *eol.Service
	sast         *opengrep.Service
	licence      *licencepolicy.Service
	preferences  *preferences.Service
	notify       *notifications.Service
	llm          *localllm.Service
}

// newServerServices opens the database and builds every service a server-mode
// process needs. The caller closes the result once, which stops the worker
// pool before releasing the database and the Trivy handles.
func newServerServices(ctx context.Context, paths app.Paths, port, concurrency int, deps serveDeps) (*serverServices, error) {
	if paths.DataDir == "" {
		return nil, errors.New("serve: data directory is not resolved")
	}
	// One serve per data directory. The lock also tells `bastion mcp` that a
	// server is running: a second manager would recover (fail) this one's scans
	// and race its Trivy database downloads. It is released when Close runs,
	// including when startup fails below.
	releaseLock, err := servelock.Acquire(paths.DataDir)
	if err != nil {
		return nil, fmt.Errorf("serve: %w", err)
	}
	// Database setup (migrations) must run even when the caller's context is
	// already canceled: tests start the server with an immediately canceled
	// context to exercise the shutdown path.
	openCtx := context.WithoutCancel(ctx)
	db, err := deps.openDB(openCtx, paths.DBPath())
	if err != nil {
		releaseLock()
		return nil, fmt.Errorf("open database: %w", err)
	}

	services := &serverServices{db: db, releaseLock: releaseLock, events: events.NewBroker()}
	ok := false
	defer func() {
		if !ok {
			services.Close()
		}
	}()

	secretStore := deps.newSecretStore()
	services.connections, err = connections.NewService(db, secretStore,
		connections.WithGitHubFactory(
			func(token string) (connections.GitHubClient, error) {
				return github.New(github.Config{Token: token, Version: version})
			},
		),
		connections.WithAWSFactory(
			func(profile, region string) (connections.AWSClient, error) {
				return awsclient.New(awsclient.Config{Profile: profile, Region: region, Version: version})
			},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create connections service: %w", err)
	}

	// The EPSS feed is opt-in and off by default; with the setting off its
	// Status call and every lookup are no-ops and no request is made.
	services.epss = newEPSSService(paths)
	// Go reachability is opt-in too (#37): off by default, so no govulncheck
	// process runs and findings carry no reachability.
	services.reachability = govulncheck.New(govulncheck.Config{DataDir: paths.DataDir})
	// Outdated-package lookup is opt-in (#38): off by default, so no request
	// reaches api.deps.dev and scans carry no outdated findings.
	services.outdated = depsdev.New(depsdev.Config{DataDir: paths.DataDir, Version: version})
	// The end-of-life lookup is opt-in too (#55): off means no request reaches
	// endoflife.date.
	services.eol = eol.New(eol.Config{DataDir: paths.DataDir, Version: version})
	// SAST is opt-in (#33): off by default, so nothing is downloaded and
	// repository scans are unchanged until the user turns it on.
	services.sast = newOpengrepModule(paths)

	services.reports, err = reports.NewService(db,
		reports.WithEPSS(services.epss),
		// The fix plan pull request (#47) edits a manifest through the GitHub
		// REST API with the repository asset's own connection token.
		reports.WithGitHub(
			func(token string) (reports.PullRequestClient, error) {
				return github.New(github.Config{Token: token, Version: version})
			},
			services.connections,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create reports service: %w", err)
	}

	// Notifications diff a succeeded scan against the previous one and post
	// the new counts to enabled notifiers (#44/#45). The Slack webhook lives
	// in the keyring; the link points back at this serve instance.
	services.notify, err = notifications.New(notifications.Config{
		DataDir: paths.DataDir,
		DB:      db,
		Secrets: secretStore,
		Reports: services.reports,
		BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
	})
	if err != nil {
		return nil, fmt.Errorf("create notifications service: %w", err)
	}

	// The licence policy is stored in SQLite and applied at read time (#39).
	services.licence, err = licencepolicy.NewService(db)
	if err != nil {
		return nil, fmt.Errorf("create licence policy service: %w", err)
	}

	// UI preferences follow the install rather than one browser origin (#150).
	services.preferences, err = preferences.NewService(db)
	if err != nil {
		return nil, fmt.Errorf("create preferences service: %w", err)
	}

	// The optional local model is off by default and only ever reaches a
	// loopback endpoint (ADR-003, #48).
	services.llm, err = localllm.New(localllm.Config{DataDir: paths.DataDir})
	if err != nil {
		return nil, fmt.Errorf("create local model service: %w", err)
	}

	// One broker feeds both the scan workers (publish) and the subscribers
	// (the UI's SSE endpoint; MCP leaves it unused), so every lifecycle event
	// of a scan shares one bus.
	// One manager backs both the scan pipeline and /api/trivy-db, so a download
	// started in the UI is the one a scan waits for instead of a second one.
	services.trivyDB = trivy.NewManager(paths.TrivyCacheDir())
	services.scanManager, err = newServerScanManager(ctx, db, paths, concurrency,
		services.connections, secretStore, services.events, services.trivyDB,
		services.outdated, services.eol, services.reachability, services.sast, services.notify)
	if err != nil {
		return nil, err
	}

	services.assets, err = assets.NewService(db,
		assets.WithScanManager(services.scanManager),
		assets.WithGitHub(
			func(token string) (assets.RepoClient, error) {
				return github.New(github.Config{Token: token, Version: version})
			},
			services.connections,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create assets service: %w", err)
	}

	// Scheduled scans (#58) run only while this serve process is up. The
	// scheduler checks once now and then every five minutes; Close stops it
	// before the scan workers, so a queued scan still makes it into the pool.
	services.scheduler, err = assets.NewScheduler(services.assets)
	if err != nil {
		return nil, fmt.Errorf("create scan scheduler: %w", err)
	}
	services.scheduler.Start()

	ok = true
	return services, nil
}

// Close stops the scan workers, so a running scan is persisted as canceled
// instead of being cut off by process exit, then releases the Trivy manager,
// the database and the serve lock.
func (s *serverServices) Close() {
	if s.scheduler != nil {
		s.scheduler.Close()
	}
	if s.scanManager != nil {
		stopScanManager(s.scanManager)
	}
	if s.trivyDB != nil {
		s.trivyDB.Close()
	}
	if s.db != nil {
		_ = s.db.Close()
	}
	if s.releaseLock != nil {
		s.releaseLock()
	}
}
