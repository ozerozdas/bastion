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
	"github.com/ozerozdas/bastion/internal/preferences"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/scanners/depsdev"
	"github.com/ozerozdas/bastion/internal/scanners/govulncheck"
	"github.com/ozerozdas/bastion/internal/scanners/opengrep"
	"github.com/ozerozdas/bastion/internal/scanners/trivy"
)

// serverServices is the service graph `bastion serve` and `bastion mcp` both
// build from the same database (PROJECT_SPEC.md §4): connections, the scan
// pipeline and the read models on top of it. Building it in one place keeps
// both entrypoints on the same behaviour instead of drifting apart.
type serverServices struct {
	db           *sql.DB
	events       *events.Broker
	connections  *connections.Service
	reports      *reports.Service
	assets       *assets.Service
	scanManager  *jobs.Manager
	trivyDB      *trivy.Manager
	epss         *epss.Service
	reachability *govulncheck.Service
	outdated     *depsdev.Service
	sast         *opengrep.Service
	licence      *licencepolicy.Service
	preferences  *preferences.Service
}

// newServerServices opens the database and builds every service a server-mode
// process needs. The caller closes the result once, which stops the worker
// pool before releasing the database and the Trivy handles.
func newServerServices(ctx context.Context, paths app.Paths, concurrency int, deps serveDeps) (*serverServices, error) {
	if paths.DataDir == "" {
		return nil, errors.New("serve: data directory is not resolved")
	}
	// Database setup (migrations) must run even when the caller's context is
	// already canceled: tests start the server with an immediately canceled
	// context to exercise the shutdown path.
	openCtx := context.WithoutCancel(ctx)
	db, err := deps.openDB(openCtx, paths.DBPath())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	services := &serverServices{db: db, events: events.NewBroker()}
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
	// SAST is opt-in (#33): off by default, so nothing is downloaded and
	// repository scans are unchanged until the user turns it on.
	services.sast = newOpengrepModule(paths)

	services.reports, err = reports.NewService(db, reports.WithEPSS(services.epss))
	if err != nil {
		return nil, fmt.Errorf("create reports service: %w", err)
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

	// One broker feeds both the scan workers (publish) and the subscribers
	// (the UI's SSE endpoint; MCP leaves it unused), so every lifecycle event
	// of a scan shares one bus.
	// One manager backs both the scan pipeline and /api/trivy-db, so a download
	// started in the UI is the one a scan waits for instead of a second one.
	services.trivyDB = trivy.NewManager(paths.TrivyCacheDir())
	services.scanManager, err = newServerScanManager(ctx, db, paths, concurrency,
		services.connections, secretStore, services.events, services.trivyDB,
		services.outdated, services.reachability, services.sast)
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

	ok = true
	return services, nil
}

// Close stops the scan workers, so a running scan is persisted as canceled
// instead of being cut off by process exit, then releases the Trivy manager
// and the database.
func (s *serverServices) Close() {
	if s.scanManager != nil {
		stopScanManager(s.scanManager)
	}
	if s.trivyDB != nil {
		s.trivyDB.Close()
	}
	if s.db != nil {
		_ = s.db.Close()
	}
}
