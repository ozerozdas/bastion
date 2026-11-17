package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/assets"
	"github.com/ozerozdas/bastion/internal/mcpserver"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/servelock"
)

// newMCPCmd is `bastion mcp`: the Model Context Protocol server over stdio. It
// opens the same database as `bastion serve` and reads the same stored state,
// but it never starts a scan pipeline of its own. Its only write is
// trigger_scan, which queues a scan row for a running serve to run.
func newMCPCmd(root *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Serve MCP tools over stdio for AI agents",
		Long: "Serve bastion's assets, findings, fix plans and scan diffs over the\n" +
			"Model Context Protocol on stdin/stdout, and queue scans for a running\n" +
			"bastion serve.\n\n" +
			"The server starts no scan worker, download or recovery. It opens the same\n" +
			"--data-dir and database as `bastion serve`. trigger_scan only records a\n" +
			"queued scan for that server, which runs it and shows it in the UI; the\n" +
			"tool fails when no serve holds the data directory's lock. stdout carries\n" +
			"the protocol, so logs go to stderr.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMCP(cmd, root.paths, defaultServeDeps(), &mcp.StdioTransport{})
		},
	}
}

// mcpServices is the service subset `bastion mcp` opens: the database and the
// read models on top of it. It deliberately builds no scan manager, Trivy
// manager, SAST module or EPSS fetcher, so it can never recover, fail or race
// another bastion process's scans. assets.Service is safe without a manager
// because only Enqueue needs one; trigger_scan writes the queued row itself.
type mcpServices struct {
	db      *sql.DB
	assets  *assets.Service
	reports *reports.Service
}

func newMCPServices(ctx context.Context, paths app.Paths, openDB func(context.Context, string) (*sql.DB, error)) (*mcpServices, error) {
	if paths.DataDir == "" {
		return nil, errors.New("mcp: data directory is not resolved")
	}
	// Migrations must run even when the caller's context is canceled, exactly
	// like serve's database setup.
	db, err := openDB(context.WithoutCancel(ctx), paths.DBPath())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	services := &mcpServices{db: db}
	ok := false
	defer func() {
		if !ok {
			services.Close()
		}
	}()

	services.assets, err = assets.NewService(db)
	if err != nil {
		return nil, fmt.Errorf("create assets service: %w", err)
	}
	services.reports, err = reports.NewService(db)
	if err != nil {
		return nil, fmt.Errorf("create reports service: %w", err)
	}

	ok = true
	return services, nil
}

func (s *mcpServices) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

// runMCP opens the MCP services and blocks until the client disconnects
// or the process is interrupted.
func runMCP(cmd *cobra.Command, paths app.Paths, deps serveDeps, transport mcp.Transport) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	services, err := newMCPServices(ctx, paths, deps.openDB)
	if err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	defer services.Close()

	server, err := mcpserver.New(mcpserver.Config{
		Version: version,
		Assets:  services.assets,
		Reports: services.reports,
		// serve holds the data directory's lock for its whole lifetime, so the
		// check is a read-only probe of that lock, not a network or auth surface.
		ServeRunning: func() bool { return servelock.Held(paths.DataDir) },
		Logger:       slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("mcp: %w", err)
	}

	ctx, stop := deps.notifyContext(ctx)
	defer stop()

	// stderr only: stdout is the protocol stream.
	slog.Info("bastion mcp serving over stdio", "data_dir", paths.DataDir)
	if err := server.Run(ctx, transport); err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	return nil
}
