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
)

// newMCPCmd is `bastion mcp`: the read-only Model Context Protocol server over
// stdio. It opens the same database as `bastion serve` and reads the same
// stored state, but it never starts a scan pipeline of its own.
func newMCPCmd(root *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Serve read-only MCP tools over stdio for AI agents",
		Long: "Serve bastion's assets, findings, fix plans and scan diffs over the\n" +
			"Model Context Protocol on stdin/stdout.\n\n" +
			"The server is read-only: scans run from the UI or the CLI. It opens the\n" +
			"same --data-dir and database as `bastion serve` and starts no scan worker,\n" +
			"download or recovery. stdout carries the protocol, so logs go to stderr.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMCP(cmd, root.paths, defaultServeDeps(), &mcp.StdioTransport{})
		},
	}
}

// mcpServices is the read-only service subset `bastion mcp` opens: the
// database and the read models on top of it. It deliberately builds no scan
// manager, Trivy manager, SAST module or EPSS fetcher, so it can never recover,
// fail or race another bastion process's scans. assets.Service is safe without
// a manager because the read paths (List, Scans) never touch it; only Enqueue
// does, and no MCP tool queues scans any more.
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

// runMCP opens the read-only services and blocks until the client disconnects
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
		Logger:  slog.Default(),
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
