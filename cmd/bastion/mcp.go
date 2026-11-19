package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/assets"
	"github.com/ozerozdas/bastion/internal/httpapi"
	"github.com/ozerozdas/bastion/internal/mcpserver"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/securitynews"
	"github.com/ozerozdas/bastion/internal/servelock"
)

// newMCPCmd is `bastion mcp`: the Model Context Protocol server over stdio. It
// opens the same database as `bastion serve` and reads the same stored state,
// but it never starts a scan pipeline of its own. Its only write is
// trigger_scan, which queues a scan row for a running serve to run.
func newMCPCmd(root *rootOptions) *cobra.Command {
	var useHTTP bool
	var port int
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve MCP tools over stdio for AI agents",
		Long: "Serve bastion's assets, findings, fix plans and scan diffs over the\n" +
			"Model Context Protocol on stdin/stdout, and queue scans for a running\n" +
			"bastion serve.\n\n" +
			"The server starts no scan worker, download or recovery. It opens the same\n" +
			"--data-dir and database as `bastion serve`. trigger_scan only records a\n" +
			"queued scan for that server, which runs it and shows it in the UI; the\n" +
			"tool fails when no serve holds the data directory's lock. stdout carries\n" +
			"the protocol, so logs go to stderr.\n\n" +
			"--http serves the same tools over streamable HTTP on 127.0.0.1 instead,\n" +
			"for clients that only speak HTTP. It never binds another interface.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !useHTTP {
				return runMCP(cmd, root.paths, defaultServeDeps(), stdioServe(&mcp.StdioTransport{}))
			}
			if port < 0 || port > 65535 {
				return errors.New("--port must be 0-65535 (0 picks a free port)")
			}
			ln, err := httpapi.Listen(port)
			if err != nil {
				return fmt.Errorf("mcp: %w", err)
			}
			return runMCP(cmd, root.paths, defaultServeDeps(), httpServe(ln, cmd.ErrOrStderr()))
		},
	}
	cmd.Flags().BoolVar(&useHTTP, "http", false, "serve MCP over HTTP on 127.0.0.1 instead of stdio")
	cmd.Flags().IntVar(&port, "port", 0, "loopback port for --http (0 picks a free port)")
	return cmd
}

// mcpServeFunc runs a built MCP server until ctx ends.
type mcpServeFunc func(ctx context.Context, server *mcpserver.Server) error

func stdioServe(transport mcp.Transport) mcpServeFunc {
	return func(ctx context.Context, server *mcpserver.Server) error {
		// stderr only: stdout is the protocol stream.
		slog.Info("bastion mcp serving over stdio")
		return server.Run(ctx, transport)
	}
}

// httpServe serves MCP on ln, which httpapi.Listen bound to 127.0.0.1 only.
func httpServe(ln net.Listener, out io.Writer) mcpServeFunc {
	return func(ctx context.Context, server *mcpserver.Server) error {
		srv := &http.Server{
			Handler:           server.HTTPHandler(slog.Default()),
			ReadHeaderTimeout: 10 * time.Second,
		}
		_, _ = fmt.Fprintf(out, "bastion mcp is serving at http://%s/\n", ln.Addr())
		errc := make(chan error, 1)
		go func() { errc <- srv.Serve(ln) }()
		select {
		case err := <-errc:
			return err
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shutdown)
		}
	}
}

// mcpServices is the service subset `bastion mcp` opens: the database and the
// read models on top of it. It deliberately builds no scan manager, Trivy
// manager, SAST module or EPSS fetcher, so it can never recover, fail or race
// another bastion process's scans. assets.Service is safe without a manager
// because only Enqueue needs one; trigger_scan writes the queued row itself.
type mcpServices struct {
	db           *sql.DB
	assets       *assets.Service
	reports      *reports.Service
	securityNews *securitynews.Service
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
	// The Security News feed is read-only here (#192): the tool reads the same
	// stored setting and cache policy as the UI, never the scan pipeline.
	services.securityNews = securitynews.New(securitynews.Config{
		DataDir: paths.DataDir,
		Version: version,
	})

	ok = true
	return services, nil
}

func (s *mcpServices) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

// mcpSetupFor is what GET /api/mcp advertises (#163): the running binary's
// real path (symlinks resolved, so a package-manager shim points at the binary
// it starts) and the arguments that open the same data directory as serve.
func mcpSetupFor(paths app.Paths) (httpapi.MCPSetup, error) {
	exe, err := os.Executable()
	if err != nil {
		return httpapi.MCPSetup{}, fmt.Errorf("resolve executable: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return httpapi.MCPSetup{}, fmt.Errorf("resolve executable path: %w", err)
	}
	return httpapi.MCPSetup{
		Command: resolved,
		Args:    []string{"mcp", "--data-dir", paths.DataDir},
	}, nil
}

// runMCP opens the MCP services and blocks until the client disconnects
// or the process is interrupted.
func runMCP(cmd *cobra.Command, paths app.Paths, deps serveDeps, serve mcpServeFunc) error {
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
		Version:      version,
		Assets:       services.assets,
		Reports:      services.reports,
		SecurityNews: services.securityNews,
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

	if err := serve(ctx, server); err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	return nil
}
