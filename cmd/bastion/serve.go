package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/httpapi"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/update"
)

// serveOptions are the flags of `bastion serve`, which is also what plain
// `bastion` runs (PROJECT_SPEC.md §3).
type serveOptions struct {
	port      int
	noBrowser bool
	// concurrency is the number of scans the worker pool runs at once.
	concurrency int
	// paths are resolved by the root command's PersistentPreRunE, so
	// --data-dir and BASTION_DATA_DIR apply to serve as well.
	paths app.Paths
}

// serveDeps isolates the side effects of `bastion serve` so tests can drive the
// command without binding a port, launching a browser, touching the user's
// keyring or installing signal handlers.
type serveDeps struct {
	listen         func(port int) (net.Listener, error)
	openBrowser    func(url string) error
	notifyContext  func(parent context.Context) (context.Context, context.CancelFunc)
	newServer      func(httpapi.Config) (*httpapi.Server, error)
	openDB         func(ctx context.Context, path string) (*sql.DB, error)
	newSecretStore func() secrets.Store
	// newUpdateChecker builds the release checker. Tests inject one with a
	// stubbed environment, so CI=true in the test process cannot disable it.
	newUpdateChecker func(app.Paths) *update.Checker
}

func defaultServeDeps() serveDeps {
	return serveDeps{
		listen:      httpapi.Listen,
		openBrowser: browser.OpenURL,
		notifyContext: func(parent context.Context) (context.Context, context.CancelFunc) {
			return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
		},
		newServer:        httpapi.New,
		openDB:           store.Open,
		newSecretStore:   secrets.NewStore,
		newUpdateChecker: newUpdateChecker,
	}
}

// addServeFlags registers the serve flags on cmd. The same serveOptions is
// registered on the root command too, so plain `bastion` accepts them.
func addServeFlags(cmd *cobra.Command, opts *serveOptions) {
	cmd.Flags().IntVar(&opts.port, "port", 0,
		"port to listen on; 0 picks a free port")
	cmd.Flags().BoolVar(&opts.noBrowser, "no-browser", false,
		"do not open the UI in the browser")
	cmd.Flags().IntVar(&opts.concurrency, "concurrency", jobs.DefaultConcurrency,
		"number of scans to run at once")
}

func newServeCmd(root *rootOptions) *cobra.Command {
	opts := &serveOptions{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the local UI and API server",
		Long: "Start the local UI and API server on 127.0.0.1.\n\n" +
			"The URL printed on start contains a single-use token that the server\n" +
			"exchanges for a session cookie, so only the browser it opens (or a\n" +
			"browser you paste the URL into) can use the API.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.paths = root.paths
			return runServe(cmd, opts, defaultServeDeps())
		},
	}
	addServeFlags(cmd, opts)
	return cmd
}

// runServe binds the loopback listener, prints the browser URL, opens the
// browser and blocks until ctx is canceled or the server fails.
//
// The URL carries the startup token and goes to the user's terminal on stderr
// only; it is never passed to slog, whose output may be collected, shipped or
// pasted into an issue (§4.3).
func runServe(cmd *cobra.Command, opts *serveOptions, deps serveDeps) error {
	// A negative or oversized port fails inside net.Listen with a message about
	// 127.0.0.1:-1; reject it here so the user sees what the flag accepts.
	if opts.port < 0 || opts.port > 65535 {
		return errors.New("--port must be 0-65535 (0 picks a free port)")
	}

	ln, err := deps.listen(opts.port)
	if err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	port, err := listenerPort(ln)
	if err != nil {
		return errors.Join(err, ln.Close())
	}

	cmdCtx := cmd.Context()
	if cmdCtx == nil {
		cmdCtx = context.Background()
	}
	services, err := newServerServices(cmdCtx, opts.paths, port, opts.concurrency, deps)
	if err != nil {
		return errors.Join(err, ln.Close())
	}
	// Stop the worker pool when the server stops, so a running scan is
	// persisted as canceled instead of being cut off by process exit.
	defer services.Close()

	updateChecker := deps.newUpdateChecker(opts.paths)
	// The MCP tab's snippets name the running binary. A resolution failure is
	// reported and the API answers that endpoint with 500; the server still
	// starts, since the configuration is advisory.
	mcpSetup, err := mcpSetupFor(opts.paths)
	if err != nil {
		slog.Warn("could not resolve the MCP command", "error", err)
	}
	srv, err := deps.newServer(httpapi.Config{
		Version:       version,
		Port:          port,
		Connections:   services.connections,
		Reports:       services.reports,
		Assets:        services.assets,
		Events:        services.events,
		Update:        updateChecker,
		TrivyDB:       services.trivyDB,
		EPSS:          services.epss,
		Reachability:  services.reachability,
		SAST:          services.sast,
		Outdated:      services.outdated,
		LicencePolicy: services.licence,
		Preferences:   services.preferences,
		Notifications: services.notify,
		MCP:           mcpSetup,
	})
	if err != nil {
		return errors.Join(fmt.Errorf("create server: %w", err), ln.Close())
	}

	url := srv.BrowserURL()
	out := cmd.ErrOrStderr()
	// Terminal write errors are not actionable; the server runs either way.
	_, _ = fmt.Fprintf(out, "bastion %s is running at %s\n", version, url)
	_, _ = fmt.Fprintln(out, "press Ctrl+C to stop")
	// The notice goes to stderr too, never stdout: `bastion scan` and its
	// machine-readable output stay untouched. Status() never waits for the
	// network, so startup is not delayed by the check.
	writeUpdateNotice(out, updateChecker.Status())
	// Start the daily EPSS refresh when the user opted in and the cache is
	// stale. Status never waits for the network, so startup is not delayed.
	services.epss.Status()

	if !opts.noBrowser {
		// Opening the browser must not block startup: a failure (headless box,
		// no handler) is reported without the URL and the user still has the
		// one printed above.
		go func() {
			if err := deps.openBrowser(url); err != nil {
				slog.Warn("could not open the browser", "error", err)
			}
		}()
	}

	ctx, stop := deps.notifyContext(cmdCtx)
	defer stop()

	if err := srv.Serve(ctx, ln); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	_, _ = fmt.Fprintln(out, "bastion stopped")
	return nil
}

// listenerPort extracts the bound port from a listener.
func listenerPort(ln net.Listener) (int, error) {
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected listener address %q", ln.Addr())
	}
	return addr.Port, nil
}
