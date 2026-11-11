package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/httpapi"
)

// serveOptions are the flags of `bastion serve`, which is also what plain
// `bastion` runs (PROJECT_SPEC.md §3).
type serveOptions struct {
	port      int
	noBrowser bool
}

// serveDeps isolates the side effects of `bastion serve` so tests can drive the
// command without binding a port, launching a browser or installing signal
// handlers.
type serveDeps struct {
	listen        func(port int) (net.Listener, error)
	openBrowser   func(url string) error
	notifyContext func(parent context.Context) (context.Context, context.CancelFunc)
	newServer     func(httpapi.Config) (*httpapi.Server, error)
}

func defaultServeDeps() serveDeps {
	return serveDeps{
		listen:      httpapi.Listen,
		openBrowser: browser.OpenURL,
		notifyContext: func(parent context.Context) (context.Context, context.CancelFunc) {
			return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
		},
		newServer: httpapi.New,
	}
}

// addServeFlags registers the serve flags on cmd. The same serveOptions is
// registered on the root command too, so plain `bastion` accepts them.
func addServeFlags(cmd *cobra.Command, opts *serveOptions) {
	cmd.Flags().IntVar(&opts.port, "port", 0,
		"port to listen on; 0 picks a free port")
	cmd.Flags().BoolVar(&opts.noBrowser, "no-browser", false,
		"do not open the UI in the browser")
}

func newServeCmd() *cobra.Command {
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
	ln, err := deps.listen(opts.port)
	if err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	port, err := listenerPort(ln)
	if err != nil {
		return errors.Join(err, ln.Close())
	}

	srv, err := deps.newServer(httpapi.Config{
		Version: version,
		Port:    port,
	})
	if err != nil {
		return errors.Join(fmt.Errorf("create server: %w", err), ln.Close())
	}

	url := srv.BrowserURL()
	out := cmd.ErrOrStderr()
	// Terminal write errors are not actionable; the server runs either way.
	_, _ = fmt.Fprintf(out, "bastion %s is running at %s\n", version, url)
	_, _ = fmt.Fprintln(out, "press Ctrl+C to stop")

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

	ctx, stop := deps.notifyContext(cmd.Context())
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
