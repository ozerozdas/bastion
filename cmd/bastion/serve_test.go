package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/httpapi"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/update"
)

// TestServeIsTheDefaultCommand: plain `bastion` must start the server, and
// `bastion serve` must behave the same (§3).
func TestServeIsTheDefaultCommand(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "serve subcommand", args: []string{"serve", "--port", "0", "--no-browser"}},
		{name: "root default", args: []string{"--port", "0", "--no-browser"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // shut down as soon as the server is up

			var stderr bytes.Buffer
			cmd := newRootCmd()
			cmd.SetArgs(append(tc.args, "--data-dir", t.TempDir()))
			cmd.SetOut(io.Discard)
			cmd.SetErr(&stderr)

			if err := cmd.ExecuteContext(ctx); err != nil {
				t.Fatalf("Execute: %v\n%s", err, stderr.String())
			}

			out := stderr.String()
			if !strings.Contains(out, "is running at http://127.0.0.1:") {
				t.Errorf("startup output names no URL:\n%s", out)
			}
			if !strings.Contains(out, "press Ctrl+C to stop") {
				t.Errorf("startup output does not explain how to stop:\n%s", out)
			}
			if !strings.Contains(out, "bastion stopped") {
				t.Errorf("shutdown was not reported:\n%s", out)
			}
		})
	}
}

// TestServePrintsTokenWithoutLoggingIt: the URL (and therefore the token) goes
// to the terminal, but no slog record may contain it (§4.3).
func TestServePrintsTokenWithoutLoggingIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetArgs([]string{"serve", "--port", "0", "--no-browser", "--log-format", "json", "--data-dir", t.TempDir()})
	cmd.SetOut(io.Discard)
	cmd.SetErr(&stderr)

	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("Execute: %v\n%s", err, stderr.String())
	}

	tokenPattern := regexp.MustCompile(`\?t=([A-Za-z0-9_-]{43})`)
	match := tokenPattern.FindStringSubmatch(stderr.String())
	if match == nil {
		t.Fatalf("no token in the startup output:\n%s", stderr.String())
	}
	token := match[1]

	for _, line := range strings.Split(stderr.String(), "\n") {
		if !strings.HasPrefix(line, "{") {
			continue // the human-readable startup banner
		}
		if strings.Contains(line, token) {
			t.Fatalf("a slog record contains the startup token: %s", line)
		}
	}
}

func TestServeFlags(t *testing.T) {
	cmd := newServeCmd(&rootOptions{})

	port := cmd.Flags().Lookup("port")
	if port == nil {
		t.Fatal("serve has no --port flag")
	}
	if port.DefValue != "0" {
		t.Errorf("--port default = %q, want %q (random free port)", port.DefValue, "0")
	}

	noBrowser := cmd.Flags().Lookup("no-browser")
	if noBrowser == nil {
		t.Fatal("serve has no --no-browser flag")
	}
	if noBrowser.DefValue != "false" {
		t.Errorf("--no-browser default = %q, want %q", noBrowser.DefValue, "false")
	}

	// The same flags exist on the root command, since it runs serve by default.
	root := newRootCmd()
	if root.Flags().Lookup("port") == nil || root.Flags().Lookup("no-browser") == nil {
		t.Error("root command does not accept the serve flags")
	}
}

// TestRunServeBrowserHandling checks the browser side effect without launching
// anything: off with --no-browser, on by default with the tokenized URL.
func TestRunServeBrowserHandling(t *testing.T) {
	cases := []struct {
		name         string
		noBrowser    bool
		wantOpenCall bool
	}{
		{name: "browser opened by default", wantOpenCall: true},
		{name: "no-browser", noBrowser: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opened := make(chan string, 1)
			canceled, cancel := context.WithCancel(context.Background())
			cancel()

			deps := serveDeps{
				listen:      httpapi.Listen,
				openBrowser: func(url string) error { opened <- url; return nil },
				notifyContext: func(context.Context) (context.Context, context.CancelFunc) {
					return context.WithCancel(canceled)
				},
				newServer:      httpapi.New,
				openDB:         store.Open,
				newSecretStore: func() secrets.Store { return secrets.NewMemoryStore() },
				newUpdateChecker: func(paths app.Paths) *update.Checker {
					return update.New(update.Config{
						CurrentVersion: "v0.1.0",
						DataDir:        paths.DataDir,
						CacheDir:       paths.CacheDir,
						Getenv:         func(string) string { return "" },
					})
				},
			}

			cmd := &cobra.Command{}
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := runServe(cmd, &serveOptions{port: 0, noBrowser: tc.noBrowser, paths: app.Paths{DataDir: t.TempDir()}}, deps)
			if err != nil {
				t.Fatalf("runServe: %v", err)
			}

			select {
			case url := <-opened:
				if !tc.wantOpenCall {
					t.Fatalf("browser opened with --no-browser: %s", url)
				}
				if !strings.HasPrefix(url, "http://127.0.0.1:") || !strings.Contains(url, "/?t=") {
					t.Errorf("browser URL = %q, want http://127.0.0.1:<port>/?t=<token>", url)
				}
			case <-time.After(2 * time.Second):
				if tc.wantOpenCall {
					t.Fatal("browser was not opened")
				}
			}
		})
	}
}

// TestRunServeRejectsOutOfRangePort: --port outside the TCP range is rejected
// before the listener is bound, so the error names the flag instead of the
// confusing "listen on 127.0.0.1:-1" (#63).
func TestRunServeRejectsOutOfRangePort(t *testing.T) {
	const wantMessage = "--port must be 0-65535 (0 picks a free port)"

	cases := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{name: "negative", port: -1, wantErr: true},
		{name: "above the range", port: 70000, wantErr: true},
		{name: "free port", port: 0},
		{name: "last valid port", port: 65535},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The stub listener stops runServe right after validation, so the
			// test never binds a port; reaching it at all is the signal that a
			// valid port passed the check.
			listened := false
			deps := serveDeps{
				listen: func(int) (net.Listener, error) {
					listened = true
					return nil, errors.New("listen stub reached")
				},
			}

			cmd := &cobra.Command{}
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := runServe(cmd, &serveOptions{port: tc.port}, deps)

			if tc.wantErr {
				if err == nil {
					t.Fatal("runServe accepted an out-of-range port")
				}
				if err.Error() != wantMessage {
					t.Errorf("error = %q, want %q", err, wantMessage)
				}
				if listened {
					t.Error("runServe bound a listener for an out-of-range port")
				}
				return
			}

			if !listened {
				t.Fatalf("runServe rejected port %d: %v", tc.port, err)
			}
			if err == nil || !strings.Contains(err.Error(), "start server") {
				t.Errorf("error = %v, want the stub listener failure", err)
			}
		})
	}
}

// TestRunServeFailsOnBusyPort: a taken port is a user-facing error, not a panic.
func TestRunServeFailsOnBusyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	busy := ln.Addr().(*net.TCPAddr).Port

	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err = runServe(cmd, &serveOptions{port: busy, noBrowser: true}, defaultServeDeps())
	if err == nil {
		t.Fatal("runServe succeeded on a busy port")
	}
	if !strings.Contains(err.Error(), "start server") {
		t.Errorf("error = %v, want it to mention starting the server", err)
	}
}
