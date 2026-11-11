// Command bastion is a local-first security center.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// rootOptions holds the process configuration shared by every subcommand. The
// raw flag values are parsed by cobra; paths are resolved and logging is
// installed once, in the root's PersistentPreRunE.
type rootOptions struct {
	dataDir   string
	cacheDir  string
	logFormat string
	logLevel  string

	paths app.Paths
}

func newRootCmd() *cobra.Command {
	opts := &rootOptions{}

	root := &cobra.Command{
		Use:               "bastion",
		Short:             "Local-first security center",
		SilenceUsage:      true,
		SilenceErrors:     false,
		PersistentPreRunE: opts.persistentPreRunE,
	}

	pf := root.PersistentFlags()
	pf.StringVar(&opts.dataDir, "data-dir", "",
		"data directory (default: <user config dir>/bastion; env "+app.EnvDataDir+")")
	pf.StringVar(&opts.cacheDir, "cache-dir", "",
		"cache directory (default: <user cache dir>/bastion; env "+app.EnvCacheDir+")")
	pf.StringVar(&opts.logFormat, "log-format", app.LogFormatText,
		"log format: "+app.LogFormatText+" or "+app.LogFormatJSON)
	pf.StringVar(&opts.logLevel, "log-level", "info",
		"log level: debug, info, warn or error")

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the bastion version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version)
			return err
		},
	})
	root.AddCommand(newSpikeTrivyCmd(opts))
	root.AddCommand(newSpikeGitleaksCmd())
	return root
}

// persistentPreRunE resolves paths and installs bastion's logger before any
// subcommand does work. The logger install is load-bearing: Trivy's slog
// hijack (ADR-001) would otherwise swallow every bastion log line.
func (o *rootOptions) persistentPreRunE(cmd *cobra.Command, _ []string) error {
	paths, err := app.Resolve(app.Flags{DataDir: o.dataDir, CacheDir: o.cacheDir})
	if err != nil {
		return err
	}
	o.paths = paths

	if _, err := app.SetupLogging(cmd.ErrOrStderr(), app.LogConfig{
		Format: o.logFormat,
		Level:  o.logLevel,
	}); err != nil {
		return err
	}
	slog.Debug("paths resolved", "data_dir", paths.DataDir, "cache_dir", paths.CacheDir)
	return nil
}
