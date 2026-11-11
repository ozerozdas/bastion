package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/scanners/trivy"
)

// newSpikeTrivyCmd is the BST-003 spike entrypoint: it scans a local directory
// with the Trivy library and prints Trivy's raw JSON report to stdout.
// It is hidden and temporary; BST-011 replaces it with `bastion scan`.
func newSpikeTrivyCmd() *cobra.Command {
	var cacheDir string
	cmd := &cobra.Command{
		Use:    "spike-trivy <dir>",
		Short:  "Spike: scan a directory with the Trivy library and print JSON",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Trivy's log package replaces slog.Default() with a buffering
			// handler at import time. Install bastion's logger so Trivy's
			// diagnostics go to stderr instead of being silently dropped.
			slog.SetDefault(slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil)))

			dir, err := resolveCacheDir(cacheDir)
			if err != nil {
				return err
			}
			cmd.PrintErrf("scanning %s (cache %s, trivy %s)\n", args[0], dir, trivy.Version)

			report, err := trivy.ScanFS(cmd.Context(), args[0], dir)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(report)); err != nil {
				return fmt.Errorf("write report: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "",
		"Trivy cache directory (default: <user cache dir>/bastion/trivy)")
	return cmd
}

// resolveCacheDir returns the Trivy cache dir: the flag value when given,
// otherwise os.UserCacheDir()/bastion/trivy.
func resolveCacheDir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache dir: %w", err)
	}
	return filepath.Join(base, "bastion", "trivy"), nil
}
