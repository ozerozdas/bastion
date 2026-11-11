package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/scanners/trivy"
)

// newSpikeTrivyCmd is the BST-003 spike entrypoint: it scans a local directory
// with the Trivy library and prints Trivy's raw JSON report to stdout.
// It is hidden and temporary; BST-011 replaces it with `bastion scan`.
func newSpikeTrivyCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:    "spike-trivy <dir>",
		Short:  "Spike: scan a directory with the Trivy library and print JSON",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cacheDir := opts.paths.TrivyCacheDir()
			cmd.PrintErrf("scanning %s (cache %s, trivy %s)\n", args[0], cacheDir, trivy.Version)

			report, err := trivy.ScanFS(cmd.Context(), args[0], cacheDir)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(report)); err != nil {
				return fmt.Errorf("write report: %w", err)
			}
			return nil
		},
	}
}
