package main

import (
	"github.com/spf13/cobra"
	"golang.org/x/vuln/scan"

	"github.com/ozerozdas/bastion/internal/scanners/govulncheck"
)

// newInternalGovulncheckCmd is the hidden child the Go reachability enrichment
// re-execs bastion with (#37). It exists so the parent can bound the analysis
// and kill the whole `go` process tree: x/vuln v1.9.0 does not plumb the
// context into its package loading. It writes govulncheck's JSON stream to
// stdout and is not part of the user-facing CLI.
func newInternalGovulncheckCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:    govulncheck.InternalCommand,
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			analysis := scan.Command(cmd.Context(),
				"-C", dir, "-format", "json", "-scan", "symbol", "./...")
			analysis.Stdout = cmd.OutOrStdout()
			analysis.Stderr = cmd.ErrOrStderr()
			if err := analysis.Start(); err != nil {
				return err
			}
			return analysis.Wait()
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "module directory to analyze")
	return cmd
}
