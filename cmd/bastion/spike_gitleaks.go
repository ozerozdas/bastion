package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/scanners/gitleaks"
	"github.com/ozerozdas/bastion/internal/secrets"
)

// newSpikeGitleaksCmd is the BST-004 spike entrypoint: it scans a local
// working tree with the Gitleaks library and prints redacted findings as JSON.
// It is hidden and temporary; BST-011 replaces it with `bastion scan`.
func newSpikeGitleaksCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "spike-gitleaks <dir>",
		Short:  "Spike: scan a directory for secrets with the Gitleaks library",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := secrets.LocalKey(secrets.NewStore())
			if err != nil {
				return err
			}
			findings, err := gitleaks.ScanDir(cmd.Context(), args[0], key)
			if err != nil {
				return err
			}

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(findings); err != nil {
				return fmt.Errorf("write findings: %w", err)
			}
			return nil
		},
	}
}
