// Command bastion is a local-first security center.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "bastion",
		Short:         "Local-first security center",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the bastion version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version)
			return err
		},
	})
	root.AddCommand(newSpikeTrivyCmd())
	return root
}
