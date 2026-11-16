package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/update"
)

// updateFlags are the `bastion update` switches.
type updateFlags struct {
	check bool
	force bool
}

// updateDeps is the command's one side effect, injectable so tests never touch
// the network or the running binary.
type updateDeps struct {
	selfUpdate func(context.Context, update.SelfUpdateConfig) error
}

// newUpdateCmd replaces the running binary with the latest release. A Homebrew
// install and a Windows build are reported, never modified.
func newUpdateCmd() *cobra.Command {
	var flags updateFlags

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update bastion to the latest release",
		Long: "Update bastion to the latest release.\n\n" +
			"The release archive is verified against the release's checksums.txt and renamed over " +
			"the running binary. A Homebrew install is left alone (the command prints `brew upgrade`), " +
			"and Windows prints the release link instead. Development builds refuse to update unless --force.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUpdate(cmd.Context(), cmd.OutOrStdout(), flags,
				updateDeps{selfUpdate: update.SelfUpdate})
		},
	}
	cmd.Flags().BoolVar(&flags.check, "check", false, "report the latest release without installing it")
	cmd.Flags().BoolVar(&flags.force, "force", false, "update even from a development build")

	return cmd
}

// runUpdate passes the flags and the build version to the self-updater.
func runUpdate(ctx context.Context, out io.Writer, flags updateFlags, deps updateDeps) error {
	return deps.selfUpdate(ctx, update.SelfUpdateConfig{
		CurrentVersion: version,
		Check:          flags.check,
		Force:          flags.force,
		Out:            out,
	})
}

// newUpdateChecker wires the opt-in release check with the resolved paths and
// the build version. It performs no I/O: the checker only reads files when
// asked, and only calls out with consent on.
func newUpdateChecker(paths app.Paths) *update.Checker {
	return update.New(update.Config{
		CurrentVersion: version,
		DataDir:        paths.DataDir,
		CacheDir:       paths.CacheDir,
	})
}

// writeUpdateNotice prints the CLI side of the release check on stderr.
//
// It stays silent for a disabled check (CI, BASTION_NO_UPDATE_CHECK, a dev
// build), after the user said no, and when there is nothing newer: the CLI
// must never nag or turn a failed check into noise. `bastion scan` never calls
// this function, so its stdout does not change.
func writeUpdateNotice(w io.Writer, status update.Status) {
	switch {
	case status.Disabled != "":
		return
	case status.Consent == update.ConsentUnset:
		_, _ = fmt.Fprintln(w,
			"Release checks are off. Turn them on in the bastion UI; set "+
				update.EnvNoUpdateCheck+"=1 to silence this notice.")
	case status.Consent == update.ConsentOn && status.UpdateAvailable:
		_, _ = fmt.Fprintf(w, "bastion %s is available (you have %s). Update with:\n",
			displayVersion(status.Latest), displayVersion(status.Current))
		if status.Command != "" {
			_, _ = fmt.Fprintf(w, "  %s\n", status.Command)
		}
		if status.ReleaseURL != "" {
			_, _ = fmt.Fprintf(w, "  %s\n", status.ReleaseURL)
		}
	}
}

// displayVersion gives a bare version the "v" prefix the release tags use.
func displayVersion(v string) string {
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// doctorUpdate is the `bastion doctor` view of the release check. It carries no
// credential, only the local consent state and the cached result.
type doctorUpdate struct {
	State       string `json:"state"` // on, off or unset
	Disabled    string `json:"disabled,omitempty"`
	LastChecked string `json:"last_checked,omitempty"`
	Latest      string `json:"latest,omitempty"`
}

// doctorUpdateFromStatus maps the checker's snapshot onto the doctor report.
func doctorUpdateFromStatus(status update.Status) doctorUpdate {
	out := doctorUpdate{
		State:    string(status.Consent),
		Disabled: status.Disabled,
		Latest:   status.Latest,
	}
	if !status.CheckedAt.IsZero() {
		out.LastChecked = status.CheckedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// summary renders the release check as one doctor line.
func (u doctorUpdate) summary() string {
	state := u.State
	if state == "" {
		state = string(update.ConsentUnset)
	}
	if u.Disabled != "" {
		return fmt.Sprintf("%s (disabled: %s)", state, u.Disabled)
	}
	parts := []string{state}
	if u.LastChecked != "" {
		parts = append(parts, "last checked "+u.LastChecked)
	}
	if u.Latest != "" {
		parts = append(parts, "latest "+u.Latest)
	}
	return strings.Join(parts, ", ")
}
