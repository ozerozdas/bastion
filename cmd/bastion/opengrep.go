package main

import (
	"strings"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/scanners/opengrep"
)

// newOpengrepModule wires the opt-in SAST module with the resolved paths. It
// performs no I/O and no download: only an explicit Install does.
func newOpengrepModule(paths app.Paths) *opengrep.Service {
	return opengrep.New(opengrep.Config{
		DataDir:    paths.DataDir,
		ModulesDir: paths.ModulesDir(),
		Version:    version,
	})
}

// doctorOpengrep is the `bastion doctor` view of the opt-in SAST module: the
// setting, the installed state and version, never a download.
type doctorOpengrep struct {
	State        string `json:"state"` // disabled, not_installed, installed or checksum_bad
	Version      string `json:"version"`
	Path         string `json:"path,omitempty"`
	Error        string `json:"error,omitempty"`
	InstallError string `json:"install_error,omitempty"`
}

// doctorOpengrepFromStatus maps the module's snapshot onto the report.
func doctorOpengrepFromStatus(status opengrep.Status) doctorOpengrep {
	out := doctorOpengrep{
		State:        string(status.State),
		Version:      status.Version,
		Path:         status.Dir,
		Error:        status.Error,
		InstallError: status.InstallError,
	}
	if !status.Enabled {
		out.State = "disabled"
	}
	if out.State == "" {
		out.State = string(opengrep.StateNotInstalled)
	}
	return out
}

// summary renders the module as one doctor line.
func (o doctorOpengrep) summary() string {
	parts := []string{o.Version}
	switch o.State {
	case "disabled":
		parts = append(parts, "disabled")
	case string(opengrep.StateInstalled):
		parts = append(parts, "installed")
	case string(opengrep.StateChecksumBad):
		parts = append(parts, "installed, checksum bad")
	default:
		parts = append(parts, "enabled, not installed")
	}
	if o.InstallError != "" {
		parts = append(parts, "last download failed")
	}
	return strings.Join(parts, ", ")
}

// warning is the doctor hint when SAST is on but the module cannot run.
func (o doctorOpengrep) warning() string {
	switch o.State {
	case string(opengrep.StateChecksumBad):
		return "the downloaded SAST module does not match its pinned checksum: it will not run; re-enable SAST to download it again"
	case string(opengrep.StateNotInstalled):
		if o.InstallError != "" {
			return "SAST is enabled but the module download failed: " + o.InstallError
		}
		return "SAST is enabled but the module is not installed yet; the next scan or the UI downloads it"
	default:
		return ""
	}
}
