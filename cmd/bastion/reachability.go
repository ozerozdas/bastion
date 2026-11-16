package main

import (
	"strings"

	"github.com/ozerozdas/bastion/internal/scanners/govulncheck"
)

// doctorReachability reports the opt-in Go reachability enrichment (#37). With
// it on but no Go toolchain, scans still succeed and Go findings are unknown;
// the warning says so.
type doctorReachability struct {
	State     string `json:"state"` // on or off
	Available bool   `json:"go_available"`
	Error     string `json:"error,omitempty"`
}

// doctorReachabilityFromStatus maps the service's snapshot onto the report.
func doctorReachabilityFromStatus(status govulncheck.Status) doctorReachability {
	out := doctorReachability{
		State:     "off",
		Available: status.Available,
		Error:     status.Error,
	}
	if status.Enabled {
		out.State = "on"
	}
	return out
}

// summary renders the enrichment as one doctor line.
func (r doctorReachability) summary() string {
	if r.State != "on" {
		return "off (no govulncheck runs)"
	}
	parts := []string{"on"}
	if r.Available {
		parts = append(parts, "go toolchain found")
	} else {
		parts = append(parts, "go toolchain missing: findings stay unknown")
	}
	if r.Error != "" && !r.Available {
		parts = append(parts, r.Error)
	}
	return strings.Join(parts, ", ")
}

// reachabilityWarning is the doctor hint when the enrichment cannot work.
func (r doctorReachability) warning() string {
	if r.State != "on" || r.Available {
		return ""
	}
	return "Go reachability is on but no go executable was found on PATH: install Go or turn it off; Go findings stay unknown until then"
}
