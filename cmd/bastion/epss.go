package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/epss"
)

// newEPSSService wires the opt-in EPSS feed with the resolved paths. It
// performs no I/O: the setting is read once, and only with it on does the
// service ever download anything.
func newEPSSService(paths app.Paths) *epss.Service {
	return epss.New(epss.Config{
		DataDir:  paths.DataDir,
		CacheDir: paths.EPSSDir(),
		Version:  version,
	})
}

// doctorEPSS is the `bastion doctor` view of the EPSS feed: the stored setting
// and the cached feed's age, never a network call.
type doctorEPSS struct {
	State       string `json:"state"` // on or off
	LastRefresh string `json:"last_refresh,omitempty"`
	ScoreDate   string `json:"score_date,omitempty"`
	Count       int    `json:"count,omitempty"`
	Error       string `json:"error,omitempty"`
}

// doctorEPSSFromStatus maps the service's snapshot onto the doctor report.
func doctorEPSSFromStatus(status epss.Status) doctorEPSS {
	out := doctorEPSS{
		State:     "off",
		ScoreDate: status.ScoreDate,
		Count:     status.Count,
		Error:     status.Error,
	}
	if status.Enabled {
		out.State = "on"
	}
	if !status.LastRefresh.IsZero() {
		out.LastRefresh = status.LastRefresh.UTC().Format(time.RFC3339)
	}
	return out
}

// summary renders the feed as one doctor line.
func (e doctorEPSS) summary() string {
	if e.State != "on" {
		return "off (no requests)"
	}
	parts := []string{"on"}
	if e.Error != "" {
		parts = append(parts, "last download failed: "+e.Error)
		return strings.Join(parts, ", ")
	}
	if e.LastRefresh != "" {
		parts = append(parts, "last refreshed "+e.LastRefresh)
	}
	if e.ScoreDate != "" {
		parts = append(parts, "score date "+e.ScoreDate)
	}
	if e.Count > 0 {
		parts = append(parts, fmt.Sprintf("%d CVEs", e.Count))
	}
	return strings.Join(parts, ", ")
}
