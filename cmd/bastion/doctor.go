package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/scanners/gitleaks"
	"github.com/ozerozdas/bastion/internal/scanners/trivy"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/update"
)

// doctorDeps is everything `bastion doctor` inspects. It is a struct of
// functions so tests can inject fakes: the keyring check in particular writes
// and deletes a real keyring entry in production and must never run in tests.
type doctorDeps struct {
	bastionVersion string
	goVersion      string
	goos           string
	goarch         string
	paths          app.Paths

	openDB        func(ctx context.Context, path string) (*sql.DB, error)
	schemaVersion func(ctx context.Context, db *sql.DB) (int64, error)
	closeDB       func(db *sql.DB) error

	trivyVersion    string
	gitleaksVersion string

	keyringAvailable func() error
	secretStore      secrets.Store
	getenv           func(string) string

	// updateStatus is a read-only snapshot of the release check; doctor never
	// waits for the network.
	updateStatus func() update.Status
}

// doctorReport is the printed result. No field holds a credential: the HMAC key
// is reported only as a source, never as a value (PROJECT_SPEC.md §4.3).
type doctorReport struct {
	BastionVersion  string           `json:"bastion_version"`
	GoVersion       string           `json:"go_version"`
	OS              string           `json:"os"`
	Arch            string           `json:"arch"`
	DataDir         string           `json:"data_dir"`
	CacheDir        string           `json:"cache_dir"`
	Database        doctorDatabase   `json:"database"`
	TrivyVersion    string           `json:"trivy_version"`
	TrivyCache      doctorTrivyCache `json:"trivy_cache"`
	GitleaksVersion string           `json:"gitleaks_version"`
	Keyring         doctorStatus     `json:"keyring"`
	HMACKey         doctorStatus     `json:"hmac_key"`
	Update          doctorUpdate     `json:"update"`
	Warnings        []string         `json:"warnings,omitempty"`
}

// doctorDatabase reports the SQLite file and its schema version.
type doctorDatabase struct {
	Path          string `json:"path"`
	Status        string `json:"status"` // "ok" or "error"
	SchemaVersion int64  `json:"schema_version"`
	Error         string `json:"error,omitempty"`
}

// doctorTrivyCache reports the cache that holds the Trivy vulnerability DB.
// Absent is normal on a fresh install: the first scan downloads it.
type doctorTrivyCache struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Size    int64  `json:"size_bytes"`
	Error   string `json:"error,omitempty"`
}

// doctorStatus is a one-line state plus a short non-secret explanation.
type doctorStatus struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// newDoctorCmd reports paths, versions, keyring availability and database
// health (PROJECT_SPEC.md §12). It exits non-zero only when the database
// cannot be opened; everything else is a warning.
func newDoctorCmd(opts *rootOptions) *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check bastion's local setup",
		Long: "Check bastion's local setup: paths, versions, keyring availability and database health.\n\n" +
			"The keyring check writes a throwaway entry to verify the keychain works and deletes it again.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report, reportErr := runDoctor(cmd.Context(), newDoctorDeps(opts))

			var writeErr error
			if asJSON {
				writeErr = writeDoctorJSON(cmd.OutOrStdout(), report)
			} else {
				writeErr = writeDoctorText(cmd.OutOrStdout(), report)
			}
			if writeErr != nil {
				return writeErr
			}
			return reportErr
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")

	return cmd
}

// newDoctorDeps wires the production implementations.
func newDoctorDeps(opts *rootOptions) doctorDeps {
	return doctorDeps{
		bastionVersion:   version,
		goVersion:        runtime.Version(),
		goos:             runtime.GOOS,
		goarch:           runtime.GOARCH,
		paths:            opts.paths,
		openDB:           store.Open,
		schemaVersion:    store.MigrationVersion,
		closeDB:          (*sql.DB).Close,
		trivyVersion:     trivy.Version,
		gitleaksVersion:  gitleaks.Version,
		keyringAvailable: secrets.Available,
		secretStore:      secrets.NewStore(),
		getenv:           os.Getenv,
		updateStatus:     newUpdateChecker(opts.paths).Snapshot,
	}
}

// runDoctor performs every check and returns the report. The error is non-nil
// only when the database cannot be opened; degraded states are warnings so a
// headless machine still gets a useful report and exit code 0.
func runDoctor(ctx context.Context, deps doctorDeps) (doctorReport, error) {
	report := doctorReport{
		BastionVersion:  deps.bastionVersion,
		GoVersion:       deps.goVersion,
		OS:              deps.goos,
		Arch:            deps.goarch,
		DataDir:         deps.paths.DataDir,
		CacheDir:        deps.paths.CacheDir,
		TrivyVersion:    deps.trivyVersion,
		GitleaksVersion: deps.gitleaksVersion,
		Database:        doctorDatabase{Path: deps.paths.DBPath()},
	}

	if err := deps.keyringAvailable(); err != nil {
		report.Keyring = doctorStatus{Status: "unavailable", Detail: err.Error()}
		report.Warnings = append(report.Warnings,
			"keyring unavailable: bastion falls back to BASTION_* environment variables for reads; writes to the keyring will fail")
	} else {
		report.Keyring = doctorStatus{Status: "ok"}
	}

	report.HMACKey = hmacKeySource(deps)
	if report.HMACKey.Status == "error" {
		report.Warnings = append(report.Warnings,
			"local HMAC key unavailable: "+report.HMACKey.Detail)
	}

	report.TrivyCache = readTrivyCache(deps.paths.TrivyCacheDir())
	switch {
	case report.TrivyCache.Error != "":
		report.Warnings = append(report.Warnings,
			"could not read the trivy cache: "+report.TrivyCache.Error)
	case !report.TrivyCache.Present:
		report.Warnings = append(report.Warnings,
			"no trivy cache yet: first scan will download the vulnerability DB")
	}

	report.Update = doctorUpdate{State: string(update.ConsentUnset)}
	if deps.updateStatus != nil {
		report.Update = doctorUpdateFromStatus(deps.updateStatus())
	}

	database, err := deps.openDB(ctx, deps.paths.DBPath())
	if err != nil {
		report.Database.Status = "error"
		report.Database.Error = err.Error()
		return report, fmt.Errorf("open database: %w", err)
	}

	report.Database.Status = "ok"
	if schemaVersion, err := deps.schemaVersion(ctx, database); err != nil {
		report.Warnings = append(report.Warnings, "could not read schema version: "+err.Error())
	} else {
		report.Database.SchemaVersion = schemaVersion
	}
	if err := deps.closeDB(database); err != nil {
		report.Warnings = append(report.Warnings, "could not close database: "+err.Error())
	}

	return report, nil
}

// hmacKeySource reports where the local HMAC key would come from, without
// creating or printing it. LocalKey creates the key on first use, so "missing"
// is normal on a fresh install.
func hmacKeySource(deps doctorDeps) doctorStatus {
	if deps.getenv(secrets.EnvHMACKey) != "" {
		return doctorStatus{Status: "env", Detail: "from " + secrets.EnvHMACKey}
	}
	if deps.secretStore == nil {
		return doctorStatus{Status: "missing", Detail: "no secret store available"}
	}

	_, err := deps.secretStore.Get(secrets.HMACKeyName)
	switch {
	case err == nil:
		return doctorStatus{Status: "keyring", Detail: "in the OS keyring"}
	case errors.Is(err, secrets.ErrNotFound):
		return doctorStatus{
			Status: "missing",
			Detail: "created on first secret scan, or set " + secrets.EnvHMACKey,
		}
	default:
		return doctorStatus{Status: "error", Detail: err.Error()}
	}
}

// readTrivyCache measures the Trivy cache directory. A missing directory means
// no scan has run yet; the caller turns that into a warning.
func readTrivyCache(dir string) doctorTrivyCache {
	cache := doctorTrivyCache{Path: dir}

	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return cache
	}
	if err != nil {
		cache.Error = err.Error()
		return cache
	}
	if !info.IsDir() {
		cache.Error = "not a directory"
		return cache
	}
	cache.Present = true

	// WalkDir does not descend a symlinked root, so walk its target. Symlinks
	// inside the cache are not followed and do not count.
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		cache.Error = err.Error()
		return cache
	}
	err = filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		cache.Size += info.Size()
		return nil
	})
	if err != nil {
		// A partial total would read as the real size in --json.
		cache.Size = 0
		cache.Error = err.Error()
	}
	return cache
}

// writeDoctorText prints an aligned key/value report followed by warnings.
func writeDoctorText(w io.Writer, report doctorReport) error {
	rows := [][2]string{
		{"bastion", report.BastionVersion},
		{"go", report.GoVersion + " " + report.OS + "/" + report.Arch},
		{"data dir", report.DataDir},
		{"cache dir", report.CacheDir},
		{"database", report.Database.Path},
		{"db status", report.Database.summary()},
		{"trivy", report.TrivyVersion},
		{"trivy cache", report.TrivyCache.summary()},
		{"gitleaks", report.GitleaksVersion},
		{"keyring", report.Keyring.summary()},
		{"hmac key", report.HMACKey.summary()},
		{"update", report.Update.summary()},
	}

	table := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		if _, err := fmt.Fprintf(table, "%s\t%s\n", row[0], row[1]); err != nil {
			return fmt.Errorf("write doctor report: %w", err)
		}
	}
	if err := table.Flush(); err != nil {
		return fmt.Errorf("write doctor report: %w", err)
	}

	if len(report.Warnings) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("write doctor report: %w", err)
	}
	for _, warning := range report.Warnings {
		if _, err := fmt.Fprintf(w, "warning: %s\n", warning); err != nil {
			return fmt.Errorf("write doctor report: %w", err)
		}
	}
	return nil
}

// writeDoctorJSON prints the same report as indented JSON for scripting.
func writeDoctorJSON(w io.Writer, report doctorReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("write doctor report: %w", err)
	}
	return nil
}

// summary renders the database state as one line.
func (d doctorDatabase) summary() string {
	if d.Status == "ok" {
		return fmt.Sprintf("ok (schema version %d)", d.SchemaVersion)
	}
	return "error: " + d.Error
}

// summary renders the cache state as one line.
func (c doctorTrivyCache) summary() string {
	switch {
	case c.Error != "":
		return "error: " + c.Error
	case !c.Present:
		return "missing"
	default:
		return c.Path + " (" + cacheSize(c.Size) + ")"
	}
}

// cacheSize formats a byte total for the report. The GitHub clients print exact
// MiB budgets; a cache directory is rarely a round number, so this scales to the
// largest unit and keeps one decimal.
func cacheSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}

// summary renders a status and its detail, when present.
func (s doctorStatus) summary() string {
	if s.Detail == "" {
		return s.Status
	}
	return s.Status + " (" + s.Detail + ")"
}
