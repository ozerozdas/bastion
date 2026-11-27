package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/report/render"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
)

// The formats `bastion report` writes (#204).
const (
	reportFormatMarkdown = "md"
	reportFormatHTML     = "html"
	reportFormatJSON     = "json"
)

// reportOptions are the flags of one report run.
type reportOptions struct {
	format  string
	assetID int64
}

// reportDeps is what the command reads: the database and the renderers. It is a
// struct of functions so tests inject a temp database and never touch the
// user's data directory.
type reportDeps struct {
	paths   app.Paths
	openDB  func(ctx context.Context, path string) (*sql.DB, error)
	closeDB func(db *sql.DB) error

	newService func(db *sql.DB) (*reports.Service, error)
}

// newReportCmd prints one offline snapshot of the fleet or one asset. It makes
// no network call: every section comes from the local SQLite database.
func newReportCmd(opts *rootOptions) *cobra.Command {
	reportOpts := &reportOptions{format: reportFormatMarkdown}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Print an offline security report snapshot",
		Long: "Print one offline snapshot of the fleet: scan coverage, open findings, SLA status,\n" +
			"triage decisions, suppression rules and the licence policy.\n\n" +
			"The report is built from the local database only; no network call is made.\n" +
			"--asset takes an asset id (names are not resolved); omit it for the whole fleet.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd.Context(), cmd.OutOrStdout(), *reportOpts, newReportDeps(opts))
		},
	}
	cmd.Flags().StringVar(&reportOpts.format, "format", reportFormatMarkdown,
		"output format: "+reportFormatMarkdown+", "+reportFormatHTML+" or "+reportFormatJSON)
	cmd.Flags().Int64Var(&reportOpts.assetID, "asset", 0,
		"asset id to report on; asset names are not resolved (omit for the whole fleet)")

	return cmd
}

// newReportDeps wires the production implementations.
func newReportDeps(opts *rootOptions) reportDeps {
	return reportDeps{
		paths:   opts.paths,
		openDB:  store.Open,
		closeDB: (*sql.DB).Close,
		// No options: the snapshot must not reach GitHub or the EPSS feed.
		newService: func(db *sql.DB) (*reports.Service, error) {
			return reports.NewService(db)
		},
	}
}

// runReport validates the flags, reads the snapshot and writes the document.
// The format is checked before the database opens, so a typo fails fast.
func runReport(ctx context.Context, w io.Writer, opts reportOptions, deps reportDeps) error {
	format, err := reportFormat(opts.format)
	if err != nil {
		return err
	}
	if opts.assetID < 0 {
		return fmt.Errorf("report: --asset must be a positive asset id, got %d", opts.assetID)
	}

	db, err := deps.openDB(ctx, deps.paths.DBPath())
	if err != nil {
		return fmt.Errorf("report: open database: %w", err)
	}
	defer func() { _ = deps.closeDB(db) }()

	var assetID *int64
	if opts.assetID > 0 {
		// Snapshot treats an unknown asset as an empty scope, which would hide a
		// typo behind a valid-looking report. The CLI resolves the id against
		// the store first so a wrong id is an error.
		if target, err := store.LoadAssetTarget(ctx, db, opts.assetID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("report: no asset with id %d", opts.assetID)
			}
			return fmt.Errorf("report: read asset %d: %w", opts.assetID, err)
		} else if target.Archived {
			return fmt.Errorf("report: asset %d is archived", opts.assetID)
		}
		id := opts.assetID
		assetID = &id
	}

	service, err := deps.newService(db)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}
	snapshot, err := service.Snapshot(ctx, assetID)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}

	if err := renderReport(w, format, snapshot); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	return nil
}

// reportFormat normalizes the flag and rejects an unknown value with the list
// of accepted ones.
func reportFormat(value string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(value))
	switch format {
	case reportFormatMarkdown, reportFormatHTML, reportFormatJSON:
		return format, nil
	default:
		return "", fmt.Errorf("report: unsupported format %q (supported: %s, %s, %s)",
			value, reportFormatMarkdown, reportFormatHTML, reportFormatJSON)
	}
}

// renderReport writes the snapshot in the requested format.
func renderReport(w io.Writer, format string, snapshot reports.Snapshot) error {
	switch format {
	case reportFormatMarkdown:
		return render.Markdown(w, snapshot)
	case reportFormatHTML:
		return render.HTML(w, snapshot)
	case reportFormatJSON:
		return render.JSON(w, snapshot)
	default:
		// reportFormat already rejected everything else.
		return fmt.Errorf("unsupported format %q", format)
	}
}
