package reports

import (
	"context"
	"fmt"
	"regexp"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// eolDate matches the YYYY-MM-DD date the eol scanner writes into the
// description of an end-of-life finding.
var eolDate = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)

// RuntimeAsset is one asset that runs a runtime.
type RuntimeAsset struct {
	AssetID     int64
	DisplayName string
}

// Runtime is one end-of-life runtime, grouped by name and version, with every
// asset that runs it.
type Runtime struct {
	Name      string
	Ecosystem string
	Version   string
	// EOLDate is the end-of-life date as YYYY-MM-DD; empty when the scanner
	// reported none.
	EOLDate string
	// FixedVersion is the newest supported version; empty when unknown.
	FixedVersion string
	Assets       []RuntimeAsset
}

// Runtimes groups the latest open end-of-life findings of the given asset (0
// means every asset) by runtime name and version. The scope is the latest
// findings list's: the newest succeeded scan of every non-archived asset, with
// ignored findings left out and licence "allow" findings hidden.
func (s *Service) Runtimes(ctx context.Context, assetID int64) ([]Runtime, error) {
	if err := (Filter{AssetID: assetID}).validate(); err != nil {
		return nil, err
	}

	params := sqlcdb.RuntimeEOLFindingsParams{Now: s.expiryNow()}
	if assetID > 0 {
		params.AssetID = assetID
	}
	rows, err := sqlcdb.New(s.db).RuntimeEOLFindings(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("reports: runtimes: %w", err)
	}

	runtimes := make([]Runtime, 0)
	position := make(map[string]int)
	for _, row := range rows {
		name := row.PackageName.String
		version := row.PackageVersion.String
		key := name + "\x00" + version
		index, ok := position[key]
		if !ok {
			index = len(runtimes)
			position[key] = index
			runtimes = append(runtimes, Runtime{
				Name:         name,
				Ecosystem:    row.Ecosystem.String,
				Version:      version,
				EOLDate:      eolDate.FindString(row.Description.String),
				FixedVersion: row.FixedVersion.String,
				Assets:       make([]RuntimeAsset, 0),
			})
		} else {
			// Scanners report the same runtime with differing detail. Keep the
			// most complete row instead of whichever asset happened to sort
			// first: the end-of-life date matters most, then the fixed version,
			// then the ecosystem.
			mergeRuntimeDetails(&runtimes[index], row)
		}
		runtimes[index].Assets = append(runtimes[index].Assets, RuntimeAsset{
			AssetID:     row.AssetID,
			DisplayName: row.DisplayName,
		})
	}
	return runtimes, nil
}

// mergeRuntimeDetails fills a grouped runtime from another asset's row when
// that row is more complete, field by field in priority order.
func mergeRuntimeDetails(runtime *Runtime, row sqlcdb.RuntimeEOLFindingsRow) {
	if candidate := eolDate.FindString(row.Description.String); candidate != "" && runtime.EOLDate == "" {
		runtime.EOLDate = candidate
	}
	if candidate := row.FixedVersion.String; candidate != "" && runtime.FixedVersion == "" {
		runtime.FixedVersion = candidate
	}
	if candidate := row.Ecosystem.String; candidate != "" && runtime.Ecosystem == "" {
		runtime.Ecosystem = candidate
	}
}
