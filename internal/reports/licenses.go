package reports

import (
	"context"
	"fmt"
	"sort"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Effective licence policy values a report entry can carry.
const (
	LicensePolicyAllow = "allow"
	LicensePolicyDeny  = "deny"
	LicensePolicyNone  = "none"
)

// LicenseItem is one licence finding behind an entry.
type LicenseItem struct {
	PackageName    string
	PackageVersion string
	Ecosystem      string
	AssetID        int64
	DisplayName    string
	// Ignored is true while a live finding decision covers this finding.
	Ignored bool
	// State is the decision's value (ignored, accepted_risk or false_positive),
	// empty when no live decision applies.
	State string
}

// LicenseEntry is one licence name with the policy that applies to it.
type LicenseEntry struct {
	License string
	Policy  string
	// Packages counts the distinct package names in Items.
	Packages int
	// IgnoredPackages counts the distinct package names whose finding carries
	// a live decision.
	IgnoredPackages int
	// Assets counts the distinct assets in Items.
	Assets int
	Items  []LicenseItem
}

// LicenseReport is everything GET /api/reports/licenses returns.
type LicenseReport struct {
	Licenses []LicenseEntry
}

// Licenses lists the latest open licence findings, grouped by licence name and
// the effective allow/deny rule (#39). A per-asset rule overrides the global
// one. The scope is the findings list's, except that allow findings and
// findings carrying a live decision are kept: this report is the whole licence
// inventory, not only the issues. assetID 0 means every asset.
func (s *Service) Licenses(ctx context.Context, assetID int64) (LicenseReport, error) {
	if err := (Filter{AssetID: assetID}).validate(); err != nil {
		return LicenseReport{}, err
	}

	params := sqlcdb.ReportLicenseFindingsParams{Now: s.expiryNow()}
	if assetID > 0 {
		params.AssetID = assetID
	}
	rows, err := sqlcdb.New(s.db).ReportLicenseFindings(ctx, params)
	if err != nil {
		return LicenseReport{}, fmt.Errorf("reports: list licence findings: %w", err)
	}

	entries := make([]LicenseEntry, 0)
	byKey := make(map[string]int, len(rows))
	for _, row := range rows {
		key := row.License + "\x00" + row.Policy
		index, ok := byKey[key]
		if !ok {
			index = len(entries)
			byKey[key] = index
			entries = append(entries, LicenseEntry{
				License: row.License,
				Policy:  row.Policy,
				Items:   make([]LicenseItem, 0),
			})
		}
		entries[index].Items = append(entries[index].Items, LicenseItem{
			PackageName:    row.PackageName.String,
			PackageVersion: row.PackageVersion.String,
			Ecosystem:      row.Ecosystem.String,
			AssetID:        row.AssetID,
			DisplayName:    row.DisplayName,
			Ignored:        row.Ignored != 0,
			State:          row.State.String,
		})
	}

	for i := range entries {
		packages := make(map[string]struct{}, len(entries[i].Items))
		ignoredPackages := make(map[string]struct{})
		assets := make(map[int64]struct{}, len(entries[i].Items))
		for _, item := range entries[i].Items {
			packages[item.PackageName] = struct{}{}
			if item.Ignored {
				ignoredPackages[item.PackageName] = struct{}{}
			}
			assets[item.AssetID] = struct{}{}
		}
		entries[i].Packages = len(packages)
		entries[i].IgnoredPackages = len(ignoredPackages)
		entries[i].Assets = len(assets)
		sort.SliceStable(entries[i].Items, func(a, b int) bool {
			left, right := entries[i].Items[a], entries[i].Items[b]
			if left.DisplayName != right.DisplayName {
				return compareText(left.DisplayName, right.DisplayName) < 0
			}
			if left.PackageName != right.PackageName {
				return compareText(left.PackageName, right.PackageName) < 0
			}
			return compareText(left.PackageVersion, right.PackageVersion) < 0
		})
	}

	// Deny first, then the rest by package count descending, then by licence
	// name so equal entries have one deterministic order.
	sort.SliceStable(entries, func(i, j int) bool {
		left, right := entries[i], entries[j]
		if leftRank, rightRank := licensePolicyRank(left.Policy), licensePolicyRank(right.Policy); leftRank != rightRank {
			return leftRank < rightRank
		}
		if left.Packages != right.Packages {
			return left.Packages > right.Packages
		}
		return compareText(left.License, right.License) < 0
	})

	return LicenseReport{Licenses: entries}, nil
}

// licensePolicyRank orders deny first and then everything else.
func licensePolicyRank(policy string) int {
	if policy == LicensePolicyDeny {
		return 0
	}
	return 1
}
