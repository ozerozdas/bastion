package reports

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/epss"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// advisoryID matches the advisory ids the CVE insights report accepts: a CVE
// (at least four digits in the sequence number) or a GHSA id. Matching is
// case-insensitive; callers normalize the id before the lookup.
var advisoryID = regexp.MustCompile(`(?i)^(CVE-[0-9]{4}-[0-9]{4,}|GHSA(-[a-z0-9]{4}){3})$`)

// CVEInsightAsset is one asset's match for the requested advisory.
type CVEInsightAsset struct {
	AssetID        int64
	DisplayName    string
	Kind           string
	Severity       string
	PackageName    string
	PackageVersion string
	FixedVersion   string
	// FirstSeen is the finish time of the scan that first reported the
	// finding for the asset; nil when that scan is unknown.
	FirstSeen *time.Time
}

// CVEInsights is everything GET /api/reports/cve-insights returns.
type CVEInsights struct {
	CVE string
	// EPSS is the advisory's exploit prediction. Nil when the feed is off,
	// has not downloaded yet, or does not score the id.
	EPSS   *epss.Score
	Assets []CVEInsightAsset
}

// CVEInsights matches the latest open findings of the given asset (0 means
// every asset) against one CVE or GHSA id. The scope is the latest findings
// list's: the newest succeeded scan of every non-archived asset, with ignored
// findings left out. Aliases are merge-only and never stored, so only the rule
// id is matched. An id nothing matches is not an error.
func (s *Service) CVEInsights(ctx context.Context, cve string, assetID int64) (CVEInsights, error) {
	id, err := NormalizeCVEID(cve)
	if err != nil {
		return CVEInsights{}, err
	}
	filter := Filter{AssetID: assetID}
	if err := filter.validate(); err != nil {
		return CVEInsights{}, err
	}

	params := sqlcdb.CVEInsightsFindingsParams{Now: s.expiryNow(), Cve: id}
	if assetID > 0 {
		params.AssetID = assetID
	}
	rows, err := sqlcdb.New(s.db).CVEInsightsFindings(ctx, params)
	if err != nil {
		return CVEInsights{}, fmt.Errorf("reports: cve insights: %w", err)
	}

	insights := CVEInsights{CVE: id, Assets: make([]CVEInsightAsset, 0, len(rows))}
	if s.epss != nil {
		if score, ok := s.epss.Lookup(id); ok {
			insights.EPSS = &score
		}
	}
	for _, row := range rows {
		firstSeen, err := parseTimestamp(row.FirstSeenAt)
		if err != nil {
			return CVEInsights{}, fmt.Errorf("reports: cve insight %d: %w", row.ID, err)
		}
		insights.Assets = append(insights.Assets, CVEInsightAsset{
			AssetID:        row.AssetID,
			DisplayName:    row.DisplayName,
			Kind:           row.Kind,
			Severity:       row.Severity,
			PackageName:    row.PackageName.String,
			PackageVersion: row.PackageVersion.String,
			FixedVersion:   row.FixedVersion.String,
			FirstSeen:      firstSeen,
		})
	}
	return insights, nil
}

// NormalizeCVEID validates a CVE or GHSA id and returns its canonical form:
// upper case for a CVE (the form the scanners store), unchanged otherwise. A
// value that is neither is refused with ErrInvalid, which the handler maps to
// 400.
func NormalizeCVEID(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("%w: cve is required", ErrInvalid)
	}
	if !advisoryID.MatchString(trimmed) {
		return "", fmt.Errorf("%w: cve %q is not a CVE (CVE-YYYY-N...) or GHSA id", ErrInvalid, value)
	}
	if strings.HasPrefix(strings.ToUpper(trimmed), "CVE-") {
		return strings.ToUpper(trimmed), nil
	}
	return trimmed, nil
}
