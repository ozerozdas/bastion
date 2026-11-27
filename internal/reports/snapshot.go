package reports

import (
	"context"
	"fmt"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/licencepolicy"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Snapshot is one deterministic, offline view of the fleet: coverage, open
// findings, SLA status, triage decisions, suppression rules and the licence
// policy (#204). It reuses the same queries and read models as the web Reports
// page, so the snapshot and the UI can never disagree. Slices, never maps, keep
// the JSON field order stable.
type Snapshot struct {
	// GeneratedAt is the service clock, so a pinned clock makes two snapshots
	// byte-identical.
	GeneratedAt      time.Time                `json:"generated_at"`
	Scope            SnapshotScope            `json:"scope"`
	Coverage         SnapshotCoverage         `json:"coverage"`
	Findings         SnapshotFindings         `json:"findings"`
	SLA              SnapshotSLA              `json:"sla"`
	Decisions        SnapshotDecisions        `json:"decisions"`
	SuppressionRules SnapshotSuppressionRules `json:"suppression_rules"`
	LicencePolicy    SnapshotLicencePolicy    `json:"licence_policy"`
}

// SnapshotScope names what the snapshot covers: every non-archived asset, or
// one asset.
type SnapshotScope struct {
	// All is true when the snapshot covers the whole fleet.
	All bool `json:"all"`
	// AssetID is nil for the fleet scope.
	AssetID *int64 `json:"asset_id"`
	// AssetName is empty for the fleet scope or an asset no coverage row
	// matched.
	AssetName string `json:"asset_name"`
}

// SnapshotCoverage is how many assets were scanned and what the latest scan of
// each reported.
type SnapshotCoverage struct {
	AssetsTotal    int                     `json:"assets_total"`
	Scanned        int                     `json:"scanned"`
	NeverScanned   int                     `json:"never_scanned"`
	LastScanFailed int                     `json:"last_scan_failed"`
	Assets         []SnapshotAssetCoverage `json:"assets"`
}

// SnapshotAssetCoverage is one asset and the scanner runs of its newest scan.
type SnapshotAssetCoverage struct {
	AssetID     int64                `json:"asset_id"`
	DisplayName string               `json:"display_name"`
	Kind        string               `json:"kind"`
	Ref         string               `json:"ref"`
	LastScan    *SnapshotLastScan    `json:"last_scan"`
	Scanners    []SnapshotScannerRun `json:"scanners"`
}

// SnapshotLastScan is the newest scan of an asset, whatever its status.
type SnapshotLastScan struct {
	ID         int64      `json:"id"`
	Status     string     `json:"status"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// SnapshotScannerRun is one scanner's result inside a scan.
type SnapshotScannerRun struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	DBVersion  string `json:"db_version"`
	Status     string `json:"status"`
	DurationMS *int64 `json:"duration_ms"`
	Error      string `json:"error"`
}

// SnapshotFindings is the open finding count per severity, fleet-wide and per
// asset. The scope and severity are the dashboard's: live decisions applied,
// licence "allow" findings hidden, denied licences raised to high.
type SnapshotFindings struct {
	Total  SeverityTotals          `json:"total"`
	Open   int                     `json:"open"`
	Assets []SnapshotAssetFindings `json:"assets"`
}

// SnapshotAssetFindings is one asset's open findings by severity.
type SnapshotAssetFindings struct {
	AssetID     int64          `json:"asset_id"`
	DisplayName string         `json:"display_name"`
	Kind        string         `json:"kind"`
	Total       int            `json:"total"`
	Severity    SeverityTotals `json:"severity"`
}

// SnapshotSLA mirrors the SLA report without the raw finding rows.
type SnapshotSLA struct {
	Thresholds        SLAThresholds     `json:"thresholds"`
	WindowDays        int               `json:"window_days"`
	OpenCount         int               `json:"open_count"`
	OverdueCount      int               `json:"overdue_count"`
	OverdueTruncated  bool              `json:"overdue_truncated"`
	FixedInWindow     int               `json:"fixed_in_window"`
	MeanTimeToFixDays *float64          `json:"mean_time_to_fix_days"`
	Overdue           []SnapshotOverdue `json:"overdue"`
}

// SnapshotOverdue is one open finding past its severity's threshold.
type SnapshotOverdue struct {
	AssetID       int64     `json:"asset_id"`
	AssetName     string    `json:"asset_name"`
	FindingID     int64     `json:"finding_id"`
	Fingerprint   string    `json:"fingerprint"`
	Type          string    `json:"type"`
	Severity      string    `json:"severity"`
	Title         string    `json:"title"`
	RuleID        string    `json:"rule_id"`
	PackageName   string    `json:"package_name"`
	Location      string    `json:"location"`
	FirstSeen     time.Time `json:"first_seen"`
	AgeDays       int       `json:"age_days"`
	ThresholdDays int       `json:"threshold_days"`
	OverdueDays   int       `json:"overdue_days"`
}

// SnapshotDecisions lists every stored triage decision, expired ones included.
type SnapshotDecisions struct {
	Total       int                     `json:"total"`
	Expired     int                     `json:"expired"`
	ByState     []SnapshotDecisionCount `json:"by_state"`
	ByDecidedBy []SnapshotDecisionCount `json:"by_decided_by"`
	Entries     []SnapshotDecision      `json:"entries"`
}

// SnapshotDecisionCount is one decision tally; Key is a state or a decider.
type SnapshotDecisionCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// SnapshotDecision is one decision and the finding it covers.
type SnapshotDecision struct {
	AssetID     int64      `json:"asset_id"`
	AssetName   string     `json:"asset_name"`
	Fingerprint string     `json:"fingerprint"`
	Type        string     `json:"type"`
	RuleID      string     `json:"rule_id"`
	Title       string     `json:"title"`
	PackageName string     `json:"package_name"`
	Location    string     `json:"location"`
	Severity    string     `json:"severity"`
	State       string     `json:"state"`
	Reason      string     `json:"reason"`
	DecidedBy   string     `json:"decided_by"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Expired     bool       `json:"expired"`
	CreatedAt   time.Time  `json:"created_at"`
	RuleRef     *int64     `json:"rule_ref"`
}

// SnapshotSuppressionRules is the suppression-rule section of a snapshot: the
// active rules and a count of the proposals that close nothing yet.
type SnapshotSuppressionRules struct {
	ActiveCount   int            `json:"active_count"`
	ProposedCount int            `json:"proposed_count"`
	Rules         []SnapshotRule `json:"rules"`
}

// SnapshotRule is one active suppression rule.
type SnapshotRule struct {
	ID          int64      `json:"id"`
	AssetID     *int64     `json:"asset_id"`
	AssetName   string     `json:"asset_name"`
	FindingType string     `json:"finding_type"`
	RuleID      string     `json:"rule_id"`
	PackageName string     `json:"package_name"`
	PathGlob    string     `json:"path_glob"`
	State       string     `json:"state"`
	Reason      string     `json:"reason"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Expired     bool       `json:"expired"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	Matched     int        `json:"matched"`
}

// SnapshotLicencePolicy is the global allow/deny policy plus the non-empty
// per-asset policies of the scope.
type SnapshotLicencePolicy struct {
	Global SnapshotPolicy        `json:"global"`
	Assets []SnapshotAssetPolicy `json:"assets"`
}

// SnapshotPolicy is one scope's allow and deny lists, sorted.
type SnapshotPolicy struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// SnapshotAssetPolicy is one asset's licence policy.
type SnapshotAssetPolicy struct {
	AssetID   int64    `json:"asset_id"`
	AssetName string   `json:"asset_name"`
	Allow     []string `json:"allow"`
	Deny      []string `json:"deny"`
}

// Snapshot aggregates one report snapshot. assetID nil covers every
// non-archived asset, otherwise only that asset; an unknown or archived id
// yields an empty snapshot rather than an error, like the other reports.
func (s *Service) Snapshot(ctx context.Context, assetID *int64) (Snapshot, error) {
	if assetID != nil && *assetID < 1 {
		return Snapshot{}, fmt.Errorf("%w: asset_id must be positive", ErrInvalid)
	}

	now := s.now().UTC()
	var scopeArg interface{}
	var filterID int64
	if assetID != nil {
		scopeArg = *assetID
		filterID = *assetID
	}
	queries := sqlcdb.New(s.db)

	coverageRows, err := queries.ReportScannerCoverage(ctx, scopeArg)
	if err != nil {
		return Snapshot{}, fmt.Errorf("reports: snapshot coverage: %w", err)
	}
	coverage, err := buildCoverage(coverageRows)
	if err != nil {
		return Snapshot{}, err
	}

	snapshot := Snapshot{
		GeneratedAt: now,
		Scope: SnapshotScope{
			All:     assetID == nil,
			AssetID: assetID,
		},
		Coverage: coverage,
	}
	if len(coverage.Assets) == 1 && assetID != nil {
		snapshot.Scope.AssetName = coverage.Assets[0].DisplayName
	}

	openFindings, err := s.Findings(ctx, Filter{AssetID: filterID, Status: FindingStatusOpen})
	if err != nil {
		return Snapshot{}, fmt.Errorf("reports: snapshot findings: %w", err)
	}
	snapshot.Findings = buildFindings(coverage.Assets, openFindings)

	sla, err := s.SLA(ctx, filterID, DefaultSLAWindowDays)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.SLA = buildSLA(sla, DefaultSLAWindowDays, assetNamesOf(coverage.Assets))

	decisionRows, err := queries.ReportTriageDecisions(ctx, scopeArg)
	if err != nil {
		return Snapshot{}, fmt.Errorf("reports: snapshot decisions: %w", err)
	}
	snapshot.Decisions, err = buildDecisions(decisionRows, now)
	if err != nil {
		return Snapshot{}, err
	}

	ruleRows, err := queries.ListFindingRules(ctx, store.FormatTimestamp(now))
	if err != nil {
		return Snapshot{}, fmt.Errorf("reports: snapshot suppression rules: %w", err)
	}
	assetNames, err := s.AssetNames(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.SuppressionRules, err = buildRules(ruleRows, assetNames, now, assetID)
	if err != nil {
		return Snapshot{}, err
	}

	snapshot.LicencePolicy, err = s.snapshotLicencePolicy(ctx, coverage.Assets)
	if err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// buildCoverage folds the scanner-run rows into one entry per asset.
func buildCoverage(rows []sqlcdb.ReportScannerCoverageRow) (SnapshotCoverage, error) {
	coverage := SnapshotCoverage{Assets: make([]SnapshotAssetCoverage, 0)}
	var current *SnapshotAssetCoverage
	for _, row := range rows {
		if current == nil || current.AssetID != row.AssetID {
			coverage.Assets = append(coverage.Assets, SnapshotAssetCoverage{
				AssetID:     row.AssetID,
				DisplayName: row.DisplayName,
				Kind:        row.Kind,
				Ref:         row.Ref,
				Scanners:    make([]SnapshotScannerRun, 0),
			})
			current = &coverage.Assets[len(coverage.Assets)-1]
			if row.ScanID.Valid {
				lastScan, err := lastScanFromRow(row)
				if err != nil {
					return SnapshotCoverage{}, err
				}
				current.LastScan = lastScan
				if row.ScanStatus.String == store.ScanStatusFailed {
					coverage.LastScanFailed++
				}
			}
		}
		if row.Scanner.Valid {
			run := SnapshotScannerRun{
				Name:      row.Scanner.String,
				Version:   row.ScannerVersion.String,
				DBVersion: row.DBVersion.String,
				Status:    row.ScannerStatus.String,
				Error:     row.Error.String,
			}
			if row.DurationMS.Valid {
				duration := row.DurationMS.Int64
				run.DurationMS = &duration
			}
			current.Scanners = append(current.Scanners, run)
		}
	}

	coverage.AssetsTotal = len(coverage.Assets)
	for _, asset := range coverage.Assets {
		if asset.LastScan == nil {
			coverage.NeverScanned++
		} else {
			coverage.Scanned++
		}
	}
	return coverage, nil
}

// lastScanFromRow converts one coverage row's scan columns.
func lastScanFromRow(row sqlcdb.ReportScannerCoverageRow) (*SnapshotLastScan, error) {
	startedAt, err := parseTimestamp(row.StartedAt)
	if err != nil {
		return nil, fmt.Errorf("reports: snapshot asset %d scan %d: started: %w", row.AssetID, row.ScanID.Int64, err)
	}
	finishedAt, err := parseTimestamp(row.FinishedAt)
	if err != nil {
		return nil, fmt.Errorf("reports: snapshot asset %d scan %d: finished: %w", row.AssetID, row.ScanID.Int64, err)
	}
	return &SnapshotLastScan{
		ID:         row.ScanID.Int64,
		Status:     row.ScanStatus.String,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
	}, nil
}

// buildFindings folds the latest open findings into the coverage asset order,
// so the section carries every in-scope asset and no map defines its order.
func buildFindings(assets []SnapshotAssetCoverage, open []Finding) SnapshotFindings {
	report := SnapshotFindings{
		Open:   len(open),
		Assets: make([]SnapshotAssetFindings, 0, len(assets)),
	}
	index := make(map[int64]int, len(assets))
	for _, asset := range assets {
		index[asset.AssetID] = len(report.Assets)
		report.Assets = append(report.Assets, SnapshotAssetFindings{
			AssetID:     asset.AssetID,
			DisplayName: asset.DisplayName,
			Kind:        asset.Kind,
		})
	}

	for _, finding := range open {
		position, ok := index[finding.AssetID]
		if !ok {
			continue
		}
		entry := &report.Assets[position]
		entry.Total++
		switch findings.Severity(finding.Severity) {
		case findings.SeverityCritical:
			entry.Severity.Critical++
			report.Total.Critical++
		case findings.SeverityHigh:
			entry.Severity.High++
			report.Total.High++
		case findings.SeverityMedium:
			entry.Severity.Medium++
			report.Total.Medium++
		case findings.SeverityLow:
			entry.Severity.Low++
			report.Total.Low++
		default:
			entry.Severity.Unknown++
			report.Total.Unknown++
		}
	}
	return report
}

// buildSLA converts the SLA report into the snapshot's compact shape.
func buildSLA(report SLAReport, windowDays int, assetNames map[int64]string) SnapshotSLA {
	sla := SnapshotSLA{
		Thresholds:        report.Thresholds,
		WindowDays:        windowDays,
		OpenCount:         report.OpenCount,
		OverdueCount:      report.OverdueCount,
		OverdueTruncated:  report.OverdueTruncated,
		FixedInWindow:     report.FixedInWindow,
		MeanTimeToFixDays: report.MeanTimeToFixDays,
		Overdue:           make([]SnapshotOverdue, 0, len(report.Overdue)),
	}
	for _, overdue := range report.Overdue {
		finding := overdue.Finding
		sla.Overdue = append(sla.Overdue, SnapshotOverdue{
			AssetID:       finding.AssetID,
			AssetName:     assetNames[finding.AssetID],
			FindingID:     finding.ID,
			Fingerprint:   finding.Fingerprint,
			Type:          finding.Type,
			Severity:      finding.Severity,
			Title:         finding.Title,
			RuleID:        finding.RuleID,
			PackageName:   finding.PackageName,
			Location:      finding.Location,
			FirstSeen:     overdue.FirstSeen,
			AgeDays:       overdue.AgeDays,
			ThresholdDays: overdue.ThresholdDays,
			OverdueDays:   overdue.OverdueDays,
		})
	}
	return sla
}

// buildDecisions converts the decision rows, marks expiry against now and
// tallies states and deciders.
func buildDecisions(rows []sqlcdb.ReportTriageDecisionsRow, now time.Time) (SnapshotDecisions, error) {
	decisions := SnapshotDecisions{
		Entries:     make([]SnapshotDecision, 0, len(rows)),
		ByState:     decisionCounts([]string{store.FindingStateIgnored, store.FindingStateAcceptedRisk, store.FindingStateFalsePositive}),
		ByDecidedBy: decisionCounts([]string{store.FindingDeciderUser, store.FindingDeciderAgent}),
	}
	byState := make(map[string]int, len(decisions.ByState))
	for i := range decisions.ByState {
		byState[decisions.ByState[i].Key] = i
	}
	byDecider := make(map[string]int, len(decisions.ByDecidedBy))
	for i := range decisions.ByDecidedBy {
		byDecider[decisions.ByDecidedBy[i].Key] = i
	}

	for _, row := range rows {
		expiresAt, err := parseTimestamp(row.ExpiresAt)
		if err != nil {
			return SnapshotDecisions{}, fmt.Errorf("reports: snapshot decision %s: expiry: %w", row.Fingerprint, err)
		}
		createdAt, err := parseStoredTimestamp(row.CreatedAt)
		if err != nil {
			return SnapshotDecisions{}, fmt.Errorf("reports: snapshot decision %s: created: %w", row.Fingerprint, err)
		}
		expired := expiresAt != nil && !expiresAt.After(now)

		entry := SnapshotDecision{
			AssetID:     row.AssetID,
			AssetName:   row.DisplayName,
			Fingerprint: row.Fingerprint,
			Type:        row.FindingType,
			RuleID:      row.RuleID,
			Title:       row.Title,
			PackageName: row.PackageName,
			Location:    row.Location,
			Severity:    row.Severity,
			State:       row.State,
			Reason:      row.Reason,
			DecidedBy:   row.DecidedBy,
			ExpiresAt:   expiresAt,
			Expired:     expired,
			CreatedAt:   createdAt,
		}
		if row.RuleRef.Valid {
			ref := row.RuleRef.Int64
			entry.RuleRef = &ref
		}
		decisions.Entries = append(decisions.Entries, entry)
		decisions.Total++
		if expired {
			decisions.Expired++
		}
		if i, ok := byState[row.State]; ok {
			decisions.ByState[i].Count++
		}
		if i, ok := byDecider[row.DecidedBy]; ok {
			decisions.ByDecidedBy[i].Count++
		}
	}
	return decisions, nil
}

// decisionCounts builds a fixed tally list, so every state and decider appears
// even when it has no entries.
func decisionCounts(keys []string) []SnapshotDecisionCount {
	counts := make([]SnapshotDecisionCount, 0, len(keys))
	for _, key := range keys {
		counts = append(counts, SnapshotDecisionCount{Key: key})
	}
	return counts
}

// buildRules keeps the active rules, counts the proposals and marks expiry.
// A scoped assetID keeps only the global rules (asset_id NULL) and that
// asset's rules; the active and proposed counts follow the same filter.
func buildRules(rows []sqlcdb.ListFindingRulesRow, assetNames map[int64]string, now time.Time, assetID *int64) (SnapshotSuppressionRules, error) {
	section := SnapshotSuppressionRules{Rules: make([]SnapshotRule, 0)}
	for _, row := range rows {
		if assetID != nil && row.AssetID.Valid && row.AssetID.Int64 != *assetID {
			continue
		}
		if row.Status != store.FindingRuleActive {
			section.ProposedCount++
			continue
		}
		expiresAt, err := parseTimestamp(row.ExpiresAt)
		if err != nil {
			return SnapshotSuppressionRules{}, fmt.Errorf("reports: snapshot rule %d: expiry: %w", row.ID, err)
		}
		createdAt, err := parseStoredTimestamp(row.CreatedAt)
		if err != nil {
			return SnapshotSuppressionRules{}, fmt.Errorf("reports: snapshot rule %d: created: %w", row.ID, err)
		}
		rule := SnapshotRule{
			ID:          row.ID,
			FindingType: row.FindingType.String,
			RuleID:      row.RuleID.String,
			PackageName: row.PackageName.String,
			PathGlob:    row.PathGlob.String,
			State:       row.State,
			Reason:      row.Reason,
			ExpiresAt:   expiresAt,
			Expired:     expiresAt != nil && !expiresAt.After(now),
			CreatedBy:   row.CreatedBy,
			CreatedAt:   createdAt,
			Matched:     int(row.Matched),
		}
		if row.AssetID.Valid {
			id := row.AssetID.Int64
			rule.AssetID = &id
			rule.AssetName = assetNames[id]
		}
		section.Rules = append(section.Rules, rule)
	}
	section.ActiveCount = len(section.Rules)
	return section, nil
}

// snapshotLicencePolicy reads the global policy and the non-empty policy of
// every asset in scope.
func (s *Service) snapshotLicencePolicy(ctx context.Context, assets []SnapshotAssetCoverage) (SnapshotLicencePolicy, error) {
	service, err := licencepolicy.NewService(s.db)
	if err != nil {
		return SnapshotLicencePolicy{}, fmt.Errorf("reports: snapshot licence policy: %w", err)
	}

	global, err := service.Get(ctx, nil)
	if err != nil {
		return SnapshotLicencePolicy{}, fmt.Errorf("reports: snapshot licence policy: %w", err)
	}
	policy := SnapshotLicencePolicy{
		Global: snapshotPolicy(global),
		Assets: make([]SnapshotAssetPolicy, 0),
	}
	for _, asset := range assets {
		id := asset.AssetID
		scoped, err := service.Get(ctx, &id)
		if err != nil {
			return SnapshotLicencePolicy{}, fmt.Errorf("reports: snapshot licence policy for asset %d: %w", id, err)
		}
		if len(scoped.Allow) == 0 && len(scoped.Deny) == 0 {
			continue
		}
		policy.Assets = append(policy.Assets, SnapshotAssetPolicy{
			AssetID:   id,
			AssetName: asset.DisplayName,
			Allow:     append([]string{}, scoped.Allow...),
			Deny:      append([]string{}, scoped.Deny...),
		})
	}
	return policy, nil
}

// snapshotPolicy copies a policy into its stable JSON shape.
func snapshotPolicy(policy licencepolicy.Policy) SnapshotPolicy {
	return SnapshotPolicy{
		Allow: append([]string{}, policy.Allow...),
		Deny:  append([]string{}, policy.Deny...),
	}
}

// assetNamesOf maps the in-scope asset ids to their display names for the
// sections that only carry an id.
func assetNamesOf(assets []SnapshotAssetCoverage) map[int64]string {
	names := make(map[int64]string, len(assets))
	for _, asset := range assets {
		names[asset.AssetID] = asset.DisplayName
	}
	return names
}

// parseStoredTimestamp reads a NOT NULL stored timestamp; an empty value stays
// the zero time rather than failing the whole snapshot.
func parseStoredTimestamp(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp %q: %w", value, err)
	}
	return parsed, nil
}
