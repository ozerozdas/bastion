package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ozerozdas/bastion/internal/assets"
	"github.com/ozerozdas/bastion/internal/fixplan"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/store"
)

// scanStatusSucceeded is the only scans.status a diff accepts (§5).
const scanStatusSucceeded = "succeeded"

// scanStatusQueued is the scans.status trigger_scan returns.
const scanStatusQueued = "queued"

// severityCounts is a finding count per severity (§5).
type severityCounts struct {
	Critical int `json:"critical" jsonschema:"number of critical findings"`
	High     int `json:"high" jsonschema:"number of high findings"`
	Medium   int `json:"medium" jsonschema:"number of medium findings"`
	Low      int `json:"low" jsonschema:"number of low findings"`
	Unknown  int `json:"unknown" jsonschema:"number of findings with unknown severity"`
}

func countsFromAssets(counts assets.SeverityCounts) severityCounts {
	return severityCounts{
		Critical: counts.Critical,
		High:     counts.High,
		Medium:   counts.Medium,
		Low:      counts.Low,
		Unknown:  counts.Unknown,
	}
}

func countsFromReports(totals reports.SeverityTotals) severityCounts {
	return severityCounts{
		Critical: totals.Critical,
		High:     totals.High,
		Medium:   totals.Medium,
		Low:      totals.Low,
		Unknown:  totals.Unknown,
	}
}

func countsFromFixPlan(counts fixplan.SeverityCounts) severityCounts {
	return severityCounts{
		Critical: counts.Critical,
		High:     counts.High,
		Medium:   counts.Medium,
		Low:      counts.Low,
		Unknown:  counts.Unknown,
	}
}

// timestamp renders an optional time as RFC 3339 (UTC) or an empty string.
func timestamp(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

// --- trigger_scan --------------------------------------------------------

// errServeNotRunning is the tool error when no process exists that could run a
// queued scan. `bastion mcp` must not start a scan manager itself: a second
// manager would recover (fail) serve's scans and race its Trivy downloads.
var errServeNotRunning = errors.New("bastion serve is not running; start it to run scans")

type triggerScanInput struct {
	AssetID int64 `json:"asset_id" jsonschema:"id of the asset to scan; list_assets returns ids"`
}

type triggerScanData struct {
	ScanID int64  `json:"scan_id" jsonschema:"id of the queued scan"`
	Status string `json:"status" jsonschema:"scan status: queued"`
	// AlreadyQueued says no row was created because the asset already had a
	// queued or running scan, which ScanID names.
	AlreadyQueued bool `json:"already_queued" jsonschema:"the asset already had a queued or running scan, returned instead of a new one"`
}

// triggerScan queues a scan row for a running `bastion serve` to pick up. It
// writes exactly one queued scan row: the scan itself runs in the serve
// process, so this process needs no manager.
func (s *Server) triggerScan(ctx context.Context, _ *mcp.CallToolRequest, in triggerScanInput) (
	*mcp.CallToolResult, triggerScanData, error,
) {
	if s.serveRunning == nil || !s.serveRunning() {
		return nil, triggerScanData{}, errServeNotRunning
	}

	queued, alreadyQueued, err := s.assets.QueueMCP(ctx, in.AssetID)
	if err != nil {
		return nil, triggerScanData{}, fmt.Errorf("trigger scan: %w", err)
	}
	return nil, triggerScanData{
		ScanID:        queued.ScanID,
		Status:        scanStatusQueued,
		AlreadyQueued: alreadyQueued,
	}, nil
}

// --- set_finding_state and clear_finding_state ----------------------------

// Limits on one agent decision. The reason is shown to the user, so its length
// is refused rather than clipped.
const (
	maxAgentBatch     = 500
	maxAgentReasonLen = 1000
)

type setFindingStateInput struct {
	AssetID      int64    `json:"asset_id" jsonschema:"id of the asset the findings belong to"`
	Fingerprints []string `json:"fingerprints" jsonschema:"fingerprints from list_findings, at most 500"`
	State        string   `json:"state" jsonschema:"decision: ignored, accepted_risk or false_positive"`
	Reason       string   `json:"reason" jsonschema:"why the findings are noise, at most 1000 bytes; the user reviews it"`
	ExpiresAt    string   `json:"expires_at,omitempty" jsonschema:"optional future end of the decision: RFC 3339 or YYYY-MM-DD"`
}

type setFindingStateData struct {
	Updated   int    `json:"updated" jsonschema:"number of findings closed"`
	DecidedBy string `json:"decided_by" jsonschema:"who the decision is recorded for: agent"`
}

func (s *Server) setFindingState(ctx context.Context, _ *mcp.CallToolRequest, in setFindingStateInput) (
	*mcp.CallToolResult, setFindingStateData, error,
) {
	if len(in.Fingerprints) > maxAgentBatch {
		return nil, setFindingStateData{}, fmt.Errorf("set finding state: at most %d fingerprints per call", maxAgentBatch)
	}
	if len(in.Reason) > maxAgentReasonLen {
		return nil, setFindingStateData{}, fmt.Errorf("set finding state: reason is longer than %d bytes", maxAgentReasonLen)
	}
	unique := uniqueFingerprints(in.Fingerprints)
	err := s.assets.SetAgentFindingStates(ctx, assets.BulkFindingStateInput{
		AssetID:      in.AssetID,
		Fingerprints: unique,
		State:        in.State,
		Reason:       in.Reason,
		ExpiresAt:    in.ExpiresAt,
	})
	if err != nil {
		return nil, setFindingStateData{}, fmt.Errorf("set finding state: %w", err)
	}
	return nil, setFindingStateData{Updated: len(unique), DecidedBy: store.FindingDeciderAgent}, nil
}

type clearFindingStateInput struct {
	AssetID      int64    `json:"asset_id" jsonschema:"id of the asset the findings belong to"`
	Fingerprints []string `json:"fingerprints" jsonschema:"fingerprints to reopen, at most 500"`
}

type clearFindingStateData struct {
	Cleared int `json:"cleared" jsonschema:"number of agent decisions removed"`
}

func (s *Server) clearFindingState(ctx context.Context, _ *mcp.CallToolRequest, in clearFindingStateInput) (
	*mcp.CallToolResult, clearFindingStateData, error,
) {
	if len(in.Fingerprints) > maxAgentBatch {
		return nil, clearFindingStateData{}, fmt.Errorf("clear finding state: at most %d fingerprints per call", maxAgentBatch)
	}
	cleared, err := s.assets.ClearAgentFindingStates(ctx, in.AssetID, uniqueFingerprints(in.Fingerprints))
	if err != nil {
		return nil, clearFindingStateData{}, fmt.Errorf("clear finding state: %w", err)
	}
	return nil, clearFindingStateData{Cleared: cleared}, nil
}

// uniqueFingerprints trims the list and drops repeats, keeping blanks so the
// service rejects them.
func uniqueFingerprints(fingerprints []string) []string {
	seen := make(map[string]struct{}, len(fingerprints))
	out := make([]string, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		fingerprint = strings.TrimSpace(fingerprint)
		if _, dup := seen[fingerprint]; dup {
			continue
		}
		seen[fingerprint] = struct{}{}
		out = append(out, fingerprint)
	}
	return out
}

// --- list_assets ---------------------------------------------------------

type listAssetsInput struct{}

type assetLink struct {
	AssetID     int64  `json:"asset_id" jsonschema:"id of the linked asset"`
	Ref         string `json:"ref" jsonschema:"canonical ref of the linked asset"`
	DisplayName string `json:"display_name" jsonschema:"display name of the linked asset"`
	Source      string `json:"source,omitempty" jsonschema:"how the link was made: manual, label or heuristic"`
	Revision    string `json:"revision,omitempty" jsonschema:"revision recorded by the image label"`
}

type assetLastScan struct {
	ScanID     int64  `json:"scan_id" jsonschema:"id of the asset's newest scan"`
	Status     string `json:"status" jsonschema:"scan status: queued, running, succeeded, failed or canceled"`
	FinishedAt string `json:"finished_at,omitempty" jsonschema:"RFC 3339 finish time, empty while it has not finished"`
}

type assetItem struct {
	ID             int64          `json:"id" jsonschema:"asset id other tools take"`
	Kind           string         `json:"kind" jsonschema:"asset kind: repo, image or path"`
	DisplayName    string         `json:"display_name" jsonschema:"display name"`
	Ref            string         `json:"ref" jsonschema:"canonical ref (owner/repo, registry/repo or absolute path)"`
	DefaultBranch  string         `json:"default_branch,omitempty" jsonschema:"default branch of a repository asset"`
	ECRRegistry    string         `json:"ecr_registry,omitempty" jsonschema:"ECR registry an image was added from"`
	CreatedAt      string         `json:"created_at" jsonschema:"RFC 3339 time the asset was added"`
	LastScan       *assetLastScan `json:"last_scan,omitempty" jsonschema:"newest scan of the asset, whatever its status"`
	OpenSeverities severityCounts `json:"open_severities" jsonschema:"open findings per severity in the asset's newest succeeded scan"`
	LinkedRepo     *assetLink     `json:"linked_repo,omitempty" jsonschema:"repository an image asset was built from"`
	LinkedImages   []assetLink    `json:"linked_images" jsonschema:"images linked to a repository asset"`
}

type listAssetsData struct {
	Assets []assetItem `json:"assets" jsonschema:"tracked assets, newest activity first"`
}

func (s *Server) listAssets(ctx context.Context, _ *mcp.CallToolRequest, _ listAssetsInput) (
	*mcp.CallToolResult, untrusted[listAssetsData], error,
) {
	list, err := s.assets.List(ctx)
	if err != nil {
		return nil, untrusted[listAssetsData]{}, fmt.Errorf("list assets: %w", err)
	}

	data := listAssetsData{Assets: make([]assetItem, 0, len(list))}
	for _, asset := range list {
		data.Assets = append(data.Assets, assetItem{
			ID:             asset.ID,
			Kind:           asset.Kind,
			DisplayName:    asset.DisplayName,
			Ref:            asset.Ref,
			DefaultBranch:  asset.DefaultBranch,
			ECRRegistry:    asset.ECRRegistry,
			CreatedAt:      asset.CreatedAt.UTC().Format(time.RFC3339),
			LastScan:       lastScanItem(asset.LastScan),
			OpenSeverities: countsFromAssets(asset.OpenSeverities),
			LinkedRepo:     linkItem(asset.LinkedRepo),
			LinkedImages:   linkItems(asset.LinkedImages),
		})
	}
	return nil, wrapUntrusted(data), nil
}

func lastScanItem(scan *assets.LastScan) *assetLastScan {
	if scan == nil {
		return nil
	}
	return &assetLastScan{
		ScanID:     scan.ScanID,
		Status:     scan.Status,
		FinishedAt: timestamp(scan.FinishedAt),
	}
}

func linkItem(link *assets.AssetLink) *assetLink {
	if link == nil {
		return nil
	}
	return &assetLink{
		AssetID:     link.AssetID,
		Ref:         link.Ref,
		DisplayName: link.DisplayName,
		Source:      link.Source,
		Revision:    link.Revision,
	}
}

func linkItems(links []assets.AssetLink) []assetLink {
	out := make([]assetLink, 0, len(links))
	for _, link := range links {
		out = append(out, *linkItem(&link))
	}
	return out
}

// --- list_findings -------------------------------------------------------

type listFindingsInput struct {
	AssetID         int64  `json:"asset_id,omitempty" jsonschema:"only findings of this asset id; omit or 0 for every asset"`
	Severity        string `json:"severity,omitempty" jsonschema:"only this severity: critical, high, medium, low or unknown"`
	Type            string `json:"type,omitempty" jsonschema:"only this finding type: vulnerability, secret, outdated, misconfig, license, malware or sast"`
	Status          string `json:"status,omitempty" jsonschema:"only this effective status: open or ignored"`
	DecidedBy       string `json:"decided_by,omitempty" jsonschema:"only decisions made by: user or agent"`
	Fix             string `json:"fix,omitempty" jsonschema:"only findings with a known fix (available) or without one (none)"`
	Dependency      string `json:"dependency,omitempty" jsonschema:"only findings of direct or indirect dependencies"`
	HideTests       bool   `json:"hide_tests,omitempty" jsonschema:"leave out findings in test, fixture and example paths"`
	HideMaintenance bool   `json:"hide_maintenance,omitempty" jsonschema:"leave out licence and outdated-package findings"`
	Query           string `json:"query,omitempty" jsonschema:"case-insensitive substring of the title, rule id, package name or file path; at most 200 characters"`
	Sort            string `json:"sort,omitempty" jsonschema:"order by severity, title, package, project or type; omit for most severe first"`
	Order           string `json:"order,omitempty" jsonschema:"sort direction: asc or desc; omit for ascending"`
	Limit           int    `json:"limit,omitempty" jsonschema:"page size between 1 and 500; omit for 50"`
	Offset          int    `json:"offset,omitempty" jsonschema:"number of findings to skip; omit for 0"`
}

type epssItem struct {
	Score      float64 `json:"score" jsonschema:"probability of exploitation in the next 30 days (0..1)"`
	Percentile float64 `json:"percentile" jsonschema:"rank among all scored CVEs (0..1)"`
}

type findingItem struct {
	ID              int64     `json:"id" jsonschema:"finding id"`
	AssetID         int64     `json:"asset_id" jsonschema:"asset the finding belongs to"`
	ScanID          int64     `json:"scan_id" jsonschema:"scan that produced the finding"`
	Fingerprint     string    `json:"fingerprint" jsonschema:"stable fingerprint used by diffs and ignore decisions"`
	Type            string    `json:"type" jsonschema:"finding type"`
	Severity        string    `json:"severity" jsonschema:"severity"`
	Title           string    `json:"title" jsonschema:"finding title as the scanner reported it"`
	RuleID          string    `json:"rule_id,omitempty" jsonschema:"CVE, GHSA or scanner rule id"`
	PackageName     string    `json:"package_name,omitempty" jsonschema:"affected package"`
	PackageVersion  string    `json:"package_version,omitempty" jsonschema:"installed version"`
	FixedVersion    string    `json:"fixed_version,omitempty" jsonschema:"version that fixes the finding, empty when none is known"`
	Ecosystem       string    `json:"ecosystem,omitempty" jsonschema:"package ecosystem"`
	Location        string    `json:"location,omitempty" jsonschema:"file:line or path inside the image"`
	Occurrences     int       `json:"occurrences" jsonschema:"times the finding was reported in the scan"`
	Scanner         string    `json:"scanner" jsonschema:"scanner that produced the finding"`
	Scanners        []string  `json:"scanners" jsonschema:"every scanner that reported the finding"`
	Status          string    `json:"status" jsonschema:"effective status: open or ignored"`
	State           string    `json:"state,omitempty" jsonschema:"stored ignore decision, if any"`
	Reason          string    `json:"reason,omitempty" jsonschema:"reason recorded with the ignore decision"`
	DecidedBy       string    `json:"decided_by,omitempty" jsonschema:"who made the ignore decision: user or agent"`
	ExpiresAt       string    `json:"expires_at,omitempty" jsonschema:"RFC 3339 expiry of the ignore decision"`
	Expired         bool      `json:"expired" jsonschema:"the ignore decision expired, so the finding is open again"`
	FirstSeenScanID *int64    `json:"first_seen_scan_id,omitempty" jsonschema:"scan that first reported the finding"`
	Description     string    `json:"description,omitempty" jsonschema:"long description as the scanner reported it"`
	References      []string  `json:"references" jsonschema:"reference URLs reported by the scanner"`
	EPSS            *epssItem `json:"epss,omitempty" jsonschema:"EPSS prediction when the opt-in feed scored the rule id"`
	Reachability    string    `json:"reachability,omitempty" jsonschema:"Go reachability: reachable, unreachable or unknown"`
	LicencePolicy   string    `json:"licence_policy,omitempty" jsonschema:"effective licence rule: allow or deny"`
}

type listFindingsData struct {
	Findings []findingItem `json:"findings" jsonschema:"one page of the latest findings"`
	Total    int           `json:"total" jsonschema:"number of findings the filters match, ignoring the page"`
	Limit    int           `json:"limit" jsonschema:"page size used"`
	Offset   int           `json:"offset" jsonschema:"offset used"`
}

func (s *Server) listFindings(ctx context.Context, _ *mcp.CallToolRequest, in listFindingsInput) (
	*mcp.CallToolResult, untrusted[listFindingsData], error,
) {
	limit := in.Limit
	if limit == 0 {
		limit = reports.DefaultFindingLimit
	}
	page := reports.Page{Limit: limit, Offset: in.Offset}
	filter := reports.Filter{
		AssetID:         in.AssetID,
		Severity:        in.Severity,
		Type:            in.Type,
		Status:          in.Status,
		DecidedBy:       in.DecidedBy,
		Fix:             in.Fix,
		Dependency:      in.Dependency,
		HideTests:       in.HideTests,
		HideMaintenance: in.HideMaintenance,
		Query:           in.Query,
	}
	by := reports.Sort{Column: in.Sort, Order: in.Order}

	items, total, err := s.reports.FindingsPage(ctx, filter, page, by)
	if err != nil {
		return nil, untrusted[listFindingsData]{}, fmt.Errorf("list findings: %w", err)
	}

	data := listFindingsData{
		Findings: make([]findingItem, 0, len(items)),
		Total:    total,
		Limit:    limit,
		Offset:   in.Offset,
	}
	for _, finding := range items {
		data.Findings = append(data.Findings, findingResponse(finding))
	}
	return nil, wrapUntrusted(data), nil
}

func findingResponse(finding reports.Finding) findingItem {
	out := findingItem{
		ID:              finding.ID,
		AssetID:         finding.AssetID,
		ScanID:          finding.ScanID,
		Fingerprint:     finding.Fingerprint,
		Type:            finding.Type,
		Severity:        finding.Severity,
		Title:           finding.Title,
		RuleID:          finding.RuleID,
		PackageName:     finding.PackageName,
		PackageVersion:  finding.PackageVersion,
		FixedVersion:    finding.FixedVersion,
		Ecosystem:       finding.Ecosystem,
		Location:        finding.Location,
		Occurrences:     finding.Occurrences,
		Scanner:         finding.Scanner,
		Scanners:        finding.Scanners,
		Status:          finding.Status,
		State:           finding.State,
		Reason:          finding.Reason,
		DecidedBy:       finding.DecidedBy,
		ExpiresAt:       finding.ExpiresAt,
		Expired:         finding.Expired,
		FirstSeenScanID: finding.FirstSeenScanID,
		Description:     clip(finding.Description, MaxDescriptionBytes),
		References:      finding.References,
		Reachability:    string(finding.Reachability),
		LicencePolicy:   finding.LicencePolicy,
	}
	if out.Scanners == nil {
		out.Scanners = []string{}
	}
	if out.References == nil {
		out.References = []string{}
	}
	if len(out.References) > MaxReferences {
		out.References = out.References[:MaxReferences]
	}
	out.Title = clip(out.Title, MaxFieldBytes)
	out.Location = clip(out.Location, MaxFieldBytes)
	out.PackageName = clip(out.PackageName, MaxFieldBytes)
	out.Reason = clip(out.Reason, MaxFieldBytes)
	if finding.EPSS != nil {
		out.EPSS = &epssItem{Score: finding.EPSS.Score, Percentile: finding.EPSS.Percentile}
	}
	return out
}

func findingResponses(list []reports.Finding) []findingItem {
	out := make([]findingItem, 0, len(list))
	for _, finding := range list {
		out = append(out, findingResponse(finding))
	}
	return out
}

// --- get_fix_plan --------------------------------------------------------

type getFixPlanInput struct {
	AssetID int64 `json:"asset_id" jsonschema:"asset id whose open vulnerabilities are grouped; list_assets returns ids"`
}

type fixPlanFactor struct {
	Name   string  `json:"name" jsonschema:"factor name"`
	Value  float64 `json:"value" jsonschema:"multiplier or weight the factor contributed"`
	Detail string  `json:"detail" jsonschema:"human-readable explanation of the value"`
}

type fixPlanStep struct {
	Ecosystem         string          `json:"ecosystem" jsonschema:"package ecosystem"`
	Package           string          `json:"package" jsonschema:"package to upgrade"`
	InstalledVersions []string        `json:"installed_versions" jsonschema:"installed versions the step's findings report"`
	TargetVersion     string          `json:"target_version" jsonschema:"version the upgrade should reach"`
	Approximate       bool            `json:"approximate" jsonschema:"the target version order is a best effort, not ecosystem-authoritative"`
	FindingCount      int             `json:"finding_count" jsonschema:"open findings this upgrade closes"`
	SeverityCounts    severityCounts  `json:"severity_counts" jsonschema:"closed findings per severity"`
	FindingIDs        []int64         `json:"finding_ids" jsonschema:"ids of the findings this upgrade closes"`
	MaxEPSS           *epssItem       `json:"max_epss,omitempty" jsonschema:"highest EPSS score among the step's findings"`
	Reachability      string          `json:"reachability,omitempty" jsonschema:"Go reachability folded across the step's findings"`
	Score             float64         `json:"score" jsonschema:"prioritization score; higher is more urgent"`
	Factors           []fixPlanFactor `json:"factors" jsonschema:"score factors in the order they were applied"`
}

type fixPlanNoFix struct {
	Ecosystem      string         `json:"ecosystem" jsonschema:"package ecosystem"`
	Package        string         `json:"package" jsonschema:"package with no available fix"`
	FindingCount   int            `json:"finding_count" jsonschema:"open findings no upgrade closes"`
	SeverityCounts severityCounts `json:"severity_counts" jsonschema:"findings per severity"`
	FindingIDs     []int64        `json:"finding_ids" jsonschema:"ids of the findings with no fix"`
}

type fixPlanData struct {
	AssetID int64          `json:"asset_id" jsonschema:"asset the plan belongs to"`
	Steps   []fixPlanStep  `json:"steps" jsonschema:"package upgrades ordered by score, most urgent first"`
	NoFix   []fixPlanNoFix `json:"no_fix" jsonschema:"packages whose open findings no upgrade closes"`
}

func (s *Server) getFixPlan(ctx context.Context, _ *mcp.CallToolRequest, in getFixPlanInput) (
	*mcp.CallToolResult, untrusted[fixPlanData], error,
) {
	plan, err := s.reports.FixPlan(ctx, in.AssetID)
	if err != nil {
		return nil, untrusted[fixPlanData]{}, fmt.Errorf("get fix plan: %w", err)
	}

	data := fixPlanData{
		AssetID: in.AssetID,
		Steps:   make([]fixPlanStep, 0, len(plan.Steps)),
		NoFix:   make([]fixPlanNoFix, 0, len(plan.NoFix)),
	}
	for _, step := range plan.Steps {
		item := fixPlanStep{
			Ecosystem:         step.Ecosystem,
			Package:           step.Package,
			InstalledVersions: step.InstalledVersions,
			TargetVersion:     step.TargetVersion,
			Approximate:       step.Approximate,
			FindingCount:      step.FindingCount,
			SeverityCounts:    countsFromFixPlan(step.SeverityCounts),
			FindingIDs:        step.FindingIDs,
			Reachability:      string(step.Reachability),
			Score:             step.Score,
			Factors:           make([]fixPlanFactor, 0, len(step.Factors)),
		}
		if item.InstalledVersions == nil {
			item.InstalledVersions = []string{}
		}
		if item.FindingIDs == nil {
			item.FindingIDs = []int64{}
		}
		if step.MaxEPSS != nil {
			item.MaxEPSS = &epssItem{Score: step.MaxEPSS.Score, Percentile: step.MaxEPSS.Percentile}
		}
		for _, factor := range step.Factors {
			item.Factors = append(item.Factors, fixPlanFactor{
				Name:   factor.Name,
				Value:  factor.Value,
				Detail: factor.Detail,
			})
		}
		data.Steps = append(data.Steps, item)
	}
	for _, group := range plan.NoFix {
		item := fixPlanNoFix{
			Ecosystem:      group.Ecosystem,
			Package:        group.Package,
			FindingCount:   group.FindingCount,
			SeverityCounts: countsFromFixPlan(group.SeverityCounts),
			FindingIDs:     group.FindingIDs,
		}
		if item.FindingIDs == nil {
			item.FindingIDs = []int64{}
		}
		data.NoFix = append(data.NoFix, item)
	}
	return nil, wrapUntrusted(data), nil
}

// --- diff_scans ----------------------------------------------------------

type diffScansInput struct {
	ScanID        int64 `json:"scan_id,omitempty" jsonschema:"scan to diff, compared with against_scan_id or the asset's previous succeeded scan"`
	AgainstScanID int64 `json:"against_scan_id,omitempty" jsonschema:"baseline scan id; omit to use the newest succeeded scan older than scan_id"`
	AssetID       int64 `json:"asset_id,omitempty" jsonschema:"asset whose last two succeeded scans are diffed; used when scan_id is omitted"`
}

type scanDiffCounts struct {
	New        severityCounts `json:"new" jsonschema:"new findings per severity"`
	Fixed      severityCounts `json:"fixed" jsonschema:"fixed findings per severity"`
	Persisting severityCounts `json:"persisting" jsonschema:"persisting findings per severity"`
}

type scanDiffData struct {
	ScanID        int64          `json:"scan_id" jsonschema:"scan the diff reads the new and persisting groups from"`
	AgainstScanID *int64         `json:"against_scan_id,omitempty" jsonschema:"baseline scan; absent when the scan had nothing to compare with"`
	New           []findingItem  `json:"new" jsonschema:"findings only in scan_id"`
	Fixed         []findingItem  `json:"fixed" jsonschema:"findings only in against_scan_id"`
	Persisting    []findingItem  `json:"persisting" jsonschema:"findings in both scans"`
	Counts        scanDiffCounts `json:"counts" jsonschema:"each group's finding count per severity"`
}

func (s *Server) diffScans(ctx context.Context, _ *mcp.CallToolRequest, in diffScansInput) (
	*mcp.CallToolResult, untrusted[scanDiffData], error,
) {
	diff, err := s.resolveDiff(ctx, in)
	if err != nil {
		return nil, untrusted[scanDiffData]{}, fmt.Errorf("diff scans: %w", err)
	}
	return nil, wrapUntrusted(scanDiffData{
		ScanID:        diff.ScanID,
		AgainstScanID: diff.AgainstScanID,
		New:           findingResponses(diff.New),
		Fixed:         findingResponses(diff.Fixed),
		Persisting:    findingResponses(diff.Persisting),
		Counts: scanDiffCounts{
			New:        countsFromReports(diff.Counts.New),
			Fixed:      countsFromReports(diff.Counts.Fixed),
			Persisting: countsFromReports(diff.Counts.Persisting),
		},
	}), nil
}

// resolveDiff turns the input into a scan pair. With scan_id the baseline is
// explicit or the previous succeeded scan, as reports.ScanDiff decides; with
// only asset_id it takes the asset's newest succeeded scan and lets
// reports.ScanDiff pick the one before it.
func (s *Server) resolveDiff(ctx context.Context, in diffScansInput) (reports.ScanDiff, error) {
	if in.ScanID > 0 {
		return s.reports.ScanDiff(ctx, in.ScanID, in.AgainstScanID)
	}
	if in.AgainstScanID > 0 {
		return reports.ScanDiff{}, errors.New("against_scan_id requires scan_id")
	}
	if in.AssetID <= 0 {
		return reports.ScanDiff{}, errors.New("scan_id or asset_id is required")
	}

	page, err := s.assets.Scans(ctx, in.AssetID, assets.MaxScanLimit, 0, assets.ScanSort{})
	if err != nil {
		return reports.ScanDiff{}, err
	}
	for _, scan := range page.Scans {
		if scan.Status == scanStatusSucceeded {
			return s.reports.ScanDiff(ctx, scan.ID, 0)
		}
	}
	return reports.ScanDiff{}, fmt.Errorf("asset %d has no succeeded scan", in.AssetID)
}
