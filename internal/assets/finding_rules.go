package assets

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Limits on the text of one rule, which an agent can also supply.
const (
	maxRuleFieldLen  = 256
	maxRuleReasonLen = 1000
)

// FindingRuleInput describes a suppression rule (#181). A nil AssetID applies
// it to every asset; at least one matcher is required.
type FindingRuleInput struct {
	AssetID     *int64
	FindingType string
	RuleID      string
	PackageName string
	PathGlob    string
	State       string
	Reason      string
	ExpiresAt   string
}

// FindingRule is a stored rule and the number of findings it closes.
type FindingRule struct {
	ID int64
	FindingRuleInput
	Status    string
	CreatedBy string
	CreatedAt string
	Matched   int
}

// FindingRules lists every rule, proposals first.
func (s *Service) FindingRules(ctx context.Context) ([]FindingRule, error) {
	rows, err := sqlcdb.New(s.db).ListFindingRules(ctx, store.FormatTimestamp(time.Now()))
	if err != nil {
		return nil, fmt.Errorf("assets: list finding rules: %w", err)
	}
	out := make([]FindingRule, 0, len(rows))
	for _, row := range rows {
		rule := FindingRule{
			ID: row.ID,
			FindingRuleInput: FindingRuleInput{
				FindingType: row.FindingType.String,
				RuleID:      row.RuleID.String,
				PackageName: row.PackageName.String,
				PathGlob:    row.PathGlob.String,
				State:       row.State,
				Reason:      row.Reason,
				ExpiresAt:   row.ExpiresAt.String,
			},
			Status:    row.Status,
			CreatedBy: row.CreatedBy,
			CreatedAt: row.CreatedAt,
			Matched:   int(row.Matched),
		}
		if row.AssetID.Valid {
			id := row.AssetID.Int64
			rule.AssetID = &id
		}
		out = append(out, rule)
	}
	return out, nil
}

// CreateFindingRule stores the user's rule and applies it at once.
func (s *Service) CreateFindingRule(ctx context.Context, in FindingRuleInput) (int64, error) {
	return s.addFindingRule(ctx, in, store.FindingRuleActive, store.FindingDeciderUser)
}

// ProposeFindingRule stores an agent's rule, which closes nothing until the
// user approves it. Malware and secrets stay outside what an agent can propose.
func (s *Service) ProposeFindingRule(ctx context.Context, in FindingRuleInput) (int64, error) {
	if in.AssetID == nil {
		return 0, fmt.Errorf("%w: an agent can only propose a rule for one asset", ErrInvalid)
	}
	if kind := strings.ToLower(strings.TrimSpace(in.FindingType)); kind == "secret" || kind == "malware" {
		return 0, fmt.Errorf("%w: an agent cannot propose a rule for %s findings", ErrInvalid, kind)
	}
	return s.addFindingRule(ctx, in, store.FindingRuleProposed, store.FindingDeciderAgent)
}

// ApproveFindingRule activates a proposal and applies it.
func (s *Service) ApproveFindingRule(ctx context.Context, id int64) error {
	found, err := store.ApproveFindingRule(ctx, s.db, id)
	if err != nil {
		return fmt.Errorf("assets: %w", err)
	}
	if !found {
		return fmt.Errorf("%w: no proposed rule %d", ErrNotFound, id)
	}
	return nil
}

// DeleteFindingRule removes a rule or rejects a proposal.
func (s *Service) DeleteFindingRule(ctx context.Context, id int64) error {
	found, err := store.DeleteFindingRule(ctx, s.db, id)
	if err != nil {
		return fmt.Errorf("assets: %w", err)
	}
	if !found {
		return fmt.Errorf("%w: no rule %d", ErrNotFound, id)
	}
	return nil
}

func (s *Service) addFindingRule(ctx context.Context, in FindingRuleInput, status, createdBy string) (int64, error) {
	kind, ruleID := strings.TrimSpace(in.FindingType), strings.TrimSpace(in.RuleID)
	pkg, glob := strings.TrimSpace(in.PackageName), strings.TrimSpace(in.PathGlob)
	if kind == "" && ruleID == "" && pkg == "" && glob == "" {
		return 0, fmt.Errorf("%w: a rule needs a type, rule id, package or path", ErrInvalid)
	}
	switch kind {
	case "", "vulnerability", "secret", "outdated", "misconfig", "license", "sast":
	default:
		return 0, fmt.Errorf("%w: a rule cannot match type %q", ErrInvalid, kind)
	}
	for _, field := range []string{ruleID, pkg, glob} {
		if len(field) > maxRuleFieldLen || strings.ContainsFunc(field, unicode.IsControl) {
			return 0, fmt.Errorf("%w: rule fields are at most %d bytes of plain text", ErrInvalid, maxRuleFieldLen)
		}
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) > maxRuleReasonLen {
		return 0, fmt.Errorf("%w: reason is longer than %d bytes", ErrInvalid, maxRuleReasonLen)
	}
	if err := checkFindingDecision(in.State, reason); err != nil {
		return 0, err
	}
	expiresAt, err := s.parseExpiry(in.ExpiresAt)
	if err != nil {
		return 0, err
	}

	params := sqlcdb.CreateFindingRuleParams{
		FindingType: optionalText(kind),
		RuleID:      optionalText(ruleID),
		PackageName: optionalText(pkg),
		PathGlob:    optionalText(glob),
		State:       in.State,
		Reason:      reason,
		Status:      status,
		CreatedBy:   createdBy,
	}
	if expiresAt != nil {
		params.ExpiresAt = optionalText(store.FormatTimestamp(*expiresAt))
	}
	if in.AssetID != nil {
		if err := s.requireAsset(ctx, *in.AssetID); err != nil {
			return 0, err
		}
		params.AssetID = sql.NullInt64{Int64: *in.AssetID, Valid: true}
	}
	id, err := store.CreateFindingRule(ctx, s.db, params)
	if err != nil {
		return 0, fmt.Errorf("assets: %w", err)
	}
	return id, nil
}

func optionalText(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}
