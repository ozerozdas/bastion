package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// finding_rules.status values (#181).
const (
	FindingRuleActive   = "active"
	FindingRuleProposed = "proposed"
)

// applyFindingRules closes what the active rules match. A nil assetID covers
// every asset.
func applyFindingRules(ctx context.Context, queries *sqlcdb.Queries, assetID any) error {
	return queries.ApplyFindingRules(ctx, sqlcdb.ApplyFindingRulesParams{
		AssetID: assetID,
		Now:     FormatTimestamp(time.Now()),
	})
}

// CreateFindingRule stores a rule and, when it is active, applies it.
func CreateFindingRule(ctx context.Context, db *sql.DB, params sqlcdb.CreateFindingRuleParams) (int64, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: create finding rule: begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	queries := sqlcdb.New(tx)
	id, err := queries.CreateFindingRule(ctx, params)
	if err != nil {
		return 0, fmt.Errorf("store: create finding rule: %w", err)
	}
	if params.Status == FindingRuleActive {
		if err := applyFindingRules(ctx, queries, nil); err != nil {
			return 0, fmt.Errorf("store: apply finding rule %d: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: create finding rule: commit: %w", err)
	}
	return id, nil
}

// ApproveFindingRule activates a proposed rule. It reports false when no
// proposal has that id.
func ApproveFindingRule(ctx context.Context, db *sql.DB, id int64) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store: approve finding rule %d: begin transaction: %w", id, err)
	}
	defer func() { _ = tx.Rollback() }()

	queries := sqlcdb.New(tx)
	rows, err := queries.ActivateFindingRule(ctx, id)
	if err != nil {
		return false, fmt.Errorf("store: approve finding rule %d: %w", id, err)
	}
	if rows == 0 {
		return false, nil
	}
	if err := applyFindingRules(ctx, queries, nil); err != nil {
		return false, fmt.Errorf("store: apply finding rule %d: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store: approve finding rule %d: commit: %w", id, err)
	}
	return true, nil
}

// DeleteFindingRule removes a rule and reopens the findings it closed, unless
// another active rule still matches them. It reports false for an unknown id.
func DeleteFindingRule(ctx context.Context, db *sql.DB, id int64) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store: delete finding rule %d: begin transaction: %w", id, err)
	}
	defer func() { _ = tx.Rollback() }()

	queries := sqlcdb.New(tx)
	if err := queries.DeleteFindingStatesByRule(ctx, sql.NullInt64{Int64: id, Valid: true}); err != nil {
		return false, fmt.Errorf("store: delete finding rule %d: reopen findings: %w", id, err)
	}
	rows, err := queries.DeleteFindingRule(ctx, id)
	if err != nil {
		return false, fmt.Errorf("store: delete finding rule %d: %w", id, err)
	}
	if rows == 0 {
		return false, nil
	}
	if err := applyFindingRules(ctx, queries, nil); err != nil {
		return false, fmt.Errorf("store: delete finding rule %d: reapply rules: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store: delete finding rule %d: commit: %w", id, err)
	}
	return true, nil
}
