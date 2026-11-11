package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// finding_states.state values (PROJECT_SPEC.md §5). Any of them hides the
// finding from the open list; the state itself tells the UI why.
const (
	FindingStateIgnored       = "ignored"
	FindingStateAcceptedRisk  = "accepted_risk"
	FindingStateFalsePositive = "false_positive"
)

// SetFindingState records a user decision for one fingerprint of one asset.
// The decision is keyed on (asset_id, fingerprint), so it applies again when a
// later scan rediscovers the same finding; the findings rows themselves are
// never rewritten. Re-deciding replaces the previous state and reason.
//
// A non-blank reason is required: "why was this hidden" is what keeps an
// ignore list reviewable. An unknown state is rejected before the database
// sees it, so the caller gets a message that names the culprit.
func SetFindingState(ctx context.Context, db *sql.DB, assetID int64, fingerprint, state, reason string) error {
	if db == nil {
		return errors.New("store: set finding state: database is required")
	}
	if strings.TrimSpace(fingerprint) == "" {
		return errors.New("store: set finding state: fingerprint is required")
	}
	if !validFindingState(state) {
		return fmt.Errorf("store: set finding state: state %q is not one of %s, %s, %s",
			state, FindingStateIgnored, FindingStateAcceptedRisk, FindingStateFalsePositive)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return errors.New("store: set finding state: a reason is required")
	}

	err := sqlcdb.New(db).UpsertFindingState(ctx, sqlcdb.UpsertFindingStateParams{
		AssetID:     assetID,
		Fingerprint: fingerprint,
		State:       state,
		Reason:      nullString(reason),
	})
	if err != nil {
		return fmt.Errorf("store: set finding state %q for asset %d: %w", state, assetID, err)
	}
	return nil
}

// ClearFindingState removes the decision for one fingerprint, so later scans of
// the asset report the finding as open again. Clearing a state that does not
// exist is not an error: the outcome is the same.
func ClearFindingState(ctx context.Context, db *sql.DB, assetID int64, fingerprint string) error {
	if db == nil {
		return errors.New("store: clear finding state: database is required")
	}
	if strings.TrimSpace(fingerprint) == "" {
		return errors.New("store: clear finding state: fingerprint is required")
	}

	err := sqlcdb.New(db).DeleteFindingState(ctx, sqlcdb.DeleteFindingStateParams{
		AssetID:     assetID,
		Fingerprint: fingerprint,
	})
	if err != nil {
		return fmt.Errorf("store: clear finding state for asset %d: %w", assetID, err)
	}
	return nil
}

func validFindingState(state string) bool {
	switch state {
	case FindingStateIgnored, FindingStateAcceptedRisk, FindingStateFalsePositive:
		return true
	}
	return false
}
