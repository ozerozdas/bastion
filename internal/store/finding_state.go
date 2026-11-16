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

// MaxFindingStateBatch caps one bulk decision. The API rejects larger lists
// before they reach the store; the store refuses them too, so a direct caller
// cannot build an unbounded SQL statement.
const MaxFindingStateBatch = 5000

// UnknownFingerprintsError reports fingerprints a bulk decision named that the
// asset has no finding for. Nothing was written.
type UnknownFingerprintsError struct {
	AssetID      int64
	Fingerprints []string
}

func (e *UnknownFingerprintsError) Error() string {
	return fmt.Sprintf("store: set finding states: asset %d has no finding for %s",
		e.AssetID, fingerprintSample(e.Fingerprints))
}

// SetFindingStates records one decision for many fingerprints of one asset in
// a single transaction. Every fingerprint must already be a finding of the
// asset: one unknown fingerprint aborts the batch before any row is written,
// so the caller never has to undo a partial decision.
func SetFindingStates(ctx context.Context, db *sql.DB, assetID int64, fingerprints []string, state, reason string) error {
	if db == nil {
		return errors.New("store: set finding states: database is required")
	}
	if assetID <= 0 {
		return errors.New("store: set finding states: asset_id must be positive")
	}
	if len(fingerprints) == 0 {
		return errors.New("store: set finding states: at least one fingerprint is required")
	}
	if len(fingerprints) > MaxFindingStateBatch {
		return fmt.Errorf("store: set finding states: at most %d fingerprints per request", MaxFindingStateBatch)
	}
	if !validFindingState(state) {
		return fmt.Errorf("store: set finding states: state %q is not one of %s, %s, %s",
			state, FindingStateIgnored, FindingStateAcceptedRisk, FindingStateFalsePositive)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return errors.New("store: set finding states: a reason is required")
	}

	// Duplicates would only repeat the same upsert; the decision is per
	// fingerprint, so the batch is deduplicated once here.
	unique := make([]string, 0, len(fingerprints))
	seen := make(map[string]struct{}, len(fingerprints))
	for _, fingerprint := range fingerprints {
		fingerprint = strings.TrimSpace(fingerprint)
		if fingerprint == "" {
			return errors.New("store: set finding states: fingerprint is required")
		}
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		unique = append(unique, fingerprint)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: set finding states for asset %d: begin transaction: %w", assetID, err)
	}
	// A rollback after a successful commit is a no-op; the error is not
	// actionable either way.
	defer func() { _ = tx.Rollback() }()

	queries := sqlcdb.New(tx)
	known, err := queries.ListKnownFingerprints(ctx, sqlcdb.ListKnownFingerprintsParams{
		AssetID:      assetID,
		Fingerprints: unique,
	})
	if err != nil {
		return fmt.Errorf("store: set finding states for asset %d: check fingerprints: %w", assetID, err)
	}
	knownSet := make(map[string]struct{}, len(known))
	for _, fingerprint := range known {
		knownSet[fingerprint] = struct{}{}
	}
	unknown := make([]string, 0)
	for _, fingerprint := range unique {
		if _, ok := knownSet[fingerprint]; !ok {
			unknown = append(unknown, fingerprint)
		}
	}
	if len(unknown) > 0 {
		return &UnknownFingerprintsError{AssetID: assetID, Fingerprints: unknown}
	}

	for _, fingerprint := range unique {
		if err := queries.UpsertFindingState(ctx, sqlcdb.UpsertFindingStateParams{
			AssetID:     assetID,
			Fingerprint: fingerprint,
			State:       state,
			Reason:      nullString(reason),
		}); err != nil {
			return fmt.Errorf("store: set finding states for asset %d: fingerprint %q: %w", assetID, fingerprint, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: set finding states for asset %d: commit: %w", assetID, err)
	}
	return nil
}

// fingerprintSample keeps an error message readable when a batch names many
// unknown fingerprints; the full list stays in the typed error.
func fingerprintSample(fingerprints []string) string {
	const shown = 5
	if len(fingerprints) <= shown {
		return strings.Join(fingerprints, ", ")
	}
	return fmt.Sprintf("%s (and %d more)", strings.Join(fingerprints[:shown], ", "), len(fingerprints)-shown)
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
