package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// finding_states.state values (PROJECT_SPEC.md §5). Any of them hides the
// finding from the open list; the state itself tells the UI why.
const (
	FindingStateIgnored       = "ignored"
	FindingStateAcceptedRisk  = "accepted_risk"
	FindingStateFalsePositive = "false_positive"
)

// finding_states.decided_by values: who made the decision (#180).
const (
	FindingDeciderUser  = "user"
	FindingDeciderAgent = "agent"
)

// expiryLayout is the canonical UTC form of finding_states.expires_at. The
// read queries compare it as text with a passed-in now, so both sides must use
// it; a lexicographic comparison then orders correctly.
const expiryLayout = "2006-01-02T15:04:05.000Z"

// FormatTimestamp renders t in the canonical UTC form the finding-state
// queries compare. A caller passes a clock-derived now through it too, so a
// decision expires in the same instant for every reader and a test can pin the
// clock.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Format(expiryLayout)
}

// expiryValue converts an optional expiry to the stored column value. A nil
// expiry keeps the decision until it is cleared.
func expiryValue(expiresAt *time.Time) sql.NullString {
	if expiresAt == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: FormatTimestamp(*expiresAt), Valid: true}
}

// SetFindingState records a user decision for one fingerprint of one asset.
// The decision is keyed on (asset_id, fingerprint), so it applies again when a
// later scan rediscovers the same finding; the findings rows themselves are
// never rewritten. Re-deciding replaces the previous state, reason and expiry.
//
// A non-blank reason is required: "why was this hidden" is what keeps an
// ignore list reviewable. An unknown state is rejected before the database
// sees it, so the caller gets a message that names the culprit. An expiry is
// optional: once it passes, the finding counts as open again.
func SetFindingState(ctx context.Context, db *sql.DB, assetID int64, fingerprint, state, reason string, expiresAt *time.Time) error {
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
		ExpiresAt:   expiryValue(expiresAt),
		DecidedBy:   FindingDeciderUser,
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
// so the caller never has to undo a partial decision. The optional expiry is
// shared by the whole batch.
func SetFindingStates(ctx context.Context, db *sql.DB, assetID int64, fingerprints []string, state, reason string, expiresAt *time.Time) error {
	return setFindingStates(ctx, db, assetID, fingerprints, state, reason, expiresAt, FindingDeciderUser)
}

// AgentRefusedError reports a batch an agent may not decide. Scanned content
// is untrusted and can steer an agent, so malware and secrets stay with the
// user, as does every decision the user already made. Nothing was written.
type AgentRefusedError struct {
	// Restricted names malware and secret findings.
	Restricted []string
	// UserDecided names findings whose decision belongs to the user.
	UserDecided []string
}

func (e *AgentRefusedError) Error() string {
	parts := make([]string, 0, 2)
	if len(e.Restricted) > 0 {
		parts = append(parts, "malware and secret findings need the user's decision: "+fingerprintSample(e.Restricted))
	}
	if len(e.UserDecided) > 0 {
		parts = append(parts, "the user's decision cannot be changed: "+fingerprintSample(e.UserDecided))
	}
	return strings.Join(parts, "; ") + "; nothing was written"
}

// SetAgentFindingStates records an agent's decision, under the same rules as
// SetFindingStates. The batch is refused whole with an AgentRefusedError when
// it names a finding the agent may not decide.
func SetAgentFindingStates(ctx context.Context, db *sql.DB, assetID int64, fingerprints []string, state, reason string, expiresAt *time.Time) error {
	return setFindingStates(ctx, db, assetID, fingerprints, state, reason, expiresAt, FindingDeciderAgent)
}

// ClearAgentFindingStates removes an agent's decisions and returns how many
// were removed. Naming a decision the user made refuses the whole batch.
func ClearAgentFindingStates(ctx context.Context, db *sql.DB, assetID int64, fingerprints []string) (int, error) {
	if db == nil {
		return 0, errors.New("store: clear agent finding states: database is required")
	}
	if len(fingerprints) == 0 || len(fingerprints) > MaxFindingStateBatch {
		return 0, fmt.Errorf("store: clear agent finding states: between 1 and %d fingerprints per request", MaxFindingStateBatch)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: clear agent finding states for asset %d: begin transaction: %w", assetID, err)
	}
	defer func() { _ = tx.Rollback() }()

	queries := sqlcdb.New(tx)
	userDecided, err := queries.ListUserDecidedFingerprints(ctx, sqlcdb.ListUserDecidedFingerprintsParams{
		AssetID:      assetID,
		Now:          FormatTimestamp(time.Now()),
		Fingerprints: fingerprints,
	})
	if err != nil {
		return 0, fmt.Errorf("store: clear agent finding states for asset %d: check decisions: %w", assetID, err)
	}
	if len(userDecided) > 0 {
		return 0, &AgentRefusedError{UserDecided: userDecided}
	}

	var cleared int64
	for _, fingerprint := range fingerprints {
		rows, err := queries.DeleteAgentFindingState(ctx, sqlcdb.DeleteAgentFindingStateParams{
			AssetID:     assetID,
			Fingerprint: fingerprint,
		})
		if err != nil {
			return 0, fmt.Errorf("store: clear agent finding states for asset %d: %w", assetID, err)
		}
		cleared += rows
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: clear agent finding states for asset %d: commit: %w", assetID, err)
	}
	return int(cleared), nil
}

func setFindingStates(ctx context.Context, db *sql.DB, assetID int64, fingerprints []string, state, reason string, expiresAt *time.Time, decidedBy string) error {
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

	if decidedBy == FindingDeciderAgent {
		restricted, err := queries.ListAgentRestrictedFingerprints(ctx, sqlcdb.ListAgentRestrictedFingerprintsParams{
			AssetID:      assetID,
			Fingerprints: unique,
		})
		if err != nil {
			return fmt.Errorf("store: set finding states for asset %d: check finding types: %w", assetID, err)
		}
		userDecided, err := queries.ListUserDecidedFingerprints(ctx, sqlcdb.ListUserDecidedFingerprintsParams{
			AssetID:      assetID,
			Now:          FormatTimestamp(time.Now()),
			Fingerprints: unique,
		})
		if err != nil {
			return fmt.Errorf("store: set finding states for asset %d: check decisions: %w", assetID, err)
		}
		if len(restricted) > 0 || len(userDecided) > 0 {
			return &AgentRefusedError{Restricted: restricted, UserDecided: userDecided}
		}
	}

	for _, fingerprint := range unique {
		if err := queries.UpsertFindingState(ctx, sqlcdb.UpsertFindingStateParams{
			AssetID:     assetID,
			Fingerprint: fingerprint,
			State:       state,
			Reason:      nullString(reason),
			ExpiresAt:   expiryValue(expiresAt),
			DecidedBy:   decidedBy,
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
