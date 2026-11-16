// Package licencepolicy stores the allow/deny policy for licence findings
// (#39).
//
// A policy is global when AssetID is nil, otherwise it belongs to one asset.
// The findings queries resolve a per-asset rule over a global one at read time,
// so a change applies to stored findings immediately without rewriting scans.
package licencepolicy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Actions a rule can carry.
const (
	// ActionAllow hides a matching licence finding from the findings list,
	// grouped view, dashboard counts and export.
	ActionAllow = "allow"
	// ActionDeny keeps the finding but raises its severity to at least high.
	ActionDeny = "deny"
)

// Validation limits, mirrored by the API contract.
const (
	// MaxLicenceLength is the longest accepted licence id.
	MaxLicenceLength = 128
	// MaxLicenceEntries is the largest policy, counting allow and deny.
	MaxLicenceEntries = 500
)

// ErrInvalid marks a policy the service refuses; handlers map it to HTTP 400.
var ErrInvalid = errors.New("licence policy: invalid")

// ErrNotFound marks an asset id no asset owns; handlers map it to HTTP 404.
var ErrNotFound = errors.New("licence policy: not found")

// Policy is one scope's allow and deny lists. Entries are normalized to lower
// case and sorted, so two equal policies always compare and serialize equal.
type Policy struct {
	Allow []string
	Deny  []string
}

// Service reads and replaces licence policies. It is safe for concurrent use.
type Service struct {
	db *sql.DB
}

// NewService validates its dependency and returns a Service.
func NewService(db *sql.DB) (*Service, error) {
	if db == nil {
		return nil, errors.New("licence policy: database is required")
	}
	return &Service{db: db}, nil
}

// Get returns one scope's policy: the global policy when assetID is nil,
// otherwise that asset's policy. An unknown asset is ErrNotFound; an asset
// without rules has an empty policy.
func (s *Service) Get(ctx context.Context, assetID *int64) (Policy, error) {
	if err := s.checkAsset(ctx, assetID); err != nil {
		return Policy{}, err
	}

	rows, err := sqlcdb.New(s.db).ListLicencePolicy(ctx, nullableAssetID(assetID))
	if err != nil {
		return Policy{}, fmt.Errorf("licence policy: list: %w", err)
	}

	policy := Policy{Allow: make([]string, 0), Deny: make([]string, 0)}
	for _, row := range rows {
		switch row.Action {
		case ActionAllow:
			policy.Allow = append(policy.Allow, row.Licence)
		case ActionDeny:
			policy.Deny = append(policy.Deny, row.Licence)
		}
	}
	return policy, nil
}

// Replace validates policy and swaps one scope's rules in a single
// transaction, so a failed write leaves the previous policy intact.
func (s *Service) Replace(ctx context.Context, assetID *int64, policy Policy) (Policy, error) {
	normalized, err := Normalize(policy)
	if err != nil {
		return Policy{}, err
	}
	if err := s.checkAsset(ctx, assetID); err != nil {
		return Policy{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Policy{}, fmt.Errorf("licence policy: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	queries := sqlcdb.New(tx)
	if err := queries.DeleteLicencePolicy(ctx, nullableAssetID(assetID)); err != nil {
		return Policy{}, fmt.Errorf("licence policy: clear: %w", err)
	}

	var asset sql.NullInt64
	if assetID != nil {
		asset = sql.NullInt64{Int64: *assetID, Valid: true}
	}
	insert := func(entries []string, action string) error {
		for _, licence := range entries {
			if err := queries.InsertLicencePolicy(ctx, sqlcdb.InsertLicencePolicyParams{
				AssetID: asset,
				Licence: licence,
				Action:  action,
			}); err != nil {
				return fmt.Errorf("licence policy: insert %q: %w", licence, err)
			}
		}
		return nil
	}
	if err := insert(normalized.Allow, ActionAllow); err != nil {
		return Policy{}, err
	}
	if err := insert(normalized.Deny, ActionDeny); err != nil {
		return Policy{}, err
	}
	if err := tx.Commit(); err != nil {
		return Policy{}, fmt.Errorf("licence policy: commit: %w", err)
	}

	return normalized, nil
}

// Normalize validates a policy and returns its canonical form: trimmed,
// lower-cased, de-duplicated and sorted lists.
func Normalize(policy Policy) (Policy, error) {
	allow, err := normalizeList("allow", policy.Allow)
	if err != nil {
		return Policy{}, err
	}
	deny, err := normalizeList("deny", policy.Deny)
	if err != nil {
		return Policy{}, err
	}
	if len(allow)+len(deny) > MaxLicenceEntries {
		return Policy{}, fmt.Errorf("%w: at most %d entries are allowed", ErrInvalid, MaxLicenceEntries)
	}
	for _, licence := range allow {
		if slices.Contains(deny, licence) {
			return Policy{}, fmt.Errorf("%w: %q is in both the allow and the deny list", ErrInvalid, licence)
		}
	}
	return Policy{Allow: allow, Deny: deny}, nil
}

// normalizeList trims, lower-cases, validates and sorts one list. Duplicates
// collapse rather than fail: the same licence twice is not a second rule.
func normalizeList(name string, entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, raw := range entries {
		licence := strings.ToLower(strings.TrimSpace(raw))
		if licence == "" {
			return nil, fmt.Errorf("%w: the %s list has an empty licence", ErrInvalid, name)
		}
		if len(licence) > MaxLicenceLength {
			return nil, fmt.Errorf("%w: licence %q is longer than %d characters",
				ErrInvalid, licence, MaxLicenceLength)
		}
		for i := 0; i < len(licence); i++ {
			if licence[i] < 0x20 || licence[i] > 0x7E {
				return nil, fmt.Errorf("%w: licence %q must be printable ASCII", ErrInvalid, licence)
			}
		}
		if _, ok := seen[licence]; ok {
			continue
		}
		seen[licence] = struct{}{}
		out = append(out, licence)
	}
	slices.Sort(out)
	return out, nil
}

// checkAsset rejects an asset id no row owns. A nil id is the global scope and
// always valid.
func (s *Service) checkAsset(ctx context.Context, assetID *int64) error {
	if assetID == nil {
		return nil
	}
	if *assetID < 1 {
		return fmt.Errorf("%w: asset_id must be positive", ErrInvalid)
	}
	if _, err := sqlcdb.New(s.db).GetAsset(ctx, *assetID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: asset %d", ErrNotFound, *assetID)
		}
		return fmt.Errorf("licence policy: look up asset %d: %w", *assetID, err)
	}
	return nil
}

// nullableAssetID converts the scope pointer to the query's nullable argument.
func nullableAssetID(assetID *int64) interface{} {
	if assetID == nil {
		return nil
	}
	return *assetID
}
