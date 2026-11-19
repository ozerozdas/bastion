// Package preferences stores per-install UI choices (#150).
//
// The theme, the language and the dashboard dismissals used to live only in
// the browser's localStorage, which is scoped to one origin: changing the port
// lost them. They now also live on the server, keyed by the same localStorage
// key, so the UI can use localStorage as a first-paint cache and let the
// server copy win.
package preferences

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// MaxValueLength is the longest accepted value, in characters. It matches the
// API contract and the database CHECK.
const MaxValueLength = 64

// ErrInvalid marks preferences the service refuses; handlers map it to HTTP
// 400.
var ErrInvalid = errors.New("preferences: invalid")

// Keys is the whitelist of localStorage keys the UI synchronizes. An unknown
// key is rejected rather than stored, so a stale client cannot grow the table.
var Keys = []string{
	"bastion-theme",
	"bastion-mode",
	"bastion-font-family",
	"bastion-font-size",
	"bastion-language",
	"bastion-width",
	"bastion:get-started:cli-done",
	"bastion:get-started:dismissed",
}

// allowed is the whitelist as a set, kept in step with Keys.
var allowed = func() map[string]struct{} {
	set := make(map[string]struct{}, len(Keys))
	for _, key := range Keys {
		set[key] = struct{}{}
	}
	return set
}()

// Service reads and merges preferences. It is safe for concurrent use.
type Service struct {
	db *sql.DB
}

// NewService validates its dependency and returns a Service.
func NewService(db *sql.DB) (*Service, error) {
	if db == nil {
		return nil, errors.New("preferences: database is required")
	}
	return &Service{db: db}, nil
}

// Get returns every stored preference. A key without a value is absent, which
// is how the UI tells "the server has no copy" from a stored default.
func (s *Service) Get(ctx context.Context) (map[string]string, error) {
	rows, err := sqlcdb.New(s.db).ListPreferences(ctx)
	if err != nil {
		return nil, fmt.Errorf("preferences: list: %w", err)
	}
	return toMap(rows, nil), nil
}

// Merge validates updates and writes them in one transaction, leaving keys the
// request does not carry untouched. It returns the full stored set.
func (s *Service) Merge(ctx context.Context, updates map[string]string) (map[string]string, error) {
	if err := Validate(updates); err != nil {
		return nil, err
	}
	if len(updates) == 0 {
		return s.Get(ctx)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("preferences: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	queries := sqlcdb.New(tx)
	for key, value := range updates {
		if err := queries.UpsertPreference(ctx, sqlcdb.UpsertPreferenceParams{
			Key:   key,
			Value: value,
		}); err != nil {
			return nil, fmt.Errorf("preferences: store %q: %w", key, err)
		}
	}
	rows, err := queries.ListPreferences(ctx)
	if err != nil {
		return nil, fmt.Errorf("preferences: list: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("preferences: commit: %w", err)
	}

	// Only whitelisted keys can be written, but filtering the read as well
	// keeps a key removed from the whitelist out of every response.
	return toMap(rows, allowed), nil
}

// Validate rejects an unknown key and a value longer than MaxValueLength.
func Validate(updates map[string]string) error {
	for key, value := range updates {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%w: unknown preference %q", ErrInvalid, key)
		}
		if utf8.RuneCountInString(value) > MaxValueLength {
			return fmt.Errorf("%w: %q is longer than %d characters",
				ErrInvalid, key, MaxValueLength)
		}
	}
	return nil
}

// toMap turns the stored rows into a non-nil map. A nil filter keeps every
// key; otherwise only keys in the filter survive.
func toMap(rows []sqlcdb.ListPreferencesRow, filter map[string]struct{}) map[string]string {
	preferences := make(map[string]string, len(rows))
	for _, row := range rows {
		if filter != nil {
			if _, ok := filter[row.Key]; !ok {
				continue
			}
		}
		preferences[row.Key] = row.Value
	}
	return preferences
}
