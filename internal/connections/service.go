// Package connections manages bastion's credentialed integrations
// (PROJECT_SPEC.md §4.1, §7).
//
// A connection row holds only non-secret data; its credential lives in the OS
// keyring under a key stored in secret_ref. Tokens are never put in SQLite,
// logged or returned by the API (§4.3).
package connections

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/connections/github"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

const (
	// KindGitHub is the only kind v0.1 can create (AWS and Docker are Phase 2).
	KindGitHub = "github"

	// StatusOK is a connection whose last test succeeded.
	StatusOK = "ok"
	// StatusError is a connection whose last test failed.
	StatusError = "error"
	// StatusUnknown is a connection that has never been tested.
	StatusUnknown = "unknown"

	// secretKeyPrefix namespaces keyring entries so a user can find them:
	// the full key is bastion.connection.<id>.
	secretKeyPrefix = "bastion.connection."

	// githubTokenKey is the secrets key whose environment fallback is
	// BASTION_GITHUB_TOKEN (secrets.EnvVarName), used when no token is stored
	// for the connection (§10).
	githubTokenKey = "github-token"
)

var (
	// ErrNotFound is returned when a connection id does not exist.
	ErrNotFound = errors.New("connections: connection not found")
	// ErrConflict is returned when (kind, name) is already taken.
	ErrConflict = errors.New("connections: name already in use")
	// ErrUnsupportedKind is returned for a kind v0.1 cannot manage.
	ErrUnsupportedKind = errors.New("connections: unsupported kind")
	// ErrInvalid is returned for a request the service refuses before SQL.
	ErrInvalid = errors.New("connections: invalid input")
	// ErrNoToken means the connection has no keyring entry and the environment
	// fallback is unset. Its message is safe to show to the user.
	ErrNoToken = errors.New("no token stored for this connection and " + secrets.EnvVarName(githubTokenKey) + " is not set")
	// ErrUpstream wraps a failed GitHub call. Hint extracts the user-facing
	// explanation.
	ErrUpstream = errors.New("connections: GitHub request failed")
)

// GitHubClient is the part of internal/connections/github the service uses.
// Tests inject a fake through WithGitHubFactory; no test calls GitHub.
type GitHubClient interface {
	User(ctx context.Context) (github.User, error)
	ListRepos(ctx context.Context) ([]github.Repo, error)
}

// GitHubFactory builds a client for a token. The token is only ever passed in
// memory.
type GitHubFactory func(token string) (GitHubClient, error)

// Connection is a connection row with its credential removed. ConfigJSON is
// decoded into the identity fields; SecretRef never leaves the service.
type Connection struct {
	ID            int64
	Kind          string
	Name          string
	Status        string
	Login         string
	Hint          string
	LastCheckedAt *time.Time
	CreatedAt     time.Time
}

// CreateInput is one POST /api/connections request.
type CreateInput struct {
	Kind  string
	Name  string
	Token string
}

// Repository is one repo returned by discovery.
type Repository struct {
	FullName      string
	DefaultBranch string
	Private       bool
	Archived      bool
	AlreadyAdded  bool
}

// Option customises a Service. Tests use WithGitHubFactory.
type Option func(*Service)

// WithGitHubFactory replaces the client factory. Tests pass a fake; serve
// passes one that carries the build version in the User-Agent.
func WithGitHubFactory(factory GitHubFactory) Option {
	return func(s *Service) {
		if factory != nil {
			s.newGitHub = factory
		}
	}
}

// Service implements connection management. It is safe for concurrent use:
// *sql.DB is, and the secrets store is expected to be.
type Service struct {
	db        *sql.DB
	secrets   secrets.Store
	newGitHub GitHubFactory
	now       func() time.Time
}

// NewService validates its dependencies and returns a Service.
func NewService(db *sql.DB, secretStore secrets.Store, opts ...Option) (*Service, error) {
	if db == nil {
		return nil, errors.New("connections: database is required")
	}
	if secretStore == nil {
		return nil, errors.New("connections: secret store is required")
	}
	s := &Service{
		db:        db,
		secrets:   secretStore,
		newGitHub: defaultGitHubFactory,
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// defaultGitHubFactory builds the real client. serve replaces it with one that
// knows the build version.
func defaultGitHubFactory(token string) (GitHubClient, error) {
	return github.New(github.Config{Token: token})
}

// SecretRef is the keyring key that holds connection id's token.
func SecretRef(id int64) string {
	return secretKeyPrefix + strconv.FormatInt(id, 10)
}

// List returns every connection, ordered by kind and name.
func (s *Service) List(ctx context.Context) ([]Connection, error) {
	rows, err := sqlcdb.New(s.db).ListConnections(ctx)
	if err != nil {
		return nil, fmt.Errorf("connections: list: %w", err)
	}
	out := make([]Connection, 0, len(rows))
	for _, row := range rows {
		conn, err := connectionFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, conn)
	}
	return out, nil
}

// Get returns one connection.
func (s *Service) Get(ctx context.Context, id int64) (Connection, error) {
	row, err := s.row(ctx, id)
	if err != nil {
		return Connection{}, err
	}
	return connectionFromRow(row)
}

// Create inserts the connection, stores the token in the keyring and tests it
// once. A failed test is not an API error: the connection is returned with
// status error and a hint. If the token cannot be stored, the row is removed
// again so a broken keyring never leaves an unusable connection behind.
func (s *Service) Create(ctx context.Context, in CreateInput) (Connection, error) {
	kind := strings.TrimSpace(in.Kind)
	if kind != KindGitHub {
		return Connection{}, fmt.Errorf("%w: %q (only %s is supported)", ErrUnsupportedKind, kind, KindGitHub)
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return Connection{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	token := strings.TrimSpace(in.Token)
	if token == "" {
		return Connection{}, fmt.Errorf("%w: token is required", ErrInvalid)
	}

	queries := sqlcdb.New(s.db)
	row, err := queries.CreateConnection(ctx, sqlcdb.CreateConnectionParams{Kind: kind, Name: name})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Connection{}, fmt.Errorf("%w: %s connection %q", ErrConflict, kind, name)
	case err != nil:
		return Connection{}, fmt.Errorf("connections: create %s %q: %w", kind, name, err)
	}

	key := SecretRef(row.ID)
	if err := s.secrets.Set(key, token); err != nil {
		_, cleanupErr := queries.DeleteConnection(ctx, row.ID)
		return Connection{}, errors.Join(
			fmt.Errorf("connections: store token for %s %q: %w", kind, name, err),
			cleanupErr,
		)
	}
	if _, err := queries.SetConnectionSecretRef(ctx, sqlcdb.SetConnectionSecretRefParams{
		SecretRef: sql.NullString{String: key, Valid: true},
		ID:        row.ID,
	}); err != nil {
		// Do not leave the token behind in the keyring without a row.
		_ = s.secrets.Delete(key)
		_, _ = queries.DeleteConnection(ctx, row.ID)
		return Connection{}, fmt.Errorf("connections: record keyring key for %s %q: %w", kind, name, err)
	}

	// Test immediately: the UI shows the identity (or the reason it failed)
	// instead of a connection that looks healthy until first use.
	return s.Test(ctx, row.ID)
}

// Test calls GitHub's GET /user with the connection's token and records the
// result: status, last_checked_at, the login on success, a hint on failure.
func (s *Service) Test(ctx context.Context, id int64) (Connection, error) {
	row, err := s.row(ctx, id)
	if err != nil {
		return Connection{}, err
	}
	if row.Kind != KindGitHub {
		return Connection{}, fmt.Errorf("%w: %q", ErrUnsupportedKind, row.Kind)
	}
	return s.check(ctx, row)
}

// check performs the test and persists its outcome.
func (s *Service) check(ctx context.Context, row sqlcdb.Connection) (Connection, error) {
	checkedAt := s.now().UTC().Format(time.RFC3339Nano)

	token, tokenErr := s.token(row)
	if tokenErr != nil {
		return s.record(ctx, row, StatusError, tokenErr.Error(), "", checkedAt)
	}
	client, err := s.newGitHub(token)
	if err != nil {
		return s.record(ctx, row, StatusError, "could not initialise the GitHub client", "", checkedAt)
	}
	user, err := client.User(ctx)
	if err != nil {
		return s.record(ctx, row, StatusError, hintFor(err), "", checkedAt)
	}
	return s.record(ctx, row, StatusOK, "", user.Login, checkedAt)
}

// record writes one test result. login replaces the stored identity; an empty
// hint clears the previous failure.
func (s *Service) record(ctx context.Context, row sqlcdb.Connection, status, hint, login, checkedAt string) (Connection, error) {
	config, err := decodeConfig(row.ConfigJSON)
	if err != nil {
		return Connection{}, err
	}
	if login != "" {
		config["login"] = login
	}
	if hint != "" {
		config["hint"] = hint
	} else {
		delete(config, "hint")
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return Connection{}, fmt.Errorf("connections: encode config for %d: %w", row.ID, err)
	}

	updated, err := sqlcdb.New(s.db).SetConnectionStatus(ctx, sqlcdb.SetConnectionStatusParams{
		Status:        status,
		LastCheckedAt: sql.NullString{String: checkedAt, Valid: true},
		ConfigJSON:    string(encoded),
		ID:            row.ID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Connection{}, ErrNotFound
	}
	if err != nil {
		return Connection{}, fmt.Errorf("connections: record test result for %d: %w", row.ID, err)
	}
	return connectionFromRow(updated)
}

// Delete removes the keyring entry first, then the row. If the keyring refuses
// the delete, the row is kept so the user can retry instead of orphaning a
// credential.
func (s *Service) Delete(ctx context.Context, id int64) error {
	row, err := s.row(ctx, id)
	if err != nil {
		return err
	}
	if row.SecretRef.Valid && row.SecretRef.String != "" {
		if err := s.secrets.Delete(row.SecretRef.String); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return fmt.Errorf("connections: delete stored token for %d: %w", id, err)
		}
	}
	deleted, err := sqlcdb.New(s.db).DeleteConnection(ctx, id)
	if err != nil {
		return fmt.Errorf("connections: delete %d: %w", id, err)
	}
	if deleted == 0 {
		return ErrNotFound
	}
	return nil
}

// Discover lists the repositories the connection can see and marks the ones
// that already exist as assets.
func (s *Service) Discover(ctx context.Context, id int64) ([]Repository, error) {
	row, err := s.row(ctx, id)
	if err != nil {
		return nil, err
	}
	if row.Kind != KindGitHub {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKind, row.Kind)
	}

	token, err := s.token(row)
	if err != nil {
		return nil, err
	}
	client, err := s.newGitHub(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUpstream, err)
	}
	repos, err := client.ListRepos(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUpstream, err)
	}

	refs, err := sqlcdb.New(s.db).ListRepoAssetRefs(ctx)
	if err != nil {
		return nil, fmt.Errorf("connections: list added repositories: %w", err)
	}
	added := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		added[ref] = struct{}{}
	}

	out := make([]Repository, 0, len(repos))
	for _, repo := range repos {
		_, exists := added[repo.FullName]
		out = append(out, Repository{
			FullName:      repo.FullName,
			DefaultBranch: repo.DefaultBranch,
			Private:       repo.Private,
			Archived:      repo.Archived,
			AlreadyAdded:  exists,
		})
	}
	return out, nil
}

// Hint returns a user-facing explanation for err, suitable for a problem
// detail. It never contains a token or a GitHub response body.
func Hint(err error) string {
	if errors.Is(err, ErrNoToken) {
		return ErrNoToken.Error()
	}
	return hintFor(err)
}

// row loads one connection row, turning sql.ErrNoRows into ErrNotFound.
func (s *Service) row(ctx context.Context, id int64) (sqlcdb.Connection, error) {
	row, err := sqlcdb.New(s.db).GetConnection(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return sqlcdb.Connection{}, ErrNotFound
	}
	if err != nil {
		return sqlcdb.Connection{}, fmt.Errorf("connections: get %d: %w", id, err)
	}
	return row, nil
}

// Token returns the credential a CLI command should use for GitHub: the first
// GitHub connection's keyring entry, else BASTION_GITHUB_TOKEN (§10). It is
// the same lookup Test and Discover perform, without a connection id.
func (s *Service) Token(ctx context.Context) (string, error) {
	rows, err := sqlcdb.New(s.db).ListConnections(ctx)
	if err != nil {
		return "", fmt.Errorf("connections: list: %w", err)
	}
	for _, row := range rows {
		if row.Kind != KindGitHub {
			continue
		}
		if token, err := s.token(row); err == nil {
			return token, nil
		}
	}
	return envGitHubToken()
}

// EnvToken returns BASTION_GITHUB_TOKEN when it is set. It backs --repo scans
// that run with --no-store and therefore never open the database (§10).
func EnvToken() (string, error) {
	return envGitHubToken()
}

// envGitHubToken reads the environment fallback for github-token.
func envGitHubToken() (string, error) {
	value, err := (secrets.EnvStore{}).Get(githubTokenKey)
	if err == nil && value != "" {
		return value, nil
	}
	return "", ErrNoToken
}

// token returns the connection's credential: the keyring entry named by
// secret_ref, else BASTION_GITHUB_TOKEN (§10).
func (s *Service) token(row sqlcdb.Connection) (string, error) {
	if row.SecretRef.Valid && row.SecretRef.String != "" {
		value, err := s.secrets.Get(row.SecretRef.String)
		if err == nil && value != "" {
			return value, nil
		}
	}
	return envGitHubToken()
}

// decodeConfig decodes the non-secret config object. Unknown keys are kept so
// later connection kinds can add their own fields without a migration.
func decodeConfig(raw string) (map[string]any, error) {
	config := make(map[string]any)
	if strings.TrimSpace(raw) == "" {
		return config, nil
	}
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return nil, fmt.Errorf("connections: decode config: %w", err)
	}
	return config, nil
}

// connectionFromRow converts a row into the API-facing shape. The credential
// and secret_ref are deliberately dropped here.
func connectionFromRow(row sqlcdb.Connection) (Connection, error) {
	createdAt, err := time.Parse(time.RFC3339, row.CreatedAt)
	if err != nil {
		return Connection{}, fmt.Errorf("connections: parse created_at of %d: %w", row.ID, err)
	}
	conn := Connection{
		ID:        row.ID,
		Kind:      row.Kind,
		Name:      row.Name,
		Status:    row.Status,
		CreatedAt: createdAt,
	}
	if row.LastCheckedAt.Valid && row.LastCheckedAt.String != "" {
		checkedAt, err := time.Parse(time.RFC3339, row.LastCheckedAt.String)
		if err != nil {
			return Connection{}, fmt.Errorf("connections: parse last_checked_at of %d: %w", row.ID, err)
		}
		conn.LastCheckedAt = &checkedAt
	}

	config, err := decodeConfig(row.ConfigJSON)
	if err != nil {
		return Connection{}, err
	}
	conn.Login = configString(config, "login")
	conn.Hint = configString(config, "hint")
	return conn, nil
}

// configString reads a string member, treating absent and non-string values as
// empty.
func configString(config map[string]any, key string) string {
	value, ok := config[key].(string)
	if !ok {
		return ""
	}
	return value
}

// hintFor maps a GitHub client error to the user-facing hint. Raw error text
// is never shown: it may carry a request URL (ADR-005).
func hintFor(err error) string {
	var ghErr *github.Error
	if errors.As(err, &ghErr) {
		if ghErr.Hint != "" {
			return ghErr.Hint
		}
		if ghErr.StatusCode != 0 {
			return "GitHub returned HTTP " + strconv.Itoa(ghErr.StatusCode)
		}
		return "could not reach GitHub"
	}
	if errors.Is(err, context.Canceled) {
		return "the request to GitHub was canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "the request to GitHub timed out"
	}
	return "could not reach GitHub"
}
