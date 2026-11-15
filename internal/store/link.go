package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Link sources (asset_links.source). A manual link is a user's decision and is
// never overwritten by a scan; an oci link comes from the image's
// org.opencontainers.image.source label.
const (
	LinkSourceManual = "manual"
	LinkSourceOCI    = "oci"
)

// ImageSource is what an image's config says about the repository it was built
// from, through the OCI labels org.opencontainers.image.source and .revision.
// The scan pipeline fills it from the scanner's normalized output; an empty URL
// means the image declared no source and is never auto-linked.
type ImageSource struct {
	URL      string
	Revision string
}

// AssetLink is one repository <-> image link with both ends' display fields.
type AssetLink struct {
	ID               int64
	RepoAssetID      int64
	ImageAssetID     int64
	Source           string
	Revision         string
	CreatedAt        time.Time
	RepoRef          string
	RepoDisplayName  string
	ImageRef         string
	ImageDisplayName string
}

// ListAssetLinks reads every link, so a caller can decorate a whole asset list
// with one query instead of one per row.
func ListAssetLinks(ctx context.Context, db *sql.DB) ([]AssetLink, error) {
	if db == nil {
		return nil, errors.New("store: list asset links: database is required")
	}
	rows, err := sqlcdb.New(db).ListAssetLinks(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list asset links: %w", err)
	}
	out := make([]AssetLink, 0, len(rows))
	for _, row := range rows {
		link := AssetLink{
			ID:               row.ID,
			RepoAssetID:      row.RepoAssetID,
			ImageAssetID:     row.ImageAssetID,
			Source:           row.Source,
			Revision:         row.Revision.String,
			RepoRef:          row.RepoRef,
			RepoDisplayName:  row.RepoDisplayName,
			ImageRef:         row.ImageRef,
			ImageDisplayName: row.ImageDisplayName,
		}
		if created, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
			link.CreatedAt = created
		}
		out = append(out, link)
	}
	return out, nil
}

// SetManualLink links an image to a repository by hand. It replaces whatever
// link the image had, including one the OCI labels created, and marks the new
// one manual so a later scan leaves it alone. Kind validation belongs to the
// caller: the database only knows ids.
func SetManualLink(ctx context.Context, db *sql.DB, imageAssetID, repoAssetID int64) error {
	if db == nil {
		return errors.New("store: set asset link: database is required")
	}
	_, err := sqlcdb.New(db).SetManualAssetLink(ctx, sqlcdb.SetManualAssetLinkParams{
		RepoAssetID:  repoAssetID,
		ImageAssetID: imageAssetID,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("store: link image %d to repo %d: %w", imageAssetID, repoAssetID, err)
	}
	return nil
}

// ClearLink removes an image's link, whichever source made it. An unlinked
// image is not an error: the caller asked for a state, not for a row.
func ClearLink(ctx context.Context, db *sql.DB, imageAssetID int64) error {
	if db == nil {
		return errors.New("store: clear asset link: database is required")
	}
	if err := sqlcdb.New(db).ClearAssetLink(ctx, imageAssetID); err != nil {
		return fmt.Errorf("store: clear link of image %d: %w", imageAssetID, err)
	}
	return nil
}

// linkImageFromSource links an image to the repository its OCI source label
// names, inside the caller's transaction. A manual link is never replaced, and
// a source that names no tracked repository (or no GitHub repository at all)
// leaves the image unlinked: auto-linking guesses nothing. linked reports
// whether this call wrote a row.
func linkImageFromSource(ctx context.Context, queries *sqlcdb.Queries, imageAssetID int64, src ImageSource) (linked bool, err error) {
	ref, ok := RepoRefFromSourceURL(src.URL)
	if !ok {
		return false, nil
	}
	repo, err := queries.GetRepoAssetByRefFold(ctx, ref)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: link image %d: look up repo %q: %w", imageAssetID, ref, err)
	}

	_, err = queries.UpsertOCIAssetLink(ctx, sqlcdb.UpsertOCIAssetLinkParams{
		RepoAssetID:  repo.ID,
		ImageAssetID: imageAssetID,
		Revision:     nullString(src.Revision),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if errors.Is(err, sql.ErrNoRows) {
		// The image already has a manual link, which always wins.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: link image %d to repo %q: %w", imageAssetID, ref, err)
	}
	return true, nil
}

// RepoRefFromSourceURL turns an org.opencontainers.image.source label into the
// owner/repo ref a repo asset uses. Only the GitHub forms bastion can map
// exactly are accepted — https://github.com/owner/repo(.git) and
// git@github.com:owner/repo(.git) — so an unrelated URL is left unlinked
// rather than guessed at.
func RepoRefFromSourceURL(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", false
	}

	var path string
	if rest, isSCP := strings.CutPrefix(value, "git@"); isSCP {
		host, after, ok := strings.Cut(rest, ":")
		if !ok || !strings.EqualFold(host, "github.com") {
			return "", false
		}
		path = after
	} else {
		parsed, err := url.Parse(value)
		if err != nil {
			return "", false
		}
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https":
		default:
			return "", false
		}
		if !strings.EqualFold(parsed.Hostname(), "github.com") {
			return "", false
		}
		path = parsed.Path
	}

	// A label may carry a trailing slash or the clone suffix, in either order.
	path = strings.TrimSuffix(strings.TrimSuffix(strings.Trim(path, "/"), ".git"), "/")
	owner, name, ok := strings.Cut(path, "/")
	if !ok || !validGitHubSegment(owner) || !validGitHubSegment(name) {
		return "", false
	}
	return owner + "/" + name, true
}

// validGitHubSegment reports whether s can be one segment of a GitHub
// owner/repo pair: letters, digits, ".", "_" and "-", at most 100 characters.
func validGitHubSegment(s string) bool {
	if s == "" || len(s) > 100 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// imageAssetKind is the assets.kind an auto-link needs; a scan of anything else
// never has OCI labels to read.
const imageAssetKind = string(findings.AssetKindImage)
