package store_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// linkTestAsset creates one asset row for the link tests.
func linkTestAsset(t *testing.T, db *sql.DB, kind, ref string) sqlcdb.Asset {
	t.Helper()

	asset, err := sqlcdb.New(db).CreateAsset(context.Background(), sqlcdb.CreateAssetParams{
		Kind:         kind,
		DisplayName:  ref,
		Ref:          ref,
		MetadataJSON: "{}",
		CreatedAt:    "2026-11-15T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("CreateAsset(%s %q): %v", kind, ref, err)
	}
	return asset
}

// saveImageScan persists a succeeded scan of imageID that carries src, the way
// the job pipeline does after scanning an image.
func saveImageScan(t *testing.T, db *sql.DB, imageID int64, src store.ImageSource) {
	t.Helper()

	ctx := context.Background()
	scan, err := sqlcdb.New(db).CreateScan(ctx, sqlcdb.CreateScanParams{
		AssetID: imageID,
		Status:  "queued",
		Trigger: "cli",
	})
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := store.SaveScanResult(ctx, db, scan.ID, store.ScanResult{
		Status:      store.ScanStatusSucceeded,
		FinishedAt:  time.Date(2026, 11, 15, 10, 5, 0, 0, time.UTC),
		ImageSource: src,
	}); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}
}

// onlyLink returns the single link in the database.
func onlyLink(t *testing.T, db *sql.DB) store.AssetLink {
	t.Helper()

	links, err := store.ListAssetLinks(context.Background(), db)
	if err != nil {
		t.Fatalf("ListAssetLinks: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("links = %d, want 1: %+v", len(links), links)
	}
	return links[0]
}

func TestRepoRefFromSourceURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "https", in: "https://github.com/acme/api", want: "acme/api", ok: true},
		{name: "https git suffix", in: "https://github.com/acme/api.git", want: "acme/api", ok: true},
		{name: "https trailing slash", in: "https://github.com/acme/api/", want: "acme/api", ok: true},
		{name: "git suffix and slash", in: "https://github.com/acme/api.git/", want: "acme/api", ok: true},
		{name: "http", in: "http://github.com/acme/api", want: "acme/api", ok: true},
		{name: "scp", in: "git@github.com:acme/api.git", want: "acme/api", ok: true},
		{name: "scp without suffix", in: "git@github.com:acme/api", want: "acme/api", ok: true},
		{name: "host case", in: "https://GitHub.com/acme/api", want: "acme/api", ok: true},
		{name: "trimmed", in: "  https://github.com/acme/api  ", want: "acme/api", ok: true},
		{name: "empty", in: "", ok: false},
		{name: "other host", in: "https://gitlab.com/acme/api", ok: false},
		{name: "scp other host", in: "git@gitlab.com:acme/api.git", ok: false},
		{name: "no owner", in: "https://github.com/api", ok: false},
		{name: "nested path", in: "https://github.com/acme/api/tree/main", ok: false},
		{name: "not a url", in: "acme/api", ok: false},
		{name: "space", in: "https://github.com/acme/a pi", ok: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, ok := store.RepoRefFromSourceURL(test.in)
			if ok != test.ok {
				t.Fatalf("RepoRefFromSourceURL(%q) ok = %v, want %v", test.in, ok, test.ok)
			}
			if got != test.want {
				t.Fatalf("RepoRefFromSourceURL(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestScanResultAutoLinksImageFromLabels(t *testing.T) {
	db, _ := openTestDB(t)

	repo := linkTestAsset(t, db, "repo", "acme/api")
	image := linkTestAsset(t, db, "image", "acme/api:1.2.3")

	saveImageScan(t, db, image.ID, store.ImageSource{
		URL:      "https://github.com/acme/api.git",
		Revision: "9f2c1ab",
	})

	link := onlyLink(t, db)
	if link.RepoAssetID != repo.ID || link.ImageAssetID != image.ID {
		t.Fatalf("link = repo %d image %d, want repo %d image %d", link.RepoAssetID, link.ImageAssetID, repo.ID, image.ID)
	}
	if link.Source != store.LinkSourceOCI {
		t.Fatalf("source = %q, want %q", link.Source, store.LinkSourceOCI)
	}
	if link.Revision != "9f2c1ab" {
		t.Fatalf("revision = %q, want %q", link.Revision, "9f2c1ab")
	}
}

func TestScanResultMatchesRepoRefWithoutCase(t *testing.T) {
	db, _ := openTestDB(t)

	repo := linkTestAsset(t, db, "repo", "Acme/API")
	image := linkTestAsset(t, db, "image", "acme/api:1")

	saveImageScan(t, db, image.ID, store.ImageSource{URL: "https://github.com/acme/api"})

	link := onlyLink(t, db)
	if link.RepoAssetID != repo.ID {
		t.Fatalf("repo asset = %d, want %d", link.RepoAssetID, repo.ID)
	}
	if link.RepoRef != "Acme/API" {
		t.Fatalf("repo ref = %q, want %q", link.RepoRef, "Acme/API")
	}
}

func TestManualLinkIsNeverOverwrittenByScan(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()

	manualRepo := linkTestAsset(t, db, "repo", "acme/hand-picked")
	labelRepo := linkTestAsset(t, db, "repo", "acme/api")
	image := linkTestAsset(t, db, "image", "acme/api:1")

	if err := store.SetManualLink(ctx, db, image.ID, manualRepo.ID); err != nil {
		t.Fatalf("SetManualLink: %v", err)
	}
	saveImageScan(t, db, image.ID, store.ImageSource{
		URL:      "https://github.com/acme/api",
		Revision: "deadbee",
	})

	link := onlyLink(t, db)
	if link.RepoAssetID != manualRepo.ID {
		t.Fatalf("repo asset = %d, want the manual %d (label repo was %d)", link.RepoAssetID, manualRepo.ID, labelRepo.ID)
	}
	if link.Source != store.LinkSourceManual {
		t.Fatalf("source = %q, want %q", link.Source, store.LinkSourceManual)
	}
	if link.Revision != "" {
		t.Fatalf("revision = %q, want none for a manual link", link.Revision)
	}
}

func TestManualLinkReplacesLabelLink(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()

	labelRepo := linkTestAsset(t, db, "repo", "acme/api")
	manualRepo := linkTestAsset(t, db, "repo", "acme/mirror")
	image := linkTestAsset(t, db, "image", "acme/api:1")

	saveImageScan(t, db, image.ID, store.ImageSource{URL: "https://github.com/acme/api", Revision: "abc1234"})
	if link := onlyLink(t, db); link.RepoAssetID != labelRepo.ID {
		t.Fatalf("label link repo = %d, want %d", link.RepoAssetID, labelRepo.ID)
	}

	if err := store.SetManualLink(ctx, db, image.ID, manualRepo.ID); err != nil {
		t.Fatalf("SetManualLink: %v", err)
	}
	link := onlyLink(t, db)
	if link.RepoAssetID != manualRepo.ID || link.Source != store.LinkSourceManual || link.Revision != "" {
		t.Fatalf("link after manual set = %+v, want repo %d manual without revision", link, manualRepo.ID)
	}
}

func TestScanResultLeavesUnmatchedSourceUnlinked(t *testing.T) {
	db, _ := openTestDB(t)
	image := linkTestAsset(t, db, "image", "acme/api:1")

	saveImageScan(t, db, image.ID, store.ImageSource{URL: "https://github.com/other/repo"})

	links, err := store.ListAssetLinks(context.Background(), db)
	if err != nil {
		t.Fatalf("ListAssetLinks: %v", err)
	}
	if len(links) != 0 {
		t.Fatalf("links = %+v, want none for an untracked repository", links)
	}
}

func TestClearLink(t *testing.T) {
	db, _ := openTestDB(t)
	ctx := context.Background()

	repo := linkTestAsset(t, db, "repo", "acme/api")
	image := linkTestAsset(t, db, "image", "acme/api:1")

	if err := store.SetManualLink(ctx, db, image.ID, repo.ID); err != nil {
		t.Fatalf("SetManualLink: %v", err)
	}
	if err := store.ClearLink(ctx, db, image.ID); err != nil {
		t.Fatalf("ClearLink: %v", err)
	}
	links, err := store.ListAssetLinks(ctx, db)
	if err != nil {
		t.Fatalf("ListAssetLinks: %v", err)
	}
	if len(links) != 0 {
		t.Fatalf("links = %+v, want none after clearing", links)
	}

	// Clearing an unlinked image is a state, not a missing row.
	if err := store.ClearLink(ctx, db, image.ID); err != nil {
		t.Fatalf("ClearLink on unlinked image: %v", err)
	}
}
