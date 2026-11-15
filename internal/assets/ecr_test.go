package assets

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/store"
)

// fakeTokenSource answers credential lookups and reports the connection kind.
type fakeTokenSource struct {
	kind string
}

func (fakeTokenSource) Token(context.Context) (string, error) { return "", nil }

func (fakeTokenSource) ConnectionToken(context.Context, int64) (string, error) {
	return "", nil
}

func (f fakeTokenSource) ConnectionKind(context.Context, int64) (string, error) {
	return f.kind, nil
}

func (fakeTokenSource) AWSRegistry(context.Context, int64) (string, error) {
	return ecrRegistry, nil
}

const (
	ecrRegistry = "143709573002.dkr.ecr.eu-central-1.amazonaws.com"
	ecrDigest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ecrRef      = ecrRegistry + "/t2n-api@" + ecrDigest
)

func newECRAssetService(t *testing.T, kind string) *Service {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "bastion.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	service, err := NewService(db, WithGitHub(nil, fakeTokenSource{kind: kind}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service
}

// TestCreateECRImageStoresPinnedMetadata: an ECR asset is named by tag and
// pinned by digest, and its connection is recorded for the scan.
func TestCreateECRImageStoresPinnedMetadata(t *testing.T) {
	service := newECRAssetService(t, "aws")
	connectionID := insertAWSConnection(t, service)

	asset, err := service.Create(t.Context(), CreateInput{
		Kind: "image", Ref: ecrRef, Tag: "v1.2.3", ConnectionID: connectionID,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if asset.DisplayName != "t2n-api:v1.2.3" {
		t.Errorf("display_name = %q, want t2n-api:v1.2.3", asset.DisplayName)
	}
	if asset.Ref != ecrRef {
		t.Errorf("ref = %q, want %q", asset.Ref, ecrRef)
	}
	if asset.ConnectionID == nil || *asset.ConnectionID != connectionID {
		t.Errorf("connection_id = %v, want %d", asset.ConnectionID, connectionID)
	}
	if asset.ECRRegistry != ecrRegistry {
		t.Errorf("ecr_registry = %q, want %q", asset.ECRRegistry, ecrRegistry)
	}

	var metadata string
	if err := service.db.QueryRowContext(t.Context(),
		`SELECT metadata_json FROM assets WHERE id = ?`, asset.ID).Scan(&metadata); err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	var stored map[string]string
	if err := json.Unmarshal([]byte(metadata), &stored); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	want := map[string]string{
		"registry":   ecrRegistry,
		"repository": "t2n-api",
		"tag":        "v1.2.3",
		"digest":     ecrDigest,
	}
	for key, value := range want {
		if stored[key] != value {
			t.Errorf("metadata[%q] = %q, want %q", key, stored[key], value)
		}
	}
}

// TestCreateECRImageRejectsBadInput keeps the asset contract strict: a digest
// is required, a tag is required, and the connection must be AWS.
func TestCreateECRImageRejectsBadInput(t *testing.T) {
	service := newECRAssetService(t, "aws")
	connectionID := insertAWSConnection(t, service)
	unpinned := ecrRegistry + "/t2n-api:latest"

	for name, in := range map[string]CreateInput{
		"unpinned ref": {Kind: "image", Ref: unpinned, Tag: "latest", ConnectionID: connectionID},
		"no tag":       {Kind: "image", Ref: ecrRef, ConnectionID: connectionID},
		"bad tag":      {Kind: "image", Ref: ecrRef, Tag: "not a tag", ConnectionID: connectionID},
	} {
		if _, err := service.Create(t.Context(), in); err == nil {
			t.Errorf("%s: Create succeeded, want an error", name)
		}
	}

	github := newECRAssetService(t, "github")
	githubConnectionID := insertAWSConnection(t, github)
	if _, err := github.Create(t.Context(), CreateInput{
		Kind: "image", Ref: ecrRef, Tag: "latest", ConnectionID: githubConnectionID,
	}); err == nil || !strings.Contains(err.Error(), "not an AWS connection") {
		t.Errorf("github connection error = %v, want a not-an-AWS-connection error", err)
	}
}

// TestCreateECRImageRejectsForeignRegistry: an image must come from the
// connection's own registry host, not from a ref that merely looks like ECR.
func TestCreateECRImageRejectsForeignRegistry(t *testing.T) {
	service := newECRAssetService(t, "aws")
	connectionID := insertAWSConnection(t, service)
	evil := "evil.example.com/t2n-api@" + ecrDigest

	if _, err := service.Create(t.Context(), CreateInput{
		Kind: "image", Ref: evil, Tag: "latest", ConnectionID: connectionID,
	}); err == nil || !strings.Contains(err.Error(), "does not belong to connection") {
		t.Errorf("Create error = %v, want a foreign-registry error", err)
	}
}

// insertAWSConnection adds the connection row an ECR asset's foreign key needs.
func insertAWSConnection(t *testing.T, service *Service) int64 {
	t.Helper()
	result, err := service.db.ExecContext(t.Context(),
		`INSERT INTO connections (kind, name, config_json) VALUES ('aws', 'test', '{}')`)
	if err != nil {
		t.Fatalf("insert connection: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("connection id: %v", err)
	}
	return id
}

// TestCreateECRImageRevivesArchived: re-adding a removed ECR image revives the
// same row, so its id and finding history survive.
func TestCreateECRImageRevivesArchived(t *testing.T) {
	service := newECRAssetService(t, "aws")
	connectionID := insertAWSConnection(t, service)
	in := CreateInput{Kind: "image", Ref: ecrRef, Tag: "v1.2.3", ConnectionID: connectionID}

	first, err := service.Create(t.Context(), in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := service.Archive(t.Context(), first.ID); err != nil {
		t.Fatalf("Archive: %v", err)
	}

	revived, err := service.Create(t.Context(), in)
	if err != nil {
		t.Fatalf("Create after archive: %v", err)
	}
	if revived.ID != first.ID {
		t.Errorf("revived id = %d, want the archived row %d", revived.ID, first.ID)
	}

	var archived sql.NullString
	if err := service.db.QueryRowContext(t.Context(),
		`SELECT archived_at FROM assets WHERE id = ?`, first.ID).Scan(&archived); err != nil {
		t.Fatalf("read archived_at: %v", err)
	}
	if archived.Valid {
		t.Errorf("archived_at = %q after re-adding, want NULL", archived.String)
	}
}
