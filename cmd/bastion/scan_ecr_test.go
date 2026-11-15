package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/aws"
	"github.com/ozerozdas/bastion/internal/connections"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/sources"
	"github.com/ozerozdas/bastion/internal/store"
)

const (
	testECRRegistry = "957032250673.dkr.ecr.eu-central-1.amazonaws.com"
	testECRDigest   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fakeAWSConnection is the AWS client of the saved connection: the test and the
// registry login answer from memory, so no test reaches AWS.
type fakeAWSConnection struct{}

func (fakeAWSConnection) Identity(context.Context) (aws.Identity, error) {
	return aws.Identity{Account: "957032250673", ARN: "arn:aws:iam::957032250673:user/dev"}, nil
}

func (fakeAWSConnection) Repositories(context.Context) ([]aws.Repository, error) { return nil, nil }

func (fakeAWSConnection) AuthorizationToken(context.Context) (aws.Credentials, error) {
	return aws.Credentials{Username: "AWS", Password: "ecr-token"}, nil
}

// fakeECRClient pins a tag to its digest without reaching AWS.
type fakeECRClient struct {
	tag        string
	digest     string
	repository string
	calls      int
}

func (f *fakeECRClient) Image(_ context.Context, repository, tag, _ string) (aws.Image, error) {
	f.calls++
	f.repository = repository
	if tag != "" && tag != f.tag {
		return aws.Image{}, errors.New("image not found")
	}
	return aws.Image{Tag: f.tag, Digest: f.digest}, nil
}

// recordingImageSource records the target an image scan fetched, so a test can
// assert the registry login and the pinned ref reached the source.
type recordingImageSource struct {
	target sources.Target
}

func (*recordingImageSource) Kind() sources.TargetKind { return sources.KindImage }

func (s *recordingImageSource) Fetch(_ context.Context, t sources.Target) (*sources.Workspace, error) {
	s.target = t
	return &sources.Workspace{Image: t.Ref, RegistryAuth: t.RegistryAuth}, nil
}

// ecrScanDeps wires an ECR scan: a real SQLite database holding one tested aws
// connection, a fake ECR client for the digest and a fake image source.
func ecrScanDeps(t *testing.T) (scanDeps, *sql.DB, *fakeECRClient, *recordingImageSource) {
	t.Helper()
	deps := testScanDeps(t, t.TempDir())

	db, err := store.Open(t.Context(), deps.paths.DBPath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	service, err := connections.NewService(db, secrets.NewMemoryStore(),
		connections.WithAWSFactory(func(string, string) (connections.AWSClient, error) {
			return fakeAWSConnection{}, nil
		}),
	)
	if err != nil {
		t.Fatalf("connections.NewService: %v", err)
	}
	if _, err := service.Create(t.Context(), connections.CreateInput{
		Kind: connections.KindAWS, Name: "prod", Profile: "texttonext", Region: "eu-central-1",
	}); err != nil {
		t.Fatalf("create aws connection: %v", err)
	}

	ecr := &fakeECRClient{tag: "latest", digest: testECRDigest}
	src := &recordingImageSource{}
	deps.newTokens = func(*sql.DB) (*connections.Service, error) { return service, nil }
	deps.newECR = func(string, string) (ecrClient, error) { return ecr, nil }
	deps.newImageSource = func() sources.Source { return src }
	return deps, db, ecr, src
}

// runECRScan runs one --image scan and decodes its JSON document.
func runECRScan(t *testing.T, deps scanDeps, image string, noStore bool) scanOutput {
	t.Helper()
	var out bytes.Buffer
	opts := &scanOptions{image: image, format: scanFormatJSON, noStore: noStore}
	if err := runScan(t.Context(), &out, opts, deps); err != nil {
		t.Fatalf("scan --image %s (no-store=%v): %v\n%s", image, noStore, err, out.String())
	}
	var doc scanOutput
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode scan output: %v\n%s", err, out.String())
	}
	return doc
}

// TestRunScanECRStoresAsset: an ECR tag is pinned to its digest, stored as the
// UI stores it and scanned with the connection's login. A repeat scan reuses
// the same asset.
func TestRunScanECRStoresAsset(t *testing.T) {
	deps, db, ecr, src := ecrScanDeps(t)
	image := testECRRegistry + "/t2n-worker:latest"
	pinned := testECRRegistry + "/t2n-worker@" + testECRDigest

	first := runECRScan(t, deps, image, false)
	if first.Asset.Ref != pinned || first.Asset.DisplayName != "t2n-worker:latest" {
		t.Fatalf("asset = %+v, want t2n-worker:latest pinned to %s", first.Asset, testECRDigest)
	}
	if first.Asset.ID == 0 || first.ScanID == 0 {
		t.Fatalf("asset id = %d, scan id = %d, want both set", first.Asset.ID, first.ScanID)
	}
	if ecr.calls != 1 || ecr.repository != "t2n-worker" {
		t.Fatalf("ECR calls = %d for %q, want 1 for t2n-worker", ecr.calls, ecr.repository)
	}
	if src.target.Ref != pinned || src.target.ConnectionID == 0 {
		t.Fatalf("scan target = %+v, want the pinned ref and a connection", src.target)
	}
	if src.target.RegistryAuth == nil || src.target.RegistryAuth.Username != "AWS" {
		t.Fatalf("scan target login = %+v, want the connection's login", src.target.RegistryAuth)
	}

	// The stored asset carries the connection and the tag/digest metadata, so
	// the UI shows the same image.
	var connectionID sql.NullInt64
	var metadata string
	if err := db.QueryRowContext(t.Context(),
		`SELECT connection_id, metadata_json FROM assets WHERE id = ?`, first.Asset.ID).
		Scan(&connectionID, &metadata); err != nil {
		t.Fatalf("read asset: %v", err)
	}
	if !connectionID.Valid {
		t.Fatal("asset connection_id is NULL, want the aws connection")
	}
	var stored map[string]string
	if err := json.Unmarshal([]byte(metadata), &stored); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if stored["registry"] != testECRRegistry || stored["repository"] != "t2n-worker" ||
		stored["tag"] != "latest" || stored["digest"] != testECRDigest {
		t.Fatalf("metadata = %v, want the ECR tag pinned to its digest", stored)
	}

	// The scan records the digest it resolved.
	var targetRef sql.NullString
	if err := db.QueryRowContext(t.Context(),
		`SELECT target_ref FROM scans WHERE id = ?`, first.ScanID).Scan(&targetRef); err != nil {
		t.Fatalf("read scan: %v", err)
	}
	if targetRef.String != testECRDigest {
		t.Fatalf("scan target_ref = %q, want %q", targetRef.String, testECRDigest)
	}

	second := runECRScan(t, deps, image, false)
	if second.Asset.ID != first.Asset.ID {
		t.Fatalf("second scan asset = %d, want the reused %d", second.Asset.ID, first.Asset.ID)
	}
	if second.ScanID == first.ScanID {
		t.Fatalf("second scan id = %d, want a new scan", second.ScanID)
	}
}

// TestRunScanECRNoStore: --no-store still uses the saved connection for the
// login and the digest, but writes no asset and no scan.
func TestRunScanECRNoStore(t *testing.T) {
	deps, db, _, src := ecrScanDeps(t)
	image := testECRRegistry + "/t2n-worker:latest"
	pinned := testECRRegistry + "/t2n-worker@" + testECRDigest

	doc := runECRScan(t, deps, image, true)
	if doc.Asset.ID != 0 || doc.ScanID != 0 {
		t.Fatalf("asset id = %d, scan id = %d, want the --no-store zero ids", doc.Asset.ID, doc.ScanID)
	}
	if doc.Asset.Ref != pinned {
		t.Fatalf("asset ref = %q, want %q", doc.Asset.Ref, pinned)
	}
	if src.target.Ref != pinned || src.target.RegistryAuth == nil {
		t.Fatalf("scan target = %+v, want the pinned ref with a login", src.target)
	}

	for _, query := range []string{`SELECT count(*) FROM assets`, `SELECT count(*) FROM scans`} {
		var count int
		if err := db.QueryRowContext(t.Context(), query).Scan(&count); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		if count != 0 {
			t.Fatalf("%s = %d, want 0", query, count)
		}
	}
}

// TestRunScanECRNeedsAConnection: without a saved aws connection the CLI says
// how to add one instead of falling back to the local daemon.
func TestRunScanECRNeedsAConnection(t *testing.T) {
	deps := testScanDeps(t, t.TempDir())
	db, err := store.Open(t.Context(), deps.paths.DBPath())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service, err := connections.NewService(db, secrets.NewMemoryStore())
	if err != nil {
		t.Fatalf("connections.NewService: %v", err)
	}
	deps.newTokens = func(*sql.DB) (*connections.Service, error) { return service, nil }
	deps.newECR = func(string, string) (ecrClient, error) { return &fakeECRClient{}, nil }

	var out bytes.Buffer
	err = runScan(t.Context(), &out, &scanOptions{
		image: "123456789012.dkr.ecr.eu-west-1.amazonaws.com/app:1", format: scanFormatJSON,
	}, deps)
	if err == nil {
		t.Fatalf("scan without an aws connection succeeded:\n%s", out.String())
	}
	if want := "no AWS connection for 123456789012.dkr.ecr.eu-west-1.amazonaws.com"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

// TestSplitECRRef: only an ECR registry host takes the connection path; every
// other reference stays a local Docker image.
func TestSplitECRRef(t *testing.T) {
	tests := []struct {
		value string
		want  ecrRef
	}{
		{value: "nginx:latest"},
		{value: "ghcr.io/acme/app:1.0"},
		{value: "localhost:5000/app:1"},
		{value: "957032250673.dkr.ecr.eu-central-1.amazonaws.com/t2n-worker:latest", want: ecrRef{
			registry: testECRRegistry, repository: "t2n-worker", tag: "latest", ok: true,
		}},
		{value: testECRRegistry + "/team/t2n-worker", want: ecrRef{
			registry: testECRRegistry, repository: "team/t2n-worker", ok: true,
		}},
		{value: testECRRegistry + "/t2n-worker@" + testECRDigest, want: ecrRef{
			registry: testECRRegistry, repository: "t2n-worker", digest: testECRDigest, ok: true,
		}},
		{value: testECRRegistry + "/t2n-worker:v1@" + testECRDigest, want: ecrRef{
			registry: testECRRegistry, repository: "t2n-worker", tag: "v1", digest: testECRDigest, ok: true,
		}},
	}
	for _, test := range tests {
		if got := splitECRRef(test.value); got != test.want {
			t.Errorf("splitECRRef(%q) = %+v, want %+v", test.value, got, test.want)
		}
	}
}
