package connections

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/aws"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/store"
)

// fakeECR is an AWS client whose ECR calls answer from memory. No test reaches
// AWS.
type fakeECR struct {
	repositories []aws.Repository
	credentials  aws.Credentials
	profile      string
	region       string
	tokenCalls   int
}

func (*fakeECR) Identity(context.Context) (aws.Identity, error) {
	return aws.Identity{Account: "143709573002", ARN: "arn:aws:iam::143709573002:user/test"}, nil
}

func (f *fakeECR) Repositories(context.Context) ([]aws.Repository, error) {
	return f.repositories, nil
}

func (f *fakeECR) AuthorizationToken(context.Context) (aws.Credentials, error) {
	f.tokenCalls++
	return f.credentials, nil
}

const (
	testRegistry = "143709573002.dkr.ecr.eu-central-1.amazonaws.com"
	testDigest1  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testDigest2  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func newECRTestService(t *testing.T) (*Service, *fakeECR) {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "bastion.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	fake := &fakeECR{
		repositories: []aws.Repository{
			{
				Name: "t2n-api",
				URI:  testRegistry + "/t2n-api",
				Tags: []aws.Tag{
					{Name: "latest", Digest: testDigest1, PushedAt: time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)},
					{Name: "v1.2.3", Digest: testDigest2, PushedAt: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)},
					{Name: "stable", Digest: testDigest2, PushedAt: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)},
				},
			},
			{Name: "t2n-worker", URI: testRegistry + "/t2n-worker"},
		},
		credentials: aws.Credentials{Username: "AWS", Password: "secret-token"},
	}
	service, err := NewService(db, secrets.NewMemoryStore(),
		WithAWSFactory(func(profile, region string) (AWSClient, error) {
			fake.profile, fake.region = profile, region
			return fake, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, fake
}

// TestDiscoverECRListsRecentTags: an aws connection discovers repositories and
// tags, and a digest already tracked is flagged.
func TestDiscoverECRListsRecentTags(t *testing.T) {
	service, fake := newECRTestService(t)

	conn, err := service.Create(t.Context(), CreateInput{
		Kind: KindAWS, Name: "prod", Profile: "default", Region: "eu-central-1",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if fake.profile != "default" || fake.region != "eu-central-1" {
		t.Fatalf("client built for %q/%q, want default/eu-central-1", fake.profile, fake.region)
	}

	addedRef := testRegistry + "/t2n-api@" + testDigest1
	if _, err := service.db.ExecContext(t.Context(), `
		INSERT INTO assets (kind, connection_id, display_name, ref)
		VALUES ('image', ?, 't2n-api:latest', ?)`, conn.ID, addedRef); err != nil {
		t.Fatalf("insert asset: %v", err)
	}

	discovery, err := service.Discover(t.Context(), conn.ID)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(discovery.Repositories) != 0 {
		t.Errorf("github repositories = %d, want 0", len(discovery.Repositories))
	}
	if len(discovery.ECRRepositories) != 2 {
		t.Fatalf("ECR repositories = %d, want 2", len(discovery.ECRRepositories))
	}
	api := discovery.ECRRepositories[0]
	if api.Name != "t2n-api" || api.URI != testRegistry+"/t2n-api" {
		t.Errorf("repository = %+v", api)
	}
	if len(api.Tags) != 2 {
		t.Fatalf("tags = %d, want 2", len(api.Tags))
	}
	if len(api.Tags[0].Tags) != 1 || api.Tags[0].Tags[0] != "latest" || api.Tags[0].Ref != addedRef {
		t.Errorf("newest tag = %+v, want latest pinned to %s", api.Tags[0], addedRef)
	}
	if !api.Tags[0].AlreadyAdded {
		t.Error("latest.already_added = false, want true")
	}
	if len(api.Tags[1].Tags) != 2 || api.Tags[1].Tags[0] != "v1.2.3" || api.Tags[1].Tags[1] != "stable" {
		t.Errorf("grouped tags = %v, want [v1.2.3 stable]", api.Tags[1].Tags)
	}
	if api.Tags[1].AlreadyAdded {
		t.Error("v1.2.3.already_added = true, want false")
	}
	if api.Tags[0].PushedAt.IsZero() {
		t.Error("latest.pushed_at is zero")
	}
}

// TestECRCredentialsUsesTheConnection: the scan login comes from the aws
// connection, not from the caller.
func TestECRCredentialsUsesTheConnection(t *testing.T) {
	service, _ := newECRTestService(t)
	conn, err := service.Create(t.Context(), CreateInput{
		Kind: KindAWS, Name: "prod", Region: "eu-central-1",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	registry, err := service.AWSRegistry(t.Context(), conn.ID)
	if err != nil {
		t.Fatalf("AWSRegistry: %v", err)
	}
	credentials, err := service.ECRCredentials(t.Context(), conn.ID, registry)
	if err != nil {
		t.Fatalf("ECRCredentials: %v", err)
	}
	if credentials.Username != "AWS" || credentials.Password != "secret-token" {
		t.Errorf("credentials = %+v, want the fake's login", credentials)
	}

	if kind, err := service.ConnectionKind(t.Context(), conn.ID); err != nil || kind != KindAWS {
		t.Errorf("ConnectionKind = %q, %v; want aws", kind, err)
	}
}

// TestECRCredentialsRefusesForeignRegistry: a tampered asset must not send this
// connection's token to another host.
func TestECRCredentialsRefusesForeignRegistry(t *testing.T) {
	service, fake := newECRTestService(t)
	conn, err := service.Create(t.Context(), CreateInput{
		Kind: KindAWS, Name: "prod", Region: "eu-central-1",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = service.ECRCredentials(t.Context(), conn.ID, "evil.example.com")
	if err == nil {
		t.Fatal("ECRCredentials accepted a foreign registry")
	}
	if fake.tokenCalls != 0 {
		t.Errorf("AuthorizationToken called %d times, want 0", fake.tokenCalls)
	}
}

// TestAWSRegistryNeedsAccount: before a successful test there is no account to
// bind a registry to.
func TestAWSRegistryNeedsAccount(t *testing.T) {
	service, _ := newECRTestService(t)
	conn, err := service.Create(t.Context(), CreateInput{
		Kind: KindAWS, Name: "prod", Region: "eu-central-1",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// A connection whose test failed has no account in config_json.
	if _, err := service.db.ExecContext(t.Context(),
		`UPDATE connections SET config_json = '{"region":"eu-central-1"}' WHERE id = ?`, conn.ID); err != nil {
		t.Fatalf("clear account: %v", err)
	}
	if _, err := service.AWSRegistry(t.Context(), conn.ID); err == nil {
		t.Fatal("AWSRegistry succeeded without an account")
	}
}
