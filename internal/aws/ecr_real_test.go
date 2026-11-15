//go:build awsreal

package aws

import (
	"os"
	"testing"
)

// TestRealECRDiscovery is the manual check behind ECR discovery: it uses this
// machine's default credential chain and lists the account's repositories with
// their newest tags. Only repository names, tag names and digests are printed;
// no credential or authorization token is read or logged.
//
//	go test -tags awsreal ./internal/aws -run TestRealECRDiscovery -v
func TestRealECRDiscovery(t *testing.T) {
	profile := os.Getenv("BASTION_REAL_PROFILE")
	if profile == "" {
		profile = "default"
	}
	region := os.Getenv("BASTION_REAL_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	client, err := New(Config{Profile: profile, Region: region})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	repositories, err := client.Repositories(t.Context())
	if err != nil {
		t.Fatalf("Repositories: %v", err)
	}
	if len(repositories) == 0 {
		t.Fatalf("no ECR repositories found for profile %q in %s", profile, region)
	}

	found := false
	for _, repository := range repositories {
		t.Logf("repository=%s tags=%d", repository.Name, len(repository.Tags))
		for _, tag := range repository.Tags {
			t.Logf("  tag=%s digest=%s pushed=%s", tag.Name, tag.Digest, tag.PushedAt.Format("2006-01-02T15:04:05Z07:00"))
		}
		if repository.Name == "t2n-api" || repository.Name == "t2n-worker" {
			found = true
		}
	}
	if !found {
		t.Errorf("neither t2n-api nor t2n-worker was discovered")
	}

	credentials, err := client.AuthorizationToken(t.Context())
	if err != nil {
		t.Fatalf("AuthorizationToken: %v", err)
	}
	if credentials.Username == "" || credentials.Password == "" {
		t.Fatal("AuthorizationToken returned an empty login")
	}
	t.Logf("authorization token resolved (username=%q, expires=%s)", credentials.Username, credentials.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
}
