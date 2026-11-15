//go:build awsreal

package trivy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/aws"
	"github.com/ozerozdas/bastion/internal/sources"
)

// TestRealECRScan pulls one real ECR tag with a short-lived login and scans it.
// It is the manual check behind #13: discovery, GetAuthorizationToken and the
// remote image source in one path. Only the repository, tag and report shape
// are printed; the login is never logged.
//
//	BASTION_REAL_PROFILE=texttonext go test -tags awsreal ./internal/scanners/trivy -run TestRealECRScan -v
func TestRealECRScan(t *testing.T) {
	profile := os.Getenv("BASTION_REAL_PROFILE")
	if profile == "" {
		profile = "default"
	}
	region := os.Getenv("BASTION_REAL_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	repositoryName := os.Getenv("BASTION_REAL_ECR_REPOSITORY")
	if repositoryName == "" {
		repositoryName = "wedding-platform/production/web"
	}

	client, err := aws.New(aws.Config{Profile: profile, Region: region})
	if err != nil {
		t.Fatalf("aws.New: %v", err)
	}
	repositories, err := client.Repositories(t.Context())
	if err != nil {
		t.Fatalf("Repositories: %v", err)
	}
	var chosen *aws.Repository
	for i := range repositories {
		if repositories[i].Name == repositoryName && len(repositories[i].Tags) > 0 {
			chosen = &repositories[i]
			break
		}
	}
	if chosen == nil {
		t.Fatalf("repository %q with a tag was not found", repositoryName)
	}
	tag := chosen.Tags[0]

	credentials, err := client.AuthorizationToken(t.Context())
	if err != nil {
		t.Fatalf("AuthorizationToken: %v", err)
	}

	cacheDir := os.Getenv("BASTION_REAL_TRIVY_CACHE")
	if cacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			t.Fatalf("UserCacheDir: %v", err)
		}
		cacheDir = filepath.Join(base, "bastion", "trivy")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	ref := chosen.URI + "@" + tag.Digest
	raw, err := ScanRemoteImage(ctx, ref, cacheDir, sources.RegistryAuth{
		Username: credentials.Username,
		Password: credentials.Password,
	})
	if err != nil {
		t.Fatalf("ScanRemoteImage(%s): %v", ref, err)
	}
	if len(raw) == 0 {
		t.Fatal("ScanRemoteImage returned an empty report")
	}

	var report struct {
		ArtifactType string `json:"ArtifactType"`
		Results      []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	findings := 0
	for _, result := range report.Results {
		findings += len(result.Vulnerabilities)
	}
	if report.ArtifactType != artifactTypeContainerImage {
		t.Errorf("artifact type = %q, want %q", report.ArtifactType, artifactTypeContainerImage)
	}
	if len(report.Results) == 0 {
		t.Error("report has no results")
	}
	t.Logf("scanned %s:%s (%s): %d results, %d vulnerabilities",
		chosen.Name, tag.Name, tag.Digest, len(report.Results), findings)
}
