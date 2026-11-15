package docker

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/api/types/image"
)

func TestHostUsesDockerHost(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")

	host, ok := Host()
	if !ok || host != "tcp://127.0.0.1:2375" {
		t.Fatalf("Host() = %q, %v, want DOCKER_HOST", host, ok)
	}
}

func TestHostFindsLocalSocket(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	socket := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	original := socketPaths
	socketPaths = []string{filepath.Join(t.TempDir(), "missing.sock"), socket}
	t.Cleanup(func() { socketPaths = original })

	host, ok := Host()
	if !ok || host != "unix://"+socket {
		t.Fatalf("Host() = %q, %v, want the existing socket", host, ok)
	}
}

func TestHostReportsNothingWithoutASocket(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	original := socketPaths
	socketPaths = nil
	t.Cleanup(func() { socketPaths = original })

	if host, ok := Host(); ok || host != "" {
		t.Fatalf("Host() = %q, %v, want no host", host, ok)
	}
}

func TestImagesFromSummaries(t *testing.T) {
	images := imagesFromSummaries([]image.Summary{
		{
			ID:       "sha256:bbb",
			RepoTags: []string{"nginx:latest", "<none>:<none>", ""},
			Size:     42,
			Created:  100,
		},
		{
			ID:       "sha256:ccc",
			RepoTags: []string{"alpine:3.20"},
			Size:     7,
			Created:  200,
		},
		{
			// Untagged images are not addressable by a scan.
			ID:       "sha256:ddd",
			RepoTags: nil,
			Size:     1,
		},
	})

	if len(images) != 2 {
		t.Fatalf("images = %+v, want two tagged images", images)
	}
	if images[0].Reference != "alpine:3.20" || images[1].Reference != "nginx:latest" {
		t.Fatalf("images = %+v, want sorted references", images)
	}
	if images[1].ID != "sha256:bbb" || images[1].Size != 42 {
		t.Fatalf("nginx image = %+v, want the summary values", images[1])
	}
	if !images[1].Created.Equal(time.Unix(100, 0).UTC()) {
		t.Fatalf("created = %v, want the summary time", images[1].Created)
	}
}
