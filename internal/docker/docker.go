// Package docker talks to the local Docker daemon: it reports whether one is
// reachable, lists its images and fetches image targets for a scan.
//
// It is the only package outside internal/scanners/trivy that imports the
// Docker client, so daemon detection and listing stay in one place. Bastion
// never starts or changes a container; it only reads what the daemon already
// has.
package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"

	"github.com/ozerozdas/bastion/internal/sources"
)

// ErrUnavailable means no Docker daemon host was found.
var ErrUnavailable = errors.New("docker: no daemon is available")

const (
	// pingTimeout bounds the daemon probe. A missing or wedged socket must not
	// hold up the UI or a doctor run.
	pingTimeout = time.Second
	// listTimeout bounds one image listing. A local daemon answers in
	// milliseconds; the bound keeps a wedged socket from holding the request.
	listTimeout = 5 * time.Second
)

// socketPaths are the local sockets checked when DOCKER_HOST is unset, in the
// order Docker Desktop, OrbStack, Colima and Rancher Desktop install them.
// Tests replace the list.
var socketPaths = []string{
	"/var/run/docker.sock",
	"~/.docker/run/docker.sock",
	"~/.orbstack/run/docker.sock",
	"~/.colima/default/docker.sock",
	"~/.rd/docker.sock",
}

// Host resolves the daemon host: DOCKER_HOST when set, otherwise the first
// local socket that exists. The boolean reports whether a host was found, not
// whether it answers.
func Host() (string, bool) {
	if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); host != "" {
		return host, true
	}
	for _, path := range socketPaths {
		resolved, err := expandHome(path)
		if err != nil {
			continue
		}
		if _, err := os.Stat(resolved); err == nil {
			return "unix://" + resolved, true
		}
	}
	return "", false
}

// DaemonStatus is the daemon state doctor and the API report.
type DaemonStatus struct {
	// Found is true when the daemon answered a ping.
	Found bool
	// Host is the host that actually answered. It is empty when no daemon was
	// reached, so a stale socket is never handed to a scanner.
	Host string
	// Version is the daemon's engine version, when it answered.
	Version string
}

// Status probes the daemon with a short timeout. A daemon that does not
// answer is reported as not found rather than as an error.
func Status(ctx context.Context) DaemonStatus {
	host, ok := Host()
	if !ok {
		return DaemonStatus{}
	}
	cli, err := client.New(client.WithHost(host))
	if err != nil {
		return DaemonStatus{}
	}
	defer func() { _ = cli.Close() }()

	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if _, err := cli.Ping(pingCtx, client.PingOptions{}); err != nil {
		return DaemonStatus{}
	}
	status := DaemonStatus{Found: true, Host: host}

	versionCtx, cancelVersion := context.WithTimeout(ctx, pingTimeout)
	defer cancelVersion()
	if version, err := cli.ServerVersion(versionCtx, client.ServerVersionOptions{}); err == nil {
		status.Version = version.Version
	}
	return status
}

// Available reports whether a daemon answered a ping.
func Available(ctx context.Context) bool {
	return Status(ctx).Found
}

// Image is one local image tag. A tag is the unit a scan targets, so an image
// with several tags appears once per tag.
type Image struct {
	Reference string
	ID        string
	Size      int64
	Created   time.Time
}

// ListImages returns the tagged images of the local daemon, sorted by
// reference. Untagged images (<none>:<none>) are skipped: they cannot be
// addressed by a scan.
func ListImages(ctx context.Context) ([]Image, error) {
	host, ok := Host()
	if !ok {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	cli, err := client.New(client.WithHost(host))
	if err != nil {
		return nil, fmt.Errorf("docker: create client: %w", err)
	}
	defer func() { _ = cli.Close() }()

	result, err := cli.ImageList(ctx, client.ImageListOptions{})
	if err != nil {
		return nil, fmt.Errorf("docker: list images: %w", err)
	}

	return imagesFromSummaries(result.Items), nil
}

// imagesFromSummaries turns the daemon's summaries into one entry per tag,
// sorted by reference. Untagged images are skipped: a scan cannot address
// them.
func imagesFromSummaries(summaries []image.Summary) []Image {
	images := make([]Image, 0, len(summaries))
	for _, summary := range summaries {
		created := time.Unix(summary.Created, 0).UTC()
		for _, tag := range summary.RepoTags {
			if tag == "" || tag == "<none>:<none>" {
				continue
			}
			images = append(images, Image{
				Reference: tag,
				ID:        summary.ID,
				Size:      summary.Size,
				Created:   created,
			})
		}
	}
	slices.SortFunc(images, func(a, b Image) int {
		return strings.Compare(a.Reference, b.Reference)
	})
	return images
}

// expandHome expands a leading "~" in a socket path.
func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~")), nil
}

// Source resolves image targets. It creates nothing, so its workspaces have no
// cleanup hook: the scan reads the image the daemon already holds, or pulls a
// registry target with the login the resolver attached to it.
type Source struct{}

// NewSource returns a source for local Docker images.
func NewSource() *Source { return &Source{} }

// Kind reports that this source handles image targets.
func (*Source) Kind() sources.TargetKind { return sources.KindImage }

// Fetch checks that a daemon is reachable and returns the image reference as a
// directory-less workspace.
func (*Source) Fetch(ctx context.Context, t sources.Target) (*sources.Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.Kind != sources.KindImage {
		return nil, fmt.Errorf("docker: unsupported target kind %q", t.Kind)
	}
	ref := strings.TrimSpace(t.Ref)
	if ref == "" {
		return nil, errors.New("docker: image reference is required")
	}
	// A registry target carries its own login (an ECR asset): the scanner pulls
	// it remotely, so no local daemon is needed and none is probed.
	if t.RegistryAuth != nil {
		return &sources.Workspace{Image: ref, RegistryAuth: t.RegistryAuth}, nil
	}
	status := Status(ctx)
	if !status.Found {
		return nil, fmt.Errorf("%w: start Docker or set DOCKER_HOST", ErrUnavailable)
	}
	return &sources.Workspace{Image: ref, DockerHost: status.Host}, nil
}
