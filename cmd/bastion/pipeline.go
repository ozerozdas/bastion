package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/connections"
	githubclient "github.com/ozerozdas/bastion/internal/connections/github"
	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/jobs"
	"github.com/ozerozdas/bastion/internal/scanners"
	"github.com/ozerozdas/bastion/internal/scanners/gitleaks"
	"github.com/ozerozdas/bastion/internal/scanners/trivy"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/sources"
	githubsource "github.com/ozerozdas/bastion/internal/sources/github"
	"github.com/ozerozdas/bastion/internal/sources/localpath"
	"github.com/ozerozdas/bastion/internal/store"
)

// The scan pipeline is one implementation shared by `bastion scan` and the
// server (PROJECT_SPEC.md §4): the CLI must not carry a second persisting
// pipeline, and the UI must not carry a third. Everything that builds a
// jobs.Manager lives here.

// pipelineConfig wires a jobs.Manager.
type pipelineConfig struct {
	// DB is the SQLite handle scans are persisted through.
	DB *sql.DB
	// ScannerList are the scanners every scan runs.
	ScannerList []scanners.Scanner
	// Sources maps a target kind to its fetcher.
	Sources map[sources.TargetKind]sources.Source
	// Options are the scanner options (cache dir, HMAC key).
	Options scanners.Options
	// Concurrency is the worker count; zero means jobs.DefaultConcurrency.
	Concurrency int
	// Events receives scan lifecycle events; nil means none.
	Events jobs.Publisher
	// Resolve turns an asset into a fetchable target.
	Resolve jobs.ResolveFunc
}

// newScanManager builds the manager with the adapters that normalize their own
// output. A scanner without a normalizer fails its scanner_run rather than
// running unnormalized, so the mapping is built here once.
func newScanManager(cfg pipelineConfig) (*jobs.Manager, error) {
	normalizers := make(map[string]findings.Normalizer, len(cfg.ScannerList))
	for _, scanner := range cfg.ScannerList {
		if a, ok := scanner.(adapter); ok {
			normalizers[scanner.Name()] = a
		}
	}
	manager, err := jobs.New(jobs.Config{
		DB:          cfg.DB,
		Sources:     cfg.Sources,
		Scanners:    cfg.ScannerList,
		Normalizers: normalizers,
		Options:     func() scanners.Options { return cfg.Options },
		Concurrency: cfg.Concurrency,
		Events:      cfg.Events,
		Resolve:     cfg.Resolve,
	})
	if err != nil {
		return nil, fmt.Errorf("scan pipeline: %w", err)
	}
	return manager, nil
}

// newRepoResolver returns the server's asset resolver. A repository needs a
// commit SHA, which needs the token of the connection the asset belongs to
// (falling back to the default GitHub token), so it is resolved per scan
// rather than once at startup.
func newRepoResolver(db *sql.DB, tokens *connections.Service, buildVersion string) jobs.ResolveFunc {
	return func(ctx context.Context, asset jobs.Asset) (sources.Target, string, error) {
		target := sources.Target{Kind: asset.Kind, AssetID: asset.ID, Ref: asset.Ref}
		if asset.Kind != sources.KindRepo {
			return target, "", nil
		}

		owner, name, err := splitRepoRef(asset.Ref)
		if err != nil {
			return sources.Target{}, "", err
		}
		stored, err := store.LoadAssetTarget(ctx, db, asset.ID)
		if err != nil {
			return sources.Target{}, "", fmt.Errorf("scan: %w", err)
		}
		token, err := tokens.ConnectionToken(ctx, stored.ConnectionID)
		if err != nil {
			return sources.Target{}, "", fmt.Errorf("scan: %s: %w", asset.Ref, err)
		}
		client, err := githubclient.New(githubclient.Config{Token: token, Version: buildVersion})
		if err != nil {
			return sources.Target{}, "", fmt.Errorf("scan: create GitHub client: %w", err)
		}

		ref := stored.DefaultBranch
		if ref == "" {
			repo, err := client.Repo(ctx, owner, name)
			if err != nil {
				return sources.Target{}, "", fmt.Errorf("scan: get repo %s: %w", asset.Ref, err)
			}
			ref = repo.DefaultBranch
		}
		if ref == "" {
			return sources.Target{}, "", fmt.Errorf("scan: %s reports no default branch", asset.Ref)
		}
		sha, err := client.ResolveSHA(ctx, owner, name, ref)
		if err != nil {
			return sources.Target{}, "", fmt.Errorf("scan: resolve %s@%s: %w", asset.Ref, ref, err)
		}
		return sources.Target{Kind: sources.KindRepo, AssetID: asset.ID, Ref: asset.Ref + "@" + sha}, sha, nil
	}
}

// splitRepoRef splits an asset's canonical owner/name ref. The API validated
// it when the asset was created; a stored ref is trusted but still split
// safely.
func splitRepoRef(fullName string) (owner, name string, err error) {
	owner, name, ok := strings.Cut(fullName, "/")
	if !ok || owner == "" || name == "" {
		return "", "", fmt.Errorf("scan: asset ref %q is not owner/name", fullName)
	}
	return owner, name, nil
}

// tokenDownloader fetches repository tarballs with the token of the connection
// that owns the repository asset, falling back to the default GitHub token for
// a repository bastion does not track. The token is only ever held in memory.
type tokenDownloader struct {
	db      *sql.DB
	tokens  *connections.Service
	version string
}

// Tarball implements githubsource.Downloader.
func (d *tokenDownloader) Tarball(ctx context.Context, owner, name, sha string) (io.ReadCloser, error) {
	token, err := d.token(ctx, owner+"/"+name)
	if err != nil {
		return nil, err
	}
	client, err := githubclient.New(githubclient.Config{Token: token, Version: d.version})
	if err != nil {
		return nil, fmt.Errorf("scan: create GitHub client: %w", err)
	}
	return client.Tarball(ctx, owner, name, sha)
}

// token resolves the credential for one repository.
func (d *tokenDownloader) token(ctx context.Context, fullName string) (string, error) {
	target, found, err := store.RepoAssetTarget(ctx, d.db, fullName)
	if err != nil {
		return "", fmt.Errorf("scan: %w", err)
	}
	if !found {
		return d.tokens.Token(ctx)
	}
	return d.tokens.ConnectionToken(ctx, target.ConnectionID)
}

// newRepoSource builds the GitHub source the server fetches repositories with.
func newRepoSource(paths app.Paths, db *sql.DB, tokens *connections.Service, buildVersion string) (sources.Source, error) {
	src, err := githubsource.New(&tokenDownloader{db: db, tokens: tokens, version: buildVersion}, githubsource.Options{
		WorkspacesDir: paths.WorkspacesDir(),
	})
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return src, nil
}

// serverScanShutdownGrace bounds the worker drain when the server stops.
const serverScanShutdownGrace = 10 * time.Second

// newServerScanManager wires the server's scan pipeline: local paths and
// repositories, the same scanners as the CLI, and a resolver that reads the
// asset's connection token for repositories. Scans left unfinished by the
// previous process are failed before the server accepts requests, so a queued
// scan can never stay queued forever. bus receives the lifecycle events the
// SSE endpoint streams. trivyDB is the vulnerability DB manager the scans and
// the /api/trivy-db endpoints share.
func newServerScanManager(ctx context.Context, db *sql.DB, opts *serveOptions, tokens *connections.Service, secretStore secrets.Store, bus jobs.Publisher, trivyDB *trivy.Manager) (*jobs.Manager, error) {
	hmacKey, err := secrets.LocalKey(secretStore)
	if err != nil {
		// Only secret fingerprints need the key; everything else still works,
		// so a missing keyring must not keep the server from starting.
		slog.Warn("secret fingerprints will not be stable until a key is available", "error", err)
	}

	repoSource, err := newRepoSource(opts.paths, db, tokens, version)
	if err != nil {
		return nil, err
	}
	manager, err := newScanManager(pipelineConfig{
		DB: db,
		// Trivy serializes itself (ADR-001); running adapters one after
		// another also keeps Gitleaks independent of that lock.
		ScannerList: []scanners.Scanner{trivy.NewWithManager(trivyDB), gitleaks.New()},
		Sources: map[sources.TargetKind]sources.Source{
			sources.KindPath: localpath.New(),
			sources.KindRepo: repoSource,
		},
		Options: scanners.Options{
			CacheDir: opts.paths.TrivyCacheDir(),
			HMACKey:  hmacKey,
		},
		Concurrency: opts.concurrency,
		Events:      bus,
		Resolve:     newRepoResolver(db, tokens, version),
	})
	if err != nil {
		return nil, err
	}
	if err := manager.Recover(context.WithoutCancel(ctx)); err != nil {
		_ = manager.Close()
		return nil, err
	}
	return manager, nil
}

// stopScanManager drains the worker pool at shutdown. An expired drain is
// logged, not fatal: the process is stopping either way.
func stopScanManager(manager *jobs.Manager) {
	ctx, cancel := context.WithTimeout(context.Background(), serverScanShutdownGrace)
	defer cancel()
	if err := manager.Shutdown(ctx); err != nil {
		slog.Warn("scan workers did not stop cleanly", "error", err)
	}
}
