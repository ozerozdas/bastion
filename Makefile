VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
NPM := npm --prefix web

# Release tooling is not a go.mod tool: GoReleaser pulls a large dependency tree
# that has no business in the binary's module graph. Run it pinned via `go run`.
# Keep in sync with .github/workflows/release.yml.
GORELEASER_VERSION := v2.20.1
GORELEASER := go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)

# Dev tools (golangci-lint, sqlc, oapi-codegen) live in their own module so their
# dependencies (GPL linters among them) stay out of the binary's module graph and
# out of bastion's own self-scan.
TOOL := go tool -modfile=tools/go.mod

.PHONY: build check fmt lint test gen web-build web-check e2e release-snapshot

# The UI is embedded into the binary (web/embed.go), so it must be built
# before go build. node_modules is a file target: npm ci runs only when the
# lockfile (or package.json) is newer than the installed tree.
web/node_modules: web/package-lock.json web/package.json
	$(NPM) ci --no-audit --no-fund

web-build: web/node_modules
	$(NPM) run build

web-check: web/node_modules
	$(NPM) run typecheck
	$(NPM) run test

build: web-build
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/bastion ./cmd/bastion

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run gofmt -w ." && exit 1)

lint:
	$(TOOL) golangci-lint run ./...

test:
	go test ./...

gen:
	@# sqlc v1.31 shifts byte offsets on non-ASCII input and emits corrupt SQL silently.
	@! LC_ALL=C grep -n '[^ -~	]' db/queries/*.sql || { echo "db/queries: non-ASCII characters break sqlc"; exit 1; }
	$(TOOL) sqlc generate
	$(TOOL) oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml
	@test -d web/node_modules || $(NPM) ci --no-audit --no-fund
	$(NPM) run gen:api

# web-build first: lint and test compile web/embed.go, which needs web/dist
# (absent on a clean checkout, e.g. CI).
check: web-check web-build fmt lint test build

# e2e drives the real binary in Chromium, so it needs a browser that `check`
# does not: run `npx --prefix web playwright install chromium`, then `make e2e`.
e2e: build
	$(NPM) run e2e

# Builds all six release targets into dist/ without publishing anything.
# The before hook runs `make web-build`, so the embedded UI is current.
release-snapshot:
	$(GORELEASER) release --snapshot --clean
