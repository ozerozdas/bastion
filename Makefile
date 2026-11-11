VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
NPM := npm --prefix web

.PHONY: build check fmt lint test gen web-build web-check

# The UI is embedded into the binary (web/embed.go), so it must be built
# before go build. node_modules is a file target: npm ci runs only when the
# lockfile (or package.json) is newer than the installed tree.
web/node_modules: web/package-lock.json web/package.json
	$(NPM) ci --no-audit --no-fund

web-build: web/node_modules
	$(NPM) run build

web-check: web/node_modules
	$(NPM) run typecheck

build: web-build
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/bastion ./cmd/bastion

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run gofmt -w ." && exit 1)

lint:
	go tool golangci-lint run ./...

test:
	go test ./...

gen:
	go tool sqlc generate
	go tool oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml
	@test -d web/node_modules || $(NPM) ci --no-audit --no-fund
	$(NPM) run gen:api

check: fmt lint web-check web-build test build
