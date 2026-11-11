---
id: BST-010
title: Scanner interface + findings model + fingerprint with unit tests
phase: P0
status: review
owner_role: coder
depends_on: [BST-003, BST-004]
estimate: M
---

## Context
PROJECT_SPEC.md §12 (seed tasks), §3, §4.

## Scope
- In: Scanner interface + findings model + fingerprint with unit tests
- Out: anything not listed in the acceptance criteria.

## Acceptance criteria
- [x] Interfaces per §4.2; findings model per §5
- [x] Fingerprint per §5 incl. image (path, not layer), secret (HMAC), misconfig rules; table tests
- [x] `make check` passes

## Verification
See acceptance criteria; reviewer runs `make check` plus the commands listed there.

## Notes / Log

## Notes / Log

### 2026-11-11 — implemented (bst-010-scanner-interface)
- `internal/sources`: `TargetKind`, `Target`, `Workspace` (Dir + Cleanup; `Image` deferred to P2), `Source`; `localpath` source for `path` targets.
- `internal/scanners/scanner.go`: `Scanner` (§4.2), `Options{CacheDir, HMACKey}`, `RawResult{Scanner, Version, WorkspaceDir, Raw, Data}`.
- Adapters keep the existing `trivy.ScanFS` / `gitleaks.ScanDir` functions; `trivy.Scanner` and `gitleaks.Scanner` are thin wrappers.
- `internal/findings`: §5 model (`Finding`, `Package`, `Asset`, types incl. `malware|sast`, severities), `Fingerprint`, `NormalizeLocation`, `Compare` (new/fixed/persisting).
- Normalizers: Trivy (vulnerability/misconfig/license + package inventory) and Gitleaks (secret, high) live in their scanner packages; Trivy JSON is decoded into local minimal structs, so the §4.2 import rule holds.
- Decisions:
  - `Options` carries the Trivy cache dir and the Gitleaks HMAC key; zero values are ignored by adapters that do not need them.
  - `RawResult.WorkspaceDir` lets normalizers strip temporary workspace prefixes from locations.
  - Misconfig location is `file#<resource-or-service-cause>`, never a line number.
  - License severities keep Trivy's policy category mapping (restricted → high, notice → low); this is documented in the normalizer as informational, not exploit risk.
  - `Finding.LayerDigest` is display-only image provenance and is excluded from fingerprints, which use the package path.

Verification:
- `make check` → golangci-lint 0 issues, all tests pass, build OK.
- `go test ./internal/findings` covers the fingerprint table: version change, secret line shift, workspace temp prefix change, layer digest change keep the fingerprint; asset/type/rule/ecosystem/package/location changes do not.
- Normalizer golden tests are delivered by BST-011.
