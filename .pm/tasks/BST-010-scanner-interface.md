---
id: BST-010
title: Scanner interface + findings model + fingerprint with unit tests
phase: P0
status: done
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

### 2026-11-11 — review fixes (bst-010-review-fixes)
Branch commit for the reviewer's findings on §5 fingerprint/dedup:

- **H1 (fingerprint encoding).** `Fingerprint` no longer joins fields with `|`.
  Every field (asset id, type, rule id, ecosystem, package name, location) is
  written as `<byte length>:<value>` before sha256, so a separator inside a field
  can no longer collide with a different split. The secret location is no longer
  a `file|rule|hmac` composite: file, rule and HMAC are separate material fields.
  Tests: `TestFingerprintMaterialIsUnambiguous` (`CVE-1|x` + `npm` vs `CVE-1` +
  `x|npm`, and package/location variant), `TestFingerprintSecretFieldsAreNotDelimited`.
- **H2/M3/M4 (one finding per fingerprint per scan).** `Finding.Occurrences`
  (`json:"occurrences"`) added; `findings.Merge` groups by fingerprint, keeps the
  first in input order, upgrades to the highest severity (`SeverityRank`:
  critical > high > medium > low > unknown) and counts occurrences (≥1). It is
  called once, in the scan pipeline (`cmd/bastion/scan.go`, see BST-011).
  Tests: `internal/findings/merge_test.go` (duplicate DS-0001 → 1 finding /
  2 occurrences; low+high → high / 2; distinct fingerprints and singletons;
  empty fingerprint never collapsed).
- **M1 (schema comment + occurrences).** `db/migrations/00001_init.sql` gains
  `occurrences INTEGER NOT NULL DEFAULT 1 CHECK (occurrences >= 1)` and its
  findings.location comment now says the secret location is `file:line` for
  display while the HMAC lives only in the fingerprint material. Editing 00001 is
  allowed pre-release only — see `.pm/decisions/ADR-004-pre-release-migration-edits.md`.
  `make gen` regenerated `internal/store/sqlcdb/models.go` (`Occurrences int64`).
- **L1 (Windows paths).** `NormalizeLocation` replaces `\` with `/` before
  cleaning, so Windows-style locations normalize on every OS. Tests:
  `TestNormalizeLocationWindowsSeparators`.
- Golden files regenerated with `-update` for both normalizers: fingerprints
  changed by H1 and the `occurrences` field is new. The golden tests now apply
  `findings.Merge` before asserting, so they document the merged output the
  pipeline/UI consumes.

Verification:
- `go test ./internal/findings ./internal/scanners/...` → pass.
- `make check` → see BST-011 log (same branch).
- 2026-11-11 review (orchestrator + reviewer): review findings fixed on bst-010-review-fixes (length-prefixed fingerprint, per-scan merge with occurrences, license version key, Windows paths, deterministic CVSS, partial scanner results). make check green; fixture e2e 8 vuln/4 misconfig/1 license, both scanner runs succeeded. Done.
