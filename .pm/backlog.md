# Backlog (one line each; not scheduled)

- EOL runtime/OS detection (endoflife.date data) as `outdated` findings
- Binary hardening findings (PIE/NX/RELRO) for binaries inside images — via REA composition or native Go parsing (debug/elf, debug/macho, debug/pe)
- JS bundle inspection: shipped source maps, hardcoded endpoints/keys in built assets
- Reachability beyond Go (JS/TS call graph)
- `make gen`: drop the no-op `go generate ./...` or add real directives
- Self-scan: exclude testdata fixtures (or a .bastionignore) so intentional fixture vulns do not show as repo findings
- golang.org/x/crypto GO-2026-5932: fix only in a pseudo-version; bump when a tagged release lands
