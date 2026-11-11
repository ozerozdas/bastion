# Backlog (one line each; not scheduled)

- EOL runtime/OS detection (endoflife.date data) as `outdated` findings
- Binary hardening findings (PIE/NX/RELRO) for binaries inside images — via REA composition or native Go parsing (debug/elf, debug/macho, debug/pe)
- JS bundle inspection: shipped source maps, hardcoded endpoints/keys in built assets
- Reachability beyond Go (JS/TS call graph)
