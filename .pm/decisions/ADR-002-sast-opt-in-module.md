# ADR-002: SAST as an opt-in downloaded module

- Status: accepted (Özer, 2026-11-11)

## Context
SAST is a core Aikido module. Semgrep/Opengrep are not Go and cannot be imported as libraries, which conflicts with the single-binary principle (§1.1).

## Decision
The core stays a single pure-Go binary. SAST is an optional module: when the user enables it, bastion downloads a pinned Opengrep release into `UserCacheDir()/bastion/modules/`, verifies its SHA-256 against a checksum compiled into bastion, and runs it as a subprocess. Without it, every other feature works.

## Consequences
- New outbound call (release download), listed in README "Network calls", only on opt-in.
- Per-platform checksum table must be updated with each Opengrep bump.
- Subprocess output is untrusted input: size/time budgets apply (§4.3).
