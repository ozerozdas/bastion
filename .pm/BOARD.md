# Board

| id | title | phase | status | owner_role | depends_on |
|---|---|---|---|---|---|
| BST-001 | Repo scaffold | P0 | done | coder | — |
| BST-002 | CI | P0 | done | coder | 001 |
| BST-003 | Trivy spike → ADR-001 | P0 | done | coder | 001 |
| BST-004 | Gitleaks spike | P0 | done | coder | 001 |
| BST-005 | App paths + config | P0 | done | coder | 001 |
| BST-006 | SQLite + goose + sqlc | P0 | done | coder | 005 |
| BST-007 | OpenAPI + codegen | P0 | done | coder | 001 |
| BST-008 | HTTP server + §4.3 security | P0 | done | coder | 007 |
| BST-009 | Web scaffold + embed | P0 | done | coder | 008 |
| BST-010 | Scanner interface + fingerprint | P0 | done | coder | 003, 004 |
| BST-011 | `scan --path` + golden tests | P0 | done | coder | 010 |
| BST-012 | `doctor` | P0 | done | coder | 005, 006 |
| BST-013 | Keyring wrapper | P0 | done | coder | 005 |
| BST-014 | P0 exit check | P0 | done | tester | all |
| BST-015 | ADR-005 GitHub network calls | P1 | done | architect | — |
| BST-016 | Store: persist a scan | P1 | done | coder | — |
| BST-017 | finding_states + latest findings | P1 | in_progress | coder | 016 |
| BST-018 | `scan --path` persists (real asset id) | P1 | in_progress | coder | 016 |
| BST-019 | GitHub API client | P1 | done | coder | 015 |
| BST-020 | Connections service + API | P1 | in_progress | coder | 016, 019 |
| BST-021 | GitHub tarball source | P1 | in_progress | coder | 019 |
| BST-022 | Job system | P1 | todo | coder | 016, 021 |
| BST-023 | SSE /api/events | P1 | todo | coder | 022 |
| BST-024 | Assets, scans, finding-state API | P1 | todo | coder | 017, 020, 022 |
| BST-025 | Reports API | P1 | todo | coder | 017 |
| BST-026 | UI Connections | P1 | todo | coder | 020 |
| BST-027 | UI Projects + scan progress | P1 | todo | coder | 023, 024, 026 |
| BST-028 | UI Security Reports | P1 | todo | coder | 024, 025 |
| BST-029 | UI Dashboard | P1 | todo | coder | 025 |
| BST-030 | UI Scan History | P1 | todo | coder | 024 |
| BST-031 | CLI `scan --repo`, table/SARIF | P1 | todo | coder | 018, 021 |
| BST-032 | Vitest + Playwright smoke | P1 | todo | tester | 026–030 |
| BST-033 | CI self-scan + `make gen` cleanup | P1 | todo | coder | 031 |
| BST-034 | README, threat model, network calls | P1 | todo | coder | 027, 028, 031 |
| BST-035 | Release pipeline | P1 | todo | coder | 033 |
| BST-036 | P1 exit check | P1 | todo | tester | all |
