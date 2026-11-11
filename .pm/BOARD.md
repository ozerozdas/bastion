# Board

| id | title | phase | status | owner_role | depends_on |
|---|---|---|---|---|---|
| BST-001 | Repo scaffold | P0 | done | coder | — |
| BST-002 | CI | P0 | ready | coder | 001 |
| BST-003 | Trivy spike → ADR-001 | P0 | done | coder | 001 |
| BST-004 | Gitleaks spike | P0 | done | coder | 001 |
| BST-005 | App paths + config | P0 | done | coder | 001 |
| BST-006 | SQLite + goose + sqlc | P0 | ready | coder | 005 |
| BST-007 | OpenAPI + codegen | P0 | ready | coder | 001 |
| BST-008 | HTTP server + §4.3 security | P0 | todo | coder | 007 |
| BST-009 | Web scaffold + embed | P0 | todo | coder | 008 |
| BST-010 | Scanner interface + fingerprint | P0 | ready | coder | 003, 004 |
| BST-011 | `scan --path` + golden tests | P0 | todo | coder | 010 |
| BST-012 | `doctor` | P0 | todo | coder | 005, 006 |
| BST-013 | Keyring wrapper | P0 | done | coder | 005 |
| BST-014 | P0 exit check | P0 | todo | tester | all |
