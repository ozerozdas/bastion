---
id: BST-020
title: Connections service + API (GitHub)
phase: P1
status: in_progress
owner_role: coder
depends_on: [BST-016, BST-019]
estimate: M
---

## Context
§6 connections endpoints, §7 Connections page. Spec-first: edit api/openapi.yaml, regenerate, then implement.

## Scope
- In: OpenAPI + handlers: `GET/POST /api/connections`, `POST /api/connections/{id}/test`, `DELETE /api/connections/{id}`, `GET /api/connections/{id}/discover`. Token stored in secrets store under `secret_ref` (`bastion.connection.<id>`); env fallback `BASTION_GITHUB_TOKEN`. Test updates `status`, `last_checked_at`, records the login in `config_json`. Delete removes the keyring entry.
- Out: AWS/Docker (P2).

## Acceptance criteria
- [ ] Token never appears in any response, log line or DB column (test asserts)
- [ ] `X-Bastion` required on POST/DELETE (existing middleware)
- [ ] Discover lists repos with an `already_added` flag
- [ ] Handler tests with fake GitHub + in-memory secrets; `make check` passes

## Verification
Reviewer runs `make check` plus the commands in the acceptance criteria.

## Notes / Log
