# Security policy

## Reporting a vulnerability

Please do **not** open a public issue. Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/ozerozdas/bastion/security/advisories/new).

Include what you found, how to reproduce it, and the version (`bastion version`). You will get
an acknowledgement within a few days; fixes are released as soon as practical and credited in
the advisory unless you prefer otherwise.

## Scope

The threat model in the README ("Threat model") describes what bastion defends against and
what it does not. Reports about the local HTTP server, token handling, secret redaction,
path handling of scanned content, or unexpected network calls are especially welcome.

Vulnerabilities in Trivy or Gitleaks themselves should go to those projects; tell us too if
bastion needs to bump a version.

Only the latest release is supported.
