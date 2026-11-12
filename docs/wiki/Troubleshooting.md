# Troubleshooting

Start with:

```sh
bastion doctor          # or: bastion doctor --json
```

It prints the data and cache paths, versions, whether the keyring works, and database
health. Most problems show up there.

## Common problems

| Symptom | Likely cause | Fix |
|---|---|---|
| Browser shows `401` / "unauthorized" | The startup token was already used, or the browser was opened by hand without it | Restart `bastion` and open the freshly printed URL |
| `421 Misdirected Request` | Opened via a hostname other than `127.0.0.1` / `localhost` | Use the exact printed URL |
| First scan takes a long time | Downloading the ~1.7 GB vulnerability DB | Wait once; later scans reuse `<cache>/trivy` |
| "No space left on device" | Cache dir is on a small disk | Move it with `--cache-dir` / `BASTION_CACHE_DIR` |
| Scan fails with `401` or "token" | GitHub token revoked or expired | **Connections → Test**, replace the token if needed |
| Scan fails with `404` / "not found" | Token can't see that repository | Give the token access (fine-grained: add the repo; classic: `repo` scope) |
| Scan fails with "rate limit" | GitHub API rate limit | Wait for the reset, then scan again |
| `doctor` says keyring unavailable | Headless Linux / no Secret Service | Use `BASTION_GITHUB_TOKEN` and `BASTION_HMAC_KEY` |
| A finding keeps coming back after ignoring | It's a different fingerprint (other project, rule or location) | Ignore that one too; see [Findings](Findings.md#fingerprints-what-makes-a-finding-the-same) |
| Lots of findings from test fixtures | Fixtures contain vulnerable code on purpose | `--skip-dirs testdata` on the CLI |

## Getting more detail

```sh
bastion --log-level debug
bastion --log-level debug --log-format json scan --path .
```

Logs never contain tokens or raw secrets, so they are safe to share in an issue — still,
glance through them first.

## Starting fresh

- Delete the **cache dir** to re-download the vulnerability DB (safe).
- Delete the **data dir** to wipe projects, scans and ignore decisions (not reversible).

Paths: see [Configuration and Paths](Configuration-and-Paths.md).
