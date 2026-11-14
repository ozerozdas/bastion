# CLI Reference

```
bastion [flags]                  # same as `bastion serve`
bastion serve   [--port N] [--no-browser] [--concurrency N]
bastion scan    --path DIR | --repo owner/name[@ref]
                [--format json|table|sarif|cyclonedx] [--fail-on critical|high|medium|low]
                [--skip-dirs DIR]...  [--no-store]
bastion doctor  [--json]
bastion version
```

## Global flags

These work with every subcommand.

| Flag | Default | Meaning |
|---|---|---|
| `--data-dir` | platform config dir | Where `bastion.db` lives |
| `--cache-dir` | platform cache dir | Vulnerability DBs and temporary workspaces |
| `--log-format` | `text` | `text` or `json` |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |

See [Configuration and Paths](Configuration-and-Paths.md) for defaults and environment variables.

## `bastion serve`

Starts the local web UI. This is also what plain `bastion` does.

| Flag | Default | Meaning |
|---|---|---|
| `--port` | random free port | Port on `127.0.0.1` |
| `--no-browser` | off | Print the URL but don't open a browser |
| `--concurrency` | `2` | Maximum scans running at once |

## `bastion scan`

Scans one target without the UI and prints the findings.

| Flag | Meaning |
|---|---|
| `--path DIR` | Scan a local directory |
| `--repo owner/name[@ref]` | Scan a GitHub repo (default branch unless `@ref` is given). Token comes from a saved connection or `BASTION_GITHUB_TOKEN` |
| `--format` | `json` (default), `table`, `sarif` or `cyclonedx` (CycloneDX 1.6 SBOM, also downloadable from **Projects → Scans**) |
| `--fail-on SEVERITY` | Exit `2` if an open finding is at or above this severity |
| `--skip-dirs DIR` | Skip a directory; repeat for more |
| `--no-store` | Do not touch the database (ideal for CI) |
| `--quiet` | Do not print scan progress on stderr |

Give exactly one of `--path` or `--repo`.

Progress is printed to stderr as plain lines (`trivy: running…`, `trivy: waiting for vulnerability database…`, `trivy: succeeded (4s)`, `osv: failed: <reason>`); stdout carries only the selected format. `--quiet` silences them.

```sh
# Human-readable scan of the current directory
bastion scan --path . --format table

# A GitHub repo's default branch, as JSON
bastion scan --repo ozerozdas/bastion --format json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan finished; nothing at or above `--fail-on` |
| `1` | The scan itself failed (bad flags, network, scanner error, …) |
| `2` | Scan finished and found an open finding at or above `--fail-on` |

This lets CI tell "findings found" from "the scan broke".

## `bastion doctor`

Prints paths, versions, keyring availability and database health. Use `--json` for
scripting. First thing to run when something is wrong — see [Troubleshooting](Troubleshooting.md).

## `bastion version`

Prints the version.
