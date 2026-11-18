# CI Integration

`bastion scan` runs headless, so any CI runner can use it. Three flags matter:

- `--no-store` — don't create or touch a database on the runner,
- `--format sarif` — output for GitHub code scanning and other SARIF tools,
- `--fail-on <severity>` — fail the job (exit `2`) on serious findings.

## Secrets key

Secret findings are stored redacted together with an HMAC (see
[Findings](Findings.md#secrets)). The HMAC key normally lives in the OS keyring, which CI
runners don't have — provide one through the environment:

```sh
export BASTION_HMAC_KEY="$(openssl rand -base64 32)"
```

## Generic example

```sh
bastion scan --path . --no-store --skip-dirs testdata \
  --format sarif --fail-on critical > bastion.sarif
```

## GitHub Action

The repository ships a composite action. It installs a pinned release (checked against
the release's `checksums.txt`), caches the vulnerability DB weekly, runs the scan,
uploads SARIF to code scanning and then fails on the threshold:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - uses: ozerozdas/bastion@v0.5.1
    with:
      fail-on: critical        # empty: never fail on findings
      skip-dirs: |
        testdata
      # version: v0.5.1       # bastion release to install
      # upload-sarif: "true"  # false: only write bastion.sarif
```

Outputs: `sarif-file` and `exit-code` (`0` clean, `2` threshold reached). The SARIF is
uploaded before the step fails, so findings show up in code scanning either way.
[`.github/workflows/action-sample.yml`](../../.github/workflows/action-sample.yml) is a
working example.

## Manual GitHub Actions example

```yaml
- name: Install bastion
  run: curl -fsSL https://raw.githubusercontent.com/ozerozdas/bastion/master/install.sh | sh

- name: Scan
  run: |
    export BASTION_HMAC_KEY="$(openssl rand -base64 32)"
    ~/.local/bin/bastion scan --path . --no-store \
      --format sarif --fail-on critical > bastion.sarif
```

Uploading the SARIF file to GitHub code scanning needs the `security-events: write`
permission.

## Tips

- The first scan on a fresh runner downloads the ~1.7 GB vulnerability DB. Cache the
  [cache directory](Configuration-and-Paths.md) (`~/.cache/bastion` on Linux) between runs.
- Use `--skip-dirs` for fixtures that contain intentionally vulnerable files (bastion skips
  its own `testdata` this way).
- Exit `1` means the scan broke, not that it found something — don't treat it as a pass.
