# Configuration and Paths

Precedence everywhere: **flag > environment variable > platform default**.

## Directories

| What | macOS default | Linux default | Windows default | Override |
|---|---|---|---|---|
| Data dir (SQLite `bastion.db`) | `~/Library/Application Support/bastion` | `~/.config/bastion` | `%AppData%\bastion` | `--data-dir`, `BASTION_DATA_DIR` |
| Cache dir | `~/Library/Caches/bastion` | `~/.cache/bastion` | `%LocalAppData%\bastion` | `--cache-dir`, `BASTION_CACHE_DIR` |
| Trivy DB and checks | `<cache>/trivy` | `<cache>/trivy` | `<cache>\trivy` | via cache dir |
| Repo workspaces | `<cache>/workspaces` | `<cache>/workspaces` | `<cache>\workspaces` | via cache dir |

The defaults follow Go's `os.UserConfigDir()` and `os.UserCacheDir()`. On Windows that is
`%AppData%` (`C:\Users\<user>\AppData\Roaming`) for data and `%LocalAppData%`
(`C:\Users\<user>\AppData\Local`) for cache. Run `bastion doctor` to see the directories
bastion actually resolved on your machine.

- The **data dir** holds your projects, scans, findings and ignore decisions. Back it up if
  you care about them.
- The **cache dir** is the big one (the vulnerability DB is ~1.7 GB). Deleting it is safe;
  the next scan downloads the DB again.
- Workspaces are deleted after each scan.

## Environment variables

| Variable | Purpose |
|---|---|
| `BASTION_DATA_DIR` | Data directory |
| `BASTION_CACHE_DIR` | Cache directory |
| `BASTION_GITHUB_TOKEN` | Read-only GitHub token for headless use, when no keyring / saved connection is available |
| `BASTION_HMAC_KEY` | Base64 32-byte key for secret HMACs; overrides the keyring key (needed in CI) |

## Credentials

Tokens and keys live in the OS keyring:

| OS | Keyring |
|---|---|
| macOS | Keychain |
| Linux | Secret Service (GNOME Keyring, KWallet, …) |
| Windows | Credential Manager |

There is **no plaintext fallback file**. If no keyring is available (headless Linux, CI),
use the environment variables above.
