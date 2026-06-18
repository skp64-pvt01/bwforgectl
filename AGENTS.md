# ssh-bw — SSH ↔ Bitwarden sync

## Purpose & Objectives

Synchronise SSH key pairs between a local `~/.ssh` directory and a Bitwarden vault, providing a single source of truth for SSH credentials. Designed for developers and sysadmins who manage multiple machines and want their SSH keys (and PGP notes) backed up, versioned, and accessible from any device via Bitwarden.

### Key Objectives Achieved

- **Bidirectional sync** — push local keys to the vault (`--from-disk`) or pull vault keys to disk (`--from-server`), with safe matching by fingerprint → item name → private key body.
- **Safe dry-run mode** — bare `ssh-bw sync` is always read-only; explicit `--yes` or `--update` flags required to mutate data.
- **Multiple credential backends** — OS keyring (GNOME/KWallet/macOS/Windows) with encrypted-file fallback using PBKDF2-HMAC-SHA256 + Fernet (AES).
- **Robust Bitwarden transport** — CLI subprocess with 30s timeout, empty-stdin sentinel, SIGKILL detection, and automatic re-authentication on session expiry; optional `bw serve` REST API for faster bulk operations.
- **PGP awareness** — detects and lists PGP private/public key blocks stored as Bitwarden secure notes.
- **Production packaging** — Debian `.deb` via `dpkg-buildpackage`, GitHub Actions CI that builds and publishes releases on `v*` tags, and `scripts/release.sh` for version bumps.
- **Comprehensive tests** — 36 pytest tests covering scanning, sync logic, matching, credential round-trips, and transport edge cases.
- **Developer documentation** — PlantUML architecture diagrams (module, class, sequence) in `diagrams/` and `DEVELOPER.md`.

## Project Structure

```
ssh-bw/
├── ssh_bw/            # Package (8 modules)
│   ├── cli.py         # argparse CLI, command dispatch, credential resolution
│   ├── bwclient.py    # Bitwarden CLI + REST transport, session health
│   ├── importer.py    # Sync logic (disk↔vault), dry-run support
│   ├── credentials.py # Credential store (keyring / encrypted PBKDF2+Fernet file)
│   ├── sshscan.py     # ~/.ssh key pair scanner, fingerprint via ssh-keygen
│   ├── pgp.py         # PGP secure-note detection
│   ├── __init__.py
│   └── __main__.py
├── tests/             # 36 pytest tests (fake_bw.py, conftest.py, 4 test modules, 2 shell drivers)
├── debian/            # Debian packaging (dpkg-buildpackage)
├── diagrams/          # 6 PlantUML source + PNG diagrams
├── scripts/           # release.sh (version bump + tag + push)
├── .github/           # GitHub Actions release.yml (build .deb on v* tag)
├── pyproject.toml     # Project metadata, entry point ssh-bw=ssh_bw.cli:main
├── setup.py           # Legacy setup (mirrors pyproject.toml)
├── README.md          # User documentation
├── DEVELOPER.md       # Developer documentation with diagrams
└── AGENTS.md          # THIS FILE
```

## Architecture

- **Entry point**: `ssh-bw` → `ssh_bw.cli:main` → argparse dispatches to subcommand handlers.
- **Transport**: `BitwardenClient` wraps `bw` CLI (`subprocess`) or optional `bw serve` REST API. 30s timeout, empty-stdin sentinel, SIGKILL detection, auto-reauth on session expiry.
- **Sync direction**: `--from-disk` (default, local→vault) or `--from-server` (vault→local).
- **Matching**: fingerprint → item name → private-key body.
- **Dry-run mode**: bare `sync` (no `--yes`/`--update`) is read-only — reports differences, no mutations.
- **Credential resolution**: CLI flags → env vars → credential store → interactive prompt → optional store update on failure.

## 36 Tests

- `test_sshscan.py` — key pair scanning, normalization, fingerprinting
- `test_importer.py` — sync logic, matching, dry-run, create/update/skip/decline
- `test_bwclient.py` — bw CLI wrapper, session health, serve lifecycle
- `test_helpers.py` — pgp detection, normalize utility
- `test_credentials.py` — keyring + encrypted-file store round-trips
- Shell drivers: `test_driver.sh`, `test_system.sh`

## CLI Commands

| Command | Description |
|---|---|
| `ssh-bw store-credentials` | Persist credentials (keyring or encrypted file) |
| `ssh-bw forget-credentials` | Remove stored credentials |
| `ssh-bw sync` | Compare keys (dry run); `--yes` auto-confirms; `--update` prompts |
| `ssh-bw sync --from-server` | Pull vault keys to local disk |
| `ssh-bw list --type ssh/pgp/all` | List vault items |
| `ssh-bw output --type ssh/pgp` | Dump keys/notes to stdout or files |
| `ssh-bw delete --name/--id` | Delete vault SSH items |

## Key Design Decisions

- `--yes` alone auto-confirms (not gated on `--update`); bare `sync` = dry run.
- `BW_STORE_PASSPHRASE` env var auto-triggers credential store (no `--use-stored` needed).
- Prog name `ssh-bw` (hyphen) in help text, matching installed binary.
- Three verbosity levels: `--quiet`=0, default=1, `-v`=2, `-vv`=3.
- Env var fallbacks: `BW_PATH`, `BW_NO_SYNC`, `BW_QUIET`, `BW_EMAIL`, `BW_PASSWORD`, `BW_SESSION`, `BW_STORE_PASSPHRASE`, `SERVE_PORT`.

## Packaging

- Debian: `dpkg-buildpackage -b -uc -us` → `../ssh-bw_1.0.0-1_all.deb`.
- CI: GitHub Actions on `v*` tag → build .deb on ubuntu-24.04 → publish release.
- Release: `scripts/release.sh <version>` bumps 3 files + changelog, creates annotated tag, optionally pushes.
- Dependency: `bw` CLI suggested (Snap), `cryptography` required.
