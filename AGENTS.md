# BwForgeCtl — SSH ↔ Bitwarden sync & Git account management

## Purpose & Objectives

Manage SSH key pairs and Git (GitHub/GitLab) credentials through a Bitwarden
vault — a single source of truth for SSH keys and git account configuration,
accessible from any device.

### Key Objectives

- **Bidirectional SSH key sync** — push local keys to the vault or pull vault
  keys to disk, with safe matching by fingerprint → item name → key body.
- **Git account lifecycle** — create new GitHub/GitLab accounts (generate SSH
  key, create BW login + SSH key items, print SSH config stanza).
- **Vault auditing** — detect duplicates, orphan logins/keys, missing fields,
  and naming convention violations.
- **SSH auth verification** — test `ssh -T` against configured hosts for every
  git account in the vault.
- **Robust Bitwarden transport** — CLI subprocess with 30s timeout, empty-stdin
  sentinel, SIGKILL detection, and auto-reauth; optional `bw serve` REST API.
- **Multiple credential backends** — OS keyring with encrypted-file fallback
  (PBKDF2-HMAC-SHA256 + Fernet AES).
- **Production packaging** — Debian `.deb`, GitHub Actions CI, `pip install`.
- **33 pytest tests** covering all core modules.

## Project Structure

```
bwforgectl/
├── bw_forge_ctl/       # Package (9 modules)
│   ├── cli.py          # argparse CLI, command dispatch, credential resolution
│   ├── bwclient.py     # Bitwarden CLI + REST transport, session health
│   ├── credentials.py  # Credential store (keyring / encrypted PBKDF2+Fernet)
│   ├── importer.py     # Sync logic (disk↔vault), dry-run support
│   ├── sshscan.py      # ~/.ssh key pair scanner, fingerprint via ssh-keygen
│   ├── gitacct.py      # Git account creation, audit, verification
│   ├── pgp.py          # PGP secure-note detection
│   ├── hostscan.py     # Host key scanning + fuzzy search
│   ├── __init__.py
│   └── __main__.py
├── tests/              # 63 pytest tests (fake_bw.py, conftest.py, 5 test modules)
├── docs/
│   ├── accounts.md     # Full GitHub/GitLab account inventory
│   ├── ssh-config.example  # SSH config host stanzas for all accounts
│   └── git-with-ssh.md # Multi-account git via SSH config
├── debian/             # Debian packaging
├── diagrams/           # 6 PlantUML diagrams
├── scripts/            # dev.sh, release.sh
├── .github/            # GitHub Actions release workflow
├── pyproject.toml      # Entry point: bwforgectl=bw_forge_ctl.cli:main
├── setup.py
├── README.md
├── DEVELOPER.md
└── AGENTS.md           # THIS FILE
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `bwforgectl credential store` | Persist BW credentials (keyring or encrypted file) |
| `bwforgectl credential forget` | Remove stored credentials |
| `bwforgectl host list` | List local SSH and GPG keys |
| `bwforgectl host search <q>` | Fuzzy-search local keys by fingerprint or name |
| `bwforgectl vault list` | List SSH / PGP keys in vault |
| `bwforgectl vault search <q>` | Fuzzy-search vault keys |
| `bwforgectl vault output` | Export vault keys to files or stdout |
| `bwforgectl vault delete` | Remove keys from vault |
| `bwforgectl account create` | Create new git account (key + BW items) |
| `bwforgectl account verify` | Verify accounts via SSH auth |
| `bwforgectl audit vault` | Audit vault for consistency issues |
| `bwforgectl sync` | Bidirectional sync (default: dry run) |
| `bwforgectl sync host` | Push local keys to vault |
| `bwforgectl sync vault` | Pull vault keys to disk |

## Account Management

### Naming Conventions

**SSH key files on disk:**
```
~/.ssh/id_ed25519-<registered-email>
```

**Bitwarden item names:**

| Type | Pattern | Example |
|------|---------|---------|
| Login | `git: <platform>: <account>` | `git: github: skp1964-dev` |
| SSH Key (type 5) | `id_ed25519-<email>` | `id_ed25519-skp1964.dev@outlook.com` |
| Token | `git: <platform>: <acct>: <type>` | `git: github: pilakkat1964: pat` |
| Self-hosted | `git: <hostname>: <user>` | `git: gitlab.pilakkat.freeddns.org: root` |

**SSH config hosts:**
- GitHub: `git.<account-name>.com`
- GitLab: `gitlab.<account-name>.com`
- Self-hosted: actual hostname

### Account Inventory

Full account inventory is maintained in `docs/accounts.md`.
SSH config stanzas are in `docs/ssh-config.example`.

### Known Issues

| # | Issue | Severity | Action |
|---|-------|----------|--------|
| 1 | `newbyc333` SSH key authenticates as skp1964-dev | 🔴 | Generate + register new key |
| 2 | `proteus` SSH key authenticates as skp64-pvtconfs/skp64prj-shared01 | 🔴 | Generate + register new key |
| 3 | `goofybits` SSH key authenticates as skp64prj-shared01 | 🔴 | Generate + register new key |
| 4 | `pilakkat` (GitLab) SSH key authenticates as skp64prj-shared01 | 🔴 | Generate + register new key |
| 5 | `skp64prj-hub01` has no SSH key | 🔴 | Generate + register key |
| 6 | `skp64-dev` has no SSH key | 🟡 | Generate + register key |
| 7 | Self-hosted GitLab instances have no SSH keys | 🟡 | Generate keys when reachable |
| 8 | Duplicate BW items (e.g., skp64prj-hub01 ×4) | 🟡 | Consolidate |
| 9 | Mystery `git: github: pilakkat` login | 🟡 | Verify if real account |

## Architecture

- **Entry point**: `bwforgectl` → `bw_forge_ctl.cli:main` → argparse dispatch.
- **Transport**: `BitwardenClient` wraps `bw` CLI or `bw serve` REST API.
- **Matching**: fingerprint → item name → private-key body.
- **Credential resolution**: CLI flags → env vars → keyring → prompt.
- **SSH key gen**: `ssh-keygen -t ed25519` via subprocess.
- **Auth verify**: `ssh -T git@<host>` via subprocess.

## 63 Tests

- 36 original tests (bwclient, credentials, importer, sshscan)
- 27 new gitacct tests (parsing, builds, integration with fake vault, audit)

## Packaging

- PyPI: `pip install bwforgectl`
- Debian: `dpkg-buildpackage -b -uc -us` → `../bwforgectl_*.deb`
- CI: GitHub Actions on `v*` tag → build .deb on ubuntu-24.04
- Release: `scripts/release.sh <version>`

## Remote

- Repo: `git@github.skp64-pvt01.com:skp64-pvt01/bwforgectl.git`

## Agent Handoff

When resuming work, provide:
1. This `AGENTS.md`
2. `docs/accounts.md` for account inventory
3. `docs/ssh-config.example` for SSH config
4. Bitwarden session (`bw unlock` + `export BW_SESSION`)
