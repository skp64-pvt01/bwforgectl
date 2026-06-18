# Developer guide

## Architecture overview

```
ssh_bw/
  cli.py          — argparse entry point, subcommand dispatch
  bwclient.py     — Bitwarden vault transport (CLI + REST)
  credentials.py  — Credential persistence (keyring + encrypted file)
  importer.py     — Sync orchestration (scan → match → create/update)
  sshscan.py      — Local ~/.ssh directory scanner
  pgp.py          — PGP note detection helper
  __init__.py     — Package metadata (__version__)
  __main__.py     — `python -m ssh_bw` shim

tests/
  conftest.py         — pytest fixtures
  test_bwclient.py    — BitwardenClient unit tests
  test_credentials.py — CredentialStore unit tests
  test_importer.py    — Importer unit tests
  test_sshscan.py     — SSH scanner unit tests
  test_helpers.py     — Shared constants
  fake_bw.py          — Fake `bw` CLI executable
  fake-bw             — Symlink/wrapper for fake_bw.py
  test_driver.sh      — End-to-end shell driver (fake vault)
  test_system.sh      — System test against real vault

scripts/
  import-ssh-to-bitwarden.sh  — Legacy shell-based importer
  bw-bash-completion.bash     — Bash completion for `bw`
  bw-zsh-comoletion.zsh       — Zsh completion for `bw`

debian/
  control       — Package metadata and dependencies
  rules         — debhelper + pybuild build rules
  copyright     — License file
  changelog     — Debian changelog
  source/format — Source package format 3.0 (native)
```

### Module dependency graph

```
cli.py
  ├─ bwclient.py  ←─ fake_bw.py (test double)
  ├─ credentials.py
  ├─ importer.py
  │    ├─ bwclient.py
  │    ├─ sshscan.py
  │    └─ pgp.py
  ├─ sshscan.py
  └─ pgp.py
```

No circular dependencies. Each module can be unit-tested independently through
its public API.

## Module design

### `sshscan.py` — Local key discovery

Scans a directory (default `~/.ssh`) for SSH key pairs. A file is recognised as
a private key when its first line matches one of the known PEM markers:

| Marker | Key type |
|--------|----------|
| `-----BEGIN OPENSSH PRIVATE KEY-----` | OpenSSH (ed25519, etc.) |
| `-----BEGIN RSA PRIVATE KEY-----` | RSA |
| `-----BEGIN DSA PRIVATE KEY-----` | DSA |
| `-----BEGIN EC PRIVATE KEY-----` | ECDSA |
| `-----BEGIN PRIVATE KEY-----` | PKCS#8 |
| `-----BEGIN ENCRYPTED PRIVATE KEY-----` | Encrypted PKCS#8 |

Files named `config`, `known_hosts`, `authorized_keys`, etc. are always
excluded. The public key is read from `<name>.pub`; if missing and
`derive_missing_public=True`, `ssh-keygen -y` is called to derive it (works
only for passphrase-less keys).

Fingerprints are computed via `ssh-keygen -lf`.

### `bwclient.py` — Bitwarden transport

Abstracts the `bw` CLI behind a Pythonic interface. Two transport modes:

**CLI mode** (default): Each method spawns `bw <args>` via `subprocess.run`.
Session keys are passed via `--session` flag and `BW_SESSION` env var.

**REST mode** (`--use-serve`): Starts `bw serve` as a background subprocess on
`localhost:<port>` and uses `urllib.request` to call the REST API. Auth still
uses the CLI path. Mode is transparent to callers — `list_items`, `create_item`,
`edit_item`, and `delete_item` dispatch to the right path automatically.

### Session health

The Bitwarden CLI sometimes invalidates sessions or prompts for the master
password when the session key is missing/stale.  `ssh-bw` handles this with
three mechanisms:

1. **`verify_session()`** — runs `bw status` and checks that the vault reports
   `"unlocked"` and that the client holds a non-`None` session key.
2. **`_ensure_vault_ready()`** — called at the top of every vault operation
   (`list_items`, `create_item`, `edit_item`, `delete_item`, `get_template`).
   If the session is invalid it attempts a silent re-authentication using the
   stored `email`/`password` fields.  If no credentials are available it raises
   a clear error pointing the user at `--session`, `--email`, or `--use-stored`.
3. **`_run()` timeout + empty stdin** — every `bw` subprocess call has a
   30-second timeout and an empty stdin sentinel (`input=""`).  If `bw` ever
   tries to prompt for a password interactively, the empty input causes it to
   fail quickly instead of hanging indefinitely.  A SIGKILL (exit -9) is
   detected and flagged in the error message.

### `credentials.py` — Secure credential storage

Two backends, auto-selected:

1. **Keyring** — Uses the `keyring` package to talk to the OS secret service.
   Nothing is written to disk.

2. **Encrypted file** (fallback) — Writes a JSON payload to
   `~/.config/ssh-bw/credentials.enc` (mode 0600). The encryption key is
   derived from a user-supplied store passphrase via PBKDF2-HMAC-SHA256
   (390 000 iterations, 16-byte random salt). Payload is AES-128 encrypted
   with Fernet.

The `CredentialStore` class is pure — it does not interact with the vault. The
CLI layer (`_resolve_credentials` in `cli.py`) decides the order of precedence:
CLI flags → env vars → credential store → interactive prompt.

### `importer.py` — Sync engine

Orchestrates the full sync cycle:

1. `scan_ssh_dir()` discovers local SSH key pairs.
2. `load_ssh_records()` fetches existing SSH key items from the vault.
3. For each local pair:
   - **Match** by fingerprint → item name → private key body.
   - If no match → **create** a new vault item.
   - If match and identical → **skip**.
   - If match and different → prompt (or auto-accept/decline based on
     `confirm_update` callback).

The matching strategy prioritises fingerprint as a stable identity across
re-keying. Name match handles prefix changes. Private-key body match catches
import-from-backup scenarios where all prior metadata is lost.

### `pgp.py` — PGP note detection

Heuristic: an item is a PGP note if it is a Bitwarden secure note (type 2) and
either its body starts with a PGP marker or its name contains "pgp"/"gpg".

### `cli.py` — Command-line interface

Uses `argparse` with subparsers. Design rules:

- **Global flags** (`--bw-path`, `--use-serve`, `--serve-port`, `--no-sync`)
  are on the root parser and come **before** the subcommand in `argv`.
- **Auth flags** (`--email`, `--password`, `--session`, `--use-stored`,
  `--store-passphrase`, `--config-dir`, `--no-keyring`, `--name-prefix`) are
  on each subparser (via `_add_auth_args`) and come **after** the subcommand.
- Each subparser has a `func=cmd_*` default that the `main()` dispatcher calls.
- Return codes: 0 success, 1 user error, 2 Bitwarden error, 130 SIGINT.

## Testing strategy

Three layers:

### 1. Unit tests (pytest) — 32 tests

Located in `tests/test_*.py`. Use `fake_bw.py` as a test double for the
Bitwarden CLI. The `conftest.py` fixtures provide:

- `fake_bw_path` — path to the fake `bw` executable
- `fake_vault` — a `tmp_path`-based JSON file read by `fake_bw.py`
- `ssh_dir` — a temporary `~/.ssh` replica with sample keys

```bash
pytest -v
```

### 2. Integration / driver test — 12 tests

`tests/test_driver.sh` runs the full `ssh_bw` CLI pipeline against the fake
`bw` backend (store → sync → list → output → re-sync → delete → verify).

```bash
bash tests/test_driver.sh
```

### 3. System test — 16 tests

`tests/test_system.sh` exercises every command against a **live** Bitwarden
vault. Creates a real SSH key, imports it, lists, exports, verifies content,
re-syncs, deletes, and confirms removal.  All vault items created by the test
are prefixed with `__SSH_BW_TEST__` and cleaned up on exit via an `EXIT` trap.

```bash
# Requires a real Bitwarden account; prompts for email/password
bash tests/test_system.sh
```

### Test doubles

`tests/fake_bw.py` is a minimal reimplementation of the `bw` CLI that:

- Stores vault state as a JSON file (`$FAKE_BW_VAULT`)
- Accepts `--session` (ignored), `--raw`, `--pretty`, `--response` flags
- Supports: `status`, `login`, `unlock`, `lock`, `sync`, `encode`,
  `get template item`, `list items [--search S]`, `create item <b64>`,
  `edit item <id> <b64>`, `delete item <id> [--permanent]`
- Uses UUIDs for item IDs and a fixed session key

## Packaging

### Debian package

```bash
sudo apt install devscripts debhelper dh-python python3-all python3-setuptools
dpkg-buildpackage -b -uc -us
```

Build output is `../ssh-bw_1.0.0-1_all.deb`. The package is format `3.0
(native)` — there is no separate upstream tarball.

The `debian/rules` file pins `PATH := /usr/bin:$(PATH)` to bypass pyenv or
other non-system Python installations.

### pip package

```bash
pip install build
python -m build
pip install dist/ssh_bw-1.0.0-py3-none-any.whl
```

## Code conventions

- Python 3.10+ with `from __future__ import annotations`
- Type hints on all public functions and methods
- No docstrings on internal helpers (single-line `#` comments only)
- Dataclasses for structured data (no `TypedDict` or `NamedTuple`)
- `Optional[X]` rather than `X | None` for Python 3.9 compatibility
- `_normalize()` strips trailing whitespace and blank lines for safe key
  comparison
- All subprocess calls use `subprocess.run()` (no `shell=True`) with a 30-second
  timeout and empty stdin sentinel to prevent hangs when `bw` prompts
  interactively.
- Exit code -9 (SIGKILL) from `bw` is detected in `_run()` and flagged with a
  diagnostic message about missing/invalid session keys.
- Error handling: custom exception hierarchy rooted in `BitwardenError`
  and `CredentialError`

## Progress reporting

All progress/status messages are printed to **stderr** so they never interfere
with `--json` output or piped stdout.  The `--quiet` global flag suppresses
them entirely.

Output examples:

```
$ ssh-bw sync --update
  logging in to Bitwarden …
  logged in
  scanning /home/user/.ssh …
  found 3 key pair(s) on disk
  loaded 2 SSH key record(s) from vault
  [1/3] processing id_ed25519 …
[unchanged] SSH: id_ed25519  (identical to vault entry)
  [2/3] processing id_rsa …
[created  ] SSH: id_rsa  (created new SSH key item)
  [3/3] processing id_ecdsa …
  Key 'id_ecdsa' differs from vault entry.
  Update the vault entry? [y/N]
```

```
$ ssh-bw --use-serve sync
  starting bw serve on 127.0.0.1:8087 …
  … waiting for bw serve (3s)
  … waiting for bw serve (7s)
  bw serve ready (8.2s)
```

How it works:

- **`BitwardenClient`** has a `_progress(msg)` method and a `quiet` field.
  Calls are placed in `start_serve()` (shows wait time dots), `ensure_session()`,
  `login()`, `unlock()`, `lock()`, and `sync()`.
- **`Importer`** delegates to `self.client.quiet` and reports scan counts,
  vault record counts, and per-key progress (`[N/M] processing …`).
- **`cli.py`** has a module-level `_progress(msg, quiet)` helper and adds
  progress in every command function (e.g. "scanning …", "loading items from
  vault …", "exporting N items …").
- **`--quiet`** is a global parser flag.  It is passed through to
  `BitwardenClient(quiet=True)` and surfaces everywhere via `client.quiet`.

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| `error: Not logged in and no email provided.` | No `--email`, no `BW_EMAIL`, and no stored credentials. |
| `error: Could not decrypt stored credentials` | Wrong `--store-passphrase` for encrypted-file backend. |
| `bw serve did not start in time.` | `bw serve` not available or port already in use. |
| `bw serve exited unexpectedly` | The `bw` binary is missing or broken. Check `bw --version`. |
| `bw list items failed (exit -9)` | `bw` was killed (SIGKILL) — usually because it tried to prompt for the master password. The session key is invalid or missing; `ssh-bw` now detects this and re-authenticates automatically. |
| `bw list items timed out` | `bw` likely tried to wait for interactive password input. `ssh-bw` now sends empty stdin and enforces a 30s timeout so this fails fast. |
| `Vault session is invalid or has expired` | The `--session` key or `BW_SESSION` env var is stale, and no credentials were provided for re-auth. Use `--email`/`--password` or `--use-stored`. |
| `Bitwarden CLI ('bw') not found` | The `bw` binary is not installed or not on PATH. Install it (`snap install bw`) or set `--bw-path`. |
| `BrokenPipeError` | Pipelines from Python to another tool (e.g., `grep`); Python handles this with default SIGPIPE. |
| Package build fails with `python3 not found` | System `python3` is not on `PATH`. Check `debian/rules`. |
| Progress output is unwanted in scripts | Pass `--quiet` to suppress all stderr progress messages. |
