# bwforgectl

Sync local SSH key pairs (and PGP notes) with a Bitwarden vault.

## Installation

### Debian package (Ubuntu 24.04+ / Debian)

```bash
sudo dpkg -i bwforgectl_1.0.0-1_all.deb
sudo apt install -f  # pull in dependencies
```

**Dependencies:** `python3-cryptography`, `openssh-client`; the `bw` CLI is a
separate install (`snap install bw` or manual download).

### pip (development)

```bash
pip install .
```

## Quick start

```bash
# 1. Store credentials (you will be prompted for email/password)
bwforgectl store-credentials

# 2. Scan ~/.ssh and import keys into the vault
bwforgectl sync --update

# 3. List vaulted SSH keys
bwforgectl list --type ssh
```

## CLI reference

Global flags appear **before** the subcommand; auth flags appear **after** it.

```
bwforgectl [global-opts] <command> [auth-opts] [command-opts]
```

### Global options

| Flag | Default | Description |
|------|---------|-------------|
| `--bw-path PATH` | `bw` | Path to the `bw` executable. |
| `--use-serve` | off | Use `bw serve` REST API (faster for bulk ops). |
| `--serve-port PORT` | `8087` | Port for `bw serve`. |
| `--no-sync` | off | Skip `bw sync` before vault operations. |
| `--quiet` | off | Suppress progress messages on stderr. |

### Auth / credential options

These are accepted by every vault subcommand and must appear **after** the
subcommand name.

| Flag | Description |
|------|-------------|
| `--email EMAIL` | Bitwarden account email. Falls back to `BW_EMAIL` env, then prompt. |
| `--password PASS` | Master password. Falls back to `BW_PASSWORD` env, then prompt. |
| `--session KEY` | Existing `BW_SESSION` to reuse (skips login/unlock). |
| `--use-stored` | Load credentials from the secure store. |
| `--store-passphrase PASS` | Passphrase for the encrypted-file credential store. |
| `--config-dir DIR` | Credential store directory (default `~/.config/bwforgectl`). |
| `--no-keyring` | Force encrypted-file backend even if OS keyring is available. |
| `--name-prefix PREFIX` | Prefix for vault item names (default `SSH: `). |

### Commands

#### `store-credentials`

Persist your Bitwarden email and master password in the OS keyring or an
encrypted file (auto-selected).

```bash
bwforgectl store-credentials --email user@example.com
```

If no `--password` is given you will be prompted. When the OS keyring is
unavailable you must provide `--store-passphrase` (or you will be prompted).

#### `forget-credentials`

Remove previously stored credentials.

```bash
bwforgectl forget-credentials
```

#### `sync`

Scan a directory (default `~/.ssh`) and import or update SSH keys in the
vault.  New keys are created; existing keys with matching content are skipped.

```bash
# Import keys interactively (offers to update changed keys)
bwforgectl sync --update

# Non-interactive: auto-accept updates
bwforgectl sync --update --yes

# Use a custom directory
bwforgectl sync --ssh-dir /etc/ssh

# Machine-readable JSON output
bwforgectl sync --json
```

**Flags:** `--ssh-dir DIR`, `--update`, `--yes`, `--no-derive`

#### `list`

List SSH keys and/or PGP notes stored in the vault.

```bash
bwforgectl list --type ssh        # SSH keys only
bwforgectl list --type pgp        # PGP notes only
bwforgectl list --type all        # both (default)
bwforgectl list --type ssh --json # JSON output
```

#### `output`

Write SSH keys or PGP notes to files or stdout.

```bash
# Write to files
bwforgectl output --type ssh --name id_ed25519 --out-dir ./export

# Print public key to stdout
bwforgectl output --type ssh --name id_ed25519

# Print both public and private keys
bwforgectl output --type ssh --name id_ed25519 --show-private

# Dump PGP notes
bwforgectl output --type pgp --out-dir ./export
```

#### `delete`

Remove an SSH record from the vault.

```bash
bwforgectl delete --name id_ed25519        # move to trash
bwforgectl delete --id <item-id>           # by vault item ID
bwforgectl delete --name id_ed25519 --permanent  # permanently delete
bwforgectl delete --name id_ed25519 --yes  # skip confirmation
```

## Credential storage

Credentials can be supplied fresh each session (CLI flags, env vars, or
prompts) or persisted with `store-credentials`.

- **OS keyring** (preferred): GNOME Keyring, KWallet, macOS Keychain, or
  Windows Credential Manager.  No plaintext data is written to disk.
- **Encrypted file** (fallback): stored in `~/.config/bwforgectl/credentials.enc`,
  encrypted with AES-128 (Fernet) using a key derived via PBKDF2-HMAC-SHA256
  (390 000 iterations). The store passphrase is never saved.

## PGP notes

`bwforgectl` can discover, list, and export PGP key material stored as Bitwarden
secure notes. A note is considered a PGP note when its body begins with a PGP
marker (`-----BEGIN PGP PRIVATE/PUBLIC KEY BLOCK-----`) or its name contains
"pgp" or "gpg".

## Transport modes

| Mode | Flag | Behaviour |
|------|------|-----------|
| **CLI** | *(default)* | Each operation spawns `bw <command>`. |
| **REST** | `--use-serve` | Starts `bw serve` locally and uses the REST API (faster for bulk operations). |

CLI mode always works. REST mode is faster when syncing many keys but requires
the `bw serve` subcommand (available in modern `bw` versions).

## Environment variables

| Variable | Overrides |
|----------|-----------|
| `BW_EMAIL` | `--email` |
| `BW_PASSWORD` | `--password` |
| `BW_SESSION` | `--session` |
| `BW_STORE_PASSPHRASE` | `--store-passphrase` |

## Scripts

The `scripts/` directory contains helper scripts:

- `import-ssh-to-bitwarden.sh` — legacy shell-based importer
- `bw-bash-completion.bash` — bash completion for the `bw` CLI
- `bw-zsh-comoletion.zsh` — zsh completion for the `bw` CLI

## License

MIT
