"""Command-line interface for bwforgectl.

Subcommand groups
-----------------
  bwforgectl credential store          Save Bitwarden credentials.
  bwforgectl credential forget         Remove stored credentials.
  bwforgectl host list                 List local SSH and GPG keys.
  bwforgectl host search <query>       Fuzzy-search local keys by fingerprint or name.
  bwforgectl vault list                List SSH / PGP keys in the Bitwarden vault.
  bwforgectl vault search <query>      Fuzzy-search vault keys.
  bwforgectl vault output              Export vault keys to files or stdout.
  bwforgectl vault delete              Remove keys from the vault.
  bwforgectl account create            Create a new git account (key + BW items).
  bwforgectl account verify            Verify git accounts via SSH auth.
  bwforgectl audit vault               Audit vault for consistency issues.
  bwforgectl config list               List Host stanzas in ~/.ssh/config.
  bwforgectl config show <host>        Show a specific Host stanza.
  bwforgectl config install            Add or update a Host stanza.
  bwforgectl config remove <host>      Remove a Host stanza.
  bwforgectl sync                      Bidirectional sync (interactive).
  bwforgectl sync host                 Push local keys to vault.
  bwforgectl sync vault                Pull vault keys to local disk.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Optional

from .bwclient import TYPE_SSH_KEY, BitwardenClient, BitwardenError
from .credentials import CredentialError, Credentials, CredentialStore
from .forge_api import ForgeAPI, forge_key_name, resolve_forge_token
from .gitacct import (
    AccountVerification,
    GPGKeyResult,
    audit_git_vault,
    create_git_account,
    generate_gpg_key,
    install_ssh_config_stanza,
    load_git_logins,
    load_git_ssh_keys,
    load_gpg_notes,
    parse_git_login_name,
    ssh_host_for_account,
    store_gpg_key_in_vault,
    try_ssh_auth,
    upload_gpg_key_to_forge,
    upload_ssh_key_to_forge,
)
from .ssh_config import (
    generate_git_stanza,
    list_stanzas,
    make_stanza,
    remove_stanza,
)
from .hostscan import (
    HostKeyEntry,
    format_table,
    fuzzy_match_host,
    fuzzy_match_vault,
    scan_host_keys,
)
from .importer import (
    ACTION_CREATED,
    SyncResult,
    ACTION_DECLINED,
    ACTION_SKIPPED,
    ACTION_UNCHANGED,
    ACTION_UPDATED,
    Importer,
    SSHRecord,
)
from .pgp import is_pgp_note
from .sshscan import SSHKeyPair

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _verbose_level(args: argparse.Namespace) -> int:
    if getattr(args, "quiet", False) or os.environ.get("BW_QUIET"):
        return 0
    return getattr(args, "verbose", 1)


def _no_sync(args: argparse.Namespace) -> bool:
    return getattr(args, "no_sync", False) or bool(os.environ.get("BW_NO_SYNC"))


def _progress(msg: str, verbose: int = 1, level: int = 1) -> None:
    if verbose >= level:
        print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Full help text (shown for bare `bwforgectl` or `bwforgectl -h`)
# --------------------------------------------------------------------------- #

FULL_HELP = r"""bwforgectl — Sync local SSH key pairs (and PGP notes) with a Bitwarden vault.

Usage:
  bwforgectl [GLOBAL-OPTS] <group> <command> [AUTH-OPTS] [CMD-OPTS]

Global options (appear before the group):
  --bw-path PATH      Path to the bw executable (env: BW_PATH, default: bw).
  --use-serve         Use 'bw serve' REST API (faster for bulk operations).
  --serve-port PORT   Port for 'bw serve' (env: SERVE_PORT, default: 8087).
  --no-sync           Skip 'bw sync' before each operation (env: BW_NO_SYNC).
  --quiet             Suppress progress/diagnostic output (env: BW_QUIET).
  -v, -vv, -vvv       Increase verbosity (default: -v).

Authentication options (after the group command; accepted by vault, sync, and
credential commands):
  --email EMAIL       Bitwarden email (env: BW_EMAIL).
  --password PASS     Master password (env: BW_PASSWORD).
  --session KEY       Existing bw session key (env: BW_SESSION).
  --use-stored        Load credentials from the OS keyring or encrypted file.
  --store-passphrase PASS  Passphrase for the encrypted credential store
                           (env: BW_STORE_PASSPHRASE).
  --config-dir DIR    Credential store directory (default: ~/.config/bwforgectl).
  --no-keyring        Force encrypted-file backend (ignore OS keyring).
  --name-prefix PREFIX  Prefix for vault item names (default: 'SSH: ').

Environment variables:
  BW_EMAIL, BW_PASSWORD, BW_SESSION, BW_STORE_PASSPHRASE,
  BW_PATH, BW_NO_SYNC, BW_QUIET, SERVE_PORT

───────────────────────────────────────────────────────────────────────────────
Groups & Commands
───────────────────────────────────────────────────────────────────────────────

  CREDENTIAL — manage stored Bitwarden credentials
  ──────────────────────────────────────────────────

    bwforgectl credential store
        Save your Bitwarden email and password to the OS keyring (or an
        encrypted file).  You will be prompted for any missing values.

        Options: --email, --password, --store-passphrase, --config-dir,
                 --no-keyring

    bwforgectl credential forget
        Remove previously stored credentials.

        Options: --config-dir, --no-keyring

   HOST — inspect local keys
   ──────────────────────────

     bwforgectl host list
         List SSH and GPG keys found on this machine.
         Shows SHA256 fingerprints by default.

         Options:
           --ssh        Show only SSH keys.
           --gpg        Show only GPG keys.
           --md5        Show MD5 fingerprints instead of SHA256.
           --json       Emit machine-readable JSON.

     bwforgectl host search <query>
         Fuzzy-search local keys by fingerprint (SHA256 by default) or name.
         Matches are case-insensitive and ignore colons / spaces / prefixes.

         Options:
           --md5        Match and display MD5 fingerprints only.
           --sha256     Match and display SHA256 fingerprints only.
           --json       Emit machine-readable JSON.

  VAULT — inspect and manage vault keys
  ──────────────────────────────────────

    bwforgectl vault list
        List SSH keys and/or PGP notes stored in the Bitwarden vault.

        Options:
          --ssh        Show only SSH keys.
          --gpg        Show only PGP/GPG notes.
          --json       Emit machine-readable JSON.
          (plus authentication options)

    bwforgectl vault search <query>
        Fuzzy-search vault SSH keys by fingerprint or name.

        Options:
          --md5        Match only against MD5 fingerprints.
          --sha256     Match only against SHA256 fingerprints.
          --json       Emit machine-readable JSON.
          (plus authentication options)

    bwforgectl vault output --name <name> [--out-dir <dir>]
        Export SSH keys or PGP notes from the vault to files or stdout.

        Options:
          --type TYPE          'ssh' (default) or 'gpg'.
          --name NAME          Only output items whose name contains this.
          --out-dir DIR        Write to files in this directory (else stdout).
          --show-private       Include the private key in stdout output.
          (plus authentication options)

    bwforgectl vault delete --name <name> [--id <id>]
        Remove an SSH key record from the vault (soft-delete by default).

        Options:
          --id ID          Vault item ID to delete.
          --name NAME      Item name (or bare key name without prefix).
          --permanent      Permanently purge (skip trash).
          --yes            Skip the interactive confirmation prompt.
          (plus authentication options)

   ACCOUNT — create and verify git accounts
   ─────────────────────────────────────────

     bwforgectl account create --platform <github|gitlab> --account-name <name> --email <email>
         Create a new git account: generate an SSH key, create Bitwarden
         login + SSH key items, and print the SSH config stanza.

         Options:
           --platform {github,gitlab}  Git platform (required).
           --account-name NAME         Account name, e.g. 'skp1964-dev' (required).
           --email EMAIL               Registered email (required).
           --username USER             Git platform username (default: email).
           --password PASS             Account password (stored in BW login).
           --totp KEY                  TOTP key (stored in BW login).
           --key-type {ed25519,rsa}   SSH key type (default: ed25519).
           --ssh-dir DIR               Directory for generated SSH key.
           --no-login                  Skip creating the BW login item.
           --no-ssh-key                Skip creating the BW SSH key item.
           --dry-run                   Report what would be done.
           (plus authentication options)

     bwforgectl account verify [--platform <p>] [--account-name <name>]
         Verify git accounts by testing SSH authentication against their
         configured hosts.  Cross-references BW login items with SSH keys.

         Options:
           --platform {github,gitlab}  Filter by platform.
           --account-name NAME         Filter by account name (substring).
           --json                      Emit machine-readable JSON.
           (plus authentication options)

   AUDIT — audit vault consistency
   ─────────────────────────────────

     bwforgectl audit vault
         Check the Bitwarden vault for consistency issues:
           • Duplicate login or SSH key items
           • Missing fields (passwords, key material)
           • Orphan logins without matching SSH keys
           • Orphan SSH keys without matching logins
           • Naming convention compliance

         Options:
           --json  Emit machine-readable JSON.
           (plus authentication options)

   SYNC — synchronise local keys with the vault
   ─────────────────────────────────────────────

    bwforgectl sync
        Bidirectional sync — push new local keys to the vault and pull
        vault-only keys to disk.  Conflicts are resolved interactively.

    bwforgectl sync host
        Push local SSH keys to the vault (host → vault).
        Only keys in ~/.ssh that are new or changed are uploaded.
        Without --yes, you are prompted before each update.

    bwforgectl sync vault
        Pull SSH keys from the vault to the local disk (vault → host).
        Only keys that are new or changed on disk are written.
        Without --yes, you are prompted before each overwrite.

        Options:
          --ssh-dir DIR     Directory for local keys (default: ~/.ssh).
          --yes             Auto-confirm all changes (non-interactive).
          --dry-run         Report what would change without applying it.
          (plus authentication options)

───────────────────────────────────────────────────────────────────────────────
Examples
───────────────────────────────────────────────────────────────────────────────

  bwforgectl credential store --email you@example.com
      Save credentials for later use.

  bwforgectl host list
      Show all SSH and GPG keys on this machine.

   bwforgectl host search "SHA256:abc123"
       Find a local key by its SHA256 fingerprint (default).

   bwforgectl host search --md5 "MD5:aa:bb:cc"
       Find a local SSH key by its MD5 fingerprint.

   bwforgectl host list --md5
       List local keys showing MD5 fingerprints instead of SHA256.

  bwforgectl vault list --ssh
      List every SSH key stored in the vault.

  bwforgectl vault search "ed25519"
      Fuzzy-search vault keys matching 'ed25519'.

  bwforgectl vault output --name github --out-dir ./export
      Extract a specific vault key to files.

  bwforgectl vault delete --name old-key --yes
      Remove an SSH key record from the vault without confirmation.

  bwforgectl sync --dry-run
      Preview bidirectional sync without making changes.

   bwforgectl sync host --yes
       Push all local keys to the vault, auto-confirming changes.

   bwforgectl sync vault --yes
       Pull all vault keys to local disk, auto-confirming overwrites.

   bwforgectl account create --platform github --account-name my-new-acct --email me@example.com
       Generate SSH key, create BW login + SSH key items for a new GitHub
       account.

   bwforgectl account verify
       Test SSH authentication for all git accounts in the vault.

   bwforgectl audit vault
       Run a full consistency audit of git accounts in the vault.
"""


def print_full_help(file=None):
    print(FULL_HELP, file=file or sys.stdout)


# --------------------------------------------------------------------------- #
# Credential resolution (shared)
# --------------------------------------------------------------------------- #


def _resolve_credentials(args: argparse.Namespace) -> Credentials:
    email = getattr(args, "email", None) or os.environ.get("BW_EMAIL")
    password = getattr(args, "password", None) or os.environ.get("BW_PASSWORD")

    should_try_store = bool(
        args.use_stored or os.environ.get("BW_STORE_PASSPHRASE")
    )
    store_failed = False
    store = None
    passphrase = None
    if (not password) and should_try_store:
        store = CredentialStore(args.config_dir, prefer_keyring=not args.no_keyring)
        if store.backend == "encrypted-file":
            passphrase = args.store_passphrase or os.environ.get("BW_STORE_PASSPHRASE")
            if not passphrase:
                passphrase = getpass.getpass("Credential store passphrase: ")
        try:
            stored = store.load(store_passphrase=passphrase)
            email = email or stored.email
            password = password or stored.password
        except CredentialError as exc:
            print(f"error: could not open credential store: {exc}", file=sys.stderr)
            store_failed = True

    prompted = False
    if not email:
        email = input("Bitwarden email: ").strip()
        prompted = True
    if not password:
        password = getpass.getpass("Bitwarden master password: ")
        prompted = True

    creds = Credentials(email=email, password=password)

    if store_failed and prompted and store is not None:
        answer = (
            input("Update the credential store with these credentials? [y/N] ")
            .strip()
            .lower()
        )
        if answer in {"y", "yes"}:
            p = args.store_passphrase or os.environ.get("BW_STORE_PASSPHRASE")
            if store.backend == "encrypted-file" and not p:
                p = getpass.getpass("Choose a credential-store passphrase: ")
                confirm = getpass.getpass("Confirm passphrase: ")
                if p != confirm:
                    print(
                        "error: passphrases do not match, store not updated",
                        file=sys.stderr,
                    )
                    return creds
            store.save(creds, store_passphrase=p)
            print(
                f"Credential store updated using the '{store.backend}' backend.",
                file=sys.stderr,
            )

    return creds


def _make_client(args: argparse.Namespace, *, need_auth: bool = True) -> BitwardenClient:
    verbose = _verbose_level(args)
    creds = _resolve_credentials(args) if need_auth else None
    bw_path = args.bw_path or os.environ.get("BW_PATH", "bw")
    serve_port = args.serve_port or int(os.environ.get("SERVE_PORT", 8087))
    client = BitwardenClient(
        bw_path=bw_path,
        session=args.session or os.environ.get("BW_SESSION"),
        use_serve=args.use_serve,
        serve_port=serve_port,
        verbose=verbose,
        email=creds.email if creds else None,
        password=creds.password if creds else None,
    )
    if need_auth and not client.session:
        client.ensure_session(creds.email, creds.password)
    if args.use_serve:
        client.start_serve()
    return client


# --------------------------------------------------------------------------- #
# Credential commands
# --------------------------------------------------------------------------- #


def cmd_credential_store(args: argparse.Namespace) -> int:
    store = CredentialStore(args.config_dir, prefer_keyring=not args.no_keyring)
    email = args.email or input("Bitwarden email: ").strip()
    password = args.password or getpass.getpass("Bitwarden master password: ")
    passphrase = None
    if store.backend == "encrypted-file":
        passphrase = args.store_passphrase or os.environ.get("BW_STORE_PASSPHRASE")
        if not passphrase:
            passphrase = getpass.getpass("Choose a credential-store passphrase: ")
            confirm = getpass.getpass("Confirm passphrase: ")
            if passphrase != confirm:
                print("error: passphrases do not match", file=sys.stderr)
                return 1
    store.save(Credentials(email=email, password=password), store_passphrase=passphrase)
    print(f"Credentials stored using the '{store.backend}' backend.")
    return 0


def cmd_credential_forget(args: argparse.Namespace) -> int:
    store = CredentialStore(args.config_dir, prefer_keyring=not args.no_keyring)
    removed = store.delete()
    print("Credentials removed." if removed else "No stored credentials found.")
    return 0


# --------------------------------------------------------------------------- #
# Host commands
# --------------------------------------------------------------------------- #


def cmd_host_list(args: argparse.Namespace) -> int:
    show_ssh = args.ssh or (not args.ssh and not args.gpg)
    show_gpg = args.gpg or (not args.ssh and not args.gpg)

    entries = scan_host_keys(
        args.ssh_dir, include_ssh=show_ssh, include_gpg=show_gpg
    )

    if not entries:
        print("No keys found on this host.")
        return 0

    if args.json:
        out = []
        for e in entries:
            out.append({
                "name": e.name,
                "type": e.key_type,
                "fingerprint_sha256": e.fingerprint_sha256,
                "fingerprint_md5": e.fingerprint_md5,
                "comment": e.comment,
                "encrypted": e.encrypted,
                "source": e.source_path,
            })
        print(json.dumps(out, indent=2))
        return 0

    # Build table — SHA256 by default, MD5 with --md5
    if getattr(args, "md5", False):
        fp_header = "FINGERPRINT (MD5)"
        def _fp(e): return e.fingerprint_md5 or "-"
    else:
        fp_header = "FINGERPRINT (SHA256)"
        def _fp(e):
            fp = e.fingerprint_sha256 or e.fingerprint or ""
            if len(fp) > 56:
                fp = fp[:53] + "..."
            return fp

    headers = ["TYPE", "NAME", fp_header, "COMMENT"]
    rows = []
    for e in entries:
        rows.append([
            e.key_type.upper(),
            e.name,
            _fp(e),
            e.comment or "-",
        ])

    print(format_table(headers, rows))
    print(f"\n{len(entries)} key(s) total")
    return 0


def cmd_host_search(args: argparse.Namespace) -> int:
    query = args.query
    if not query:
        print("error: provide a search query (fingerprint or name)", file=sys.stderr)
        return 1

    entries = scan_host_keys(args.ssh_dir)
    results = fuzzy_match_host(
        entries,
        query,
        prefer_md5=args.md5,
        prefer_sha256=args.sha256,
    )

    if not results:
        print(f"No keys matching '{query}' found on this host.")
        return 1

    if args.json:
        out = []
        for e in results:
            out.append({
                "name": e.name,
                "type": e.key_type,
                "fingerprint_sha256": e.fingerprint_sha256,
                "fingerprint_md5": e.fingerprint_md5,
                "comment": e.comment,
                "encrypted": e.encrypted,
                "source": e.source_path,
            })
        print(json.dumps(out, indent=2))
        return 0

    # Determine which fingerprint to show (SHA256 by default, MD5 with --md5)
    show_md5 = getattr(args, "md5", False)

    for e in results:
        print(f"  TYPE:       {e.key_type.upper()}")
        print(f"  NAME:       {e.name}")
        if e.key_type == "ssh":
            if show_md5:
                print(f"  MD5:        {e.fingerprint_md5 or '-'}")
            else:
                print(f"  SHA256:     {e.fingerprint_sha256 or '-'}")
            print(f"  ENCRYPTED:  {'yes' if e.encrypted else 'no'}")
        else:
            print(f"  FINGERPRINT:{e.fingerprint}")
        if e.comment:
            print(f"  COMMENT:    {e.comment}")
        print(f"  SOURCE:     {e.source_path}")
        print()

    print(f"{len(results)} match(es)")
    return 0


# --------------------------------------------------------------------------- #
# Vault commands
# --------------------------------------------------------------------------- #


def _cli_vault_setup(args: argparse.Namespace):
    """Common setup for vault commands: client, sync, importer."""
    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()
        importer = Importer(client, name_prefix=args.name_prefix)
        return client, importer
    except Exception:
        client.stop_serve()
        raise


def cmd_vault_list(args: argparse.Namespace) -> int:
    verbose = _verbose_level(args)
    show_ssh = args.ssh or (not args.ssh and not args.gpg)
    show_gpg = args.gpg or (not args.ssh and not args.gpg)

    client, importer = _cli_vault_setup(args)
    try:
        _progress("  loading items from vault …", verbose)
        ssh_records = importer.load_ssh_records() if show_ssh else []
        pgp_notes = importer.load_pgp_notes() if show_gpg else []
    finally:
        client.stop_serve()

    if args.json:
        out = {
            "ssh": [
                {"id": r.id, "name": r.name, "fingerprint": r.fingerprint}
                for r in ssh_records
            ],
            "gpg": [{"id": n.get("id"), "name": n.get("name")} for n in pgp_notes],
        }
        print(json.dumps(out, indent=2))
        return 0

    total = 0
    if show_ssh and ssh_records:
        print(f"SSH keys in vault ({len(ssh_records)}):")
        headers = ["NAME", "FINGERPRINT", "ITEM ID"]
        rows = []
        for r in ssh_records:
            fp = r.fingerprint or "-"
            rows.append([r.name, fp, r.id])
        print(format_table(headers, rows))
        total += len(ssh_records)

    if show_gpg and pgp_notes:
        if total > 0:
            print()
        print(f"PGP/GPG notes in vault ({len(pgp_notes)}):")
        headers = ["NAME", "ITEM ID"]
        rows = [[n.get("name", "-"), n.get("id", "-")] for n in pgp_notes]
        print(format_table(headers, rows))
        total += len(pgp_notes)

    if total == 0:
        print("No items found in the vault.")

    return 0


def cmd_vault_search(args: argparse.Namespace) -> int:
    query = args.query
    if not query:
        print("error: provide a search query (fingerprint or name)", file=sys.stderr)
        return 1

    client, importer = _cli_vault_setup(args)
    try:
        ssh_records = importer.load_ssh_records()
    finally:
        client.stop_serve()

    results = fuzzy_match_vault(
        ssh_records,
        query,
        prefer_md5=args.md5,
        prefer_sha256=args.sha256,
    )

    if not results:
        print(f"No vault SSH keys matching '{query}'.")
        return 1

    if args.json:
        out = [
            {"id": r.id, "name": r.name, "fingerprint": r.fingerprint}
            for r in results
        ]
        print(json.dumps(out, indent=2))
        return 0

    for r in results:
        print(f"  NAME:        {r.name}")
        print(f"  FINGERPRINT: {r.fingerprint or '-'}")
        print(f"  ITEM ID:     {r.id}")
        print()

    print(f"{len(results)} match(es)")
    return 0


def cmd_vault_output(args: argparse.Namespace) -> int:
    verbose = _verbose_level(args)
    client, importer = _cli_vault_setup(args)
    try:
        _progress(f"  exporting {args.type} items …", verbose)
        if args.type == "ssh":
            count = _output_ssh(importer, args)
        else:
            count = _output_gpg(importer, args)
    finally:
        client.stop_serve()

    if count == 0:
        print("No matching items found.", file=sys.stderr)
        return 1
    return 0


def _matches(name_filter: Optional[str], name: str) -> bool:
    return name_filter is None or name_filter.lower() in (name or "").lower()


def _output_ssh(importer: Importer, args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).expanduser() if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for rec in importer.load_ssh_records():
        if not _matches(args.name, rec.name):
            continue
        count += 1
        if out_dir:
            base = rec.name.replace(args.name_prefix, "").replace("/", "_") or rec.id
            (out_dir / base).write_text(rec.private_key)
            os.chmod(out_dir / base, 0o600)
            (out_dir / f"{base}.pub").write_text(rec.public_key)
            print(f"wrote {out_dir / base} and {out_dir / base}.pub")
        else:
            print(f"### {rec.name}  [{rec.fingerprint}]")
            print(rec.public_key.rstrip())
            if args.show_private:
                print(rec.private_key.rstrip())
            print()
    return count


def _output_gpg(importer: Importer, args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).expanduser() if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for note in importer.load_pgp_notes():
        if not _matches(args.name, note.get("name", "")):
            continue
        count += 1
        body = note.get("notes", "") or ""
        if out_dir:
            base = (note.get("name") or note.get("id")).replace("/", "_")
            path = out_dir / f"{base}.asc"
            path.write_text(body)
            print(f"wrote {path}")
        else:
            print(f"### {note.get('name')}")
            print(body.rstrip())
            print()
    return count


def cmd_vault_delete(args: argparse.Namespace) -> int:
    verbose = _verbose_level(args)
    identifier = args.id or args.name
    if not identifier:
        print("error: provide --id or --name", file=sys.stderr)
        return 1

    client, importer = _cli_vault_setup(args)
    try:
        _progress("  locating matching items …", verbose)
        records = importer.load_ssh_records()
        targets = [
            r
            for r in records
            if identifier in (r.id, r.name, r.fingerprint)
            or identifier == r.name.replace(args.name_prefix, "")
        ]
        if not targets:
            print("No matching SSH records found.", file=sys.stderr)
            return 1
        if not args.yes:
            for r in targets:
                print(f"  will delete: {r.name}  [{r.fingerprint}]  ({r.id})")
            if input("Proceed? [y/N] ").strip().lower() not in {"y", "yes"}:
                print("Aborted.")
                return 0
        _progress(f"  deleting {len(targets)} item(s) …", verbose)
        results = importer.delete_ssh(identifier, permanent=args.permanent)
    finally:
        client.stop_serve()

    for r in results:
        print(f"[deleted] {r.name}  ({r.detail})")
    return 0


# --------------------------------------------------------------------------- #
# Sync commands
# --------------------------------------------------------------------------- #


def _confirm_interactive(pair: SSHKeyPair, record) -> bool:
    print(
        f"\n  Key '{pair.name}' (fp {pair.fingerprint or '?'}) differs from "
        f"vault entry '{record.name}'."
    )
    answer = input("  Update the vault entry? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def _print_sync_results(results: list, json_mode: bool = False) -> None:
    """Print sync results in a human-readable or JSON format."""
    if json_mode:
        print(json.dumps([r.__dict__ for r in results], indent=2))
        return

    action_symbols = {
        ACTION_CREATED: "+",
        ACTION_UPDATED: "~",
        ACTION_UNCHANGED: " ",
        ACTION_SKIPPED: "-",
        ACTION_DECLINED: "!",
    }
    for r in results:
        sym = action_symbols.get(r.action, "?")
        print(f" {sym} {r.name:<48s} {r.detail}")

    counts: dict = {}
    for r in results:
        counts[r.action] = counts.get(r.action, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"\nDone. {summary or 'no keys found'}")


def cmd_sync_bidirectional(args: argparse.Namespace) -> int:
    """Bidirectional sync: push new/changed local keys, pull vault-only keys."""
    verbose = _verbose_level(args)
    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()

        importer = Importer(client, name_prefix=args.name_prefix)
        ssh_dir = args.ssh_dir or os.path.expanduser("~/.ssh")

        # Phase 1: host → vault
        _progress(f"  Phase 1: host → vault  (scanning {ssh_dir} …)", verbose)
        if args.dry_run:
            _progress("  dry-run mode — no changes will be written", verbose)

        confirm_host = _confirm_interactive if not args.yes else lambda p, r: True
        if args.dry_run:
            confirm_host = lambda p, r: False

        host_results = importer.sync_directory(
            ssh_dir,
            confirm_update=confirm_host,
            dry_run=args.dry_run,
        )

        # Phase 2: vault → host
        _progress(f"\n  Phase 2: vault → host", verbose)
        vault_results = importer.sync_from_server(
            ssh_dir,
            confirm_overwrite=args.yes,
            dry_run=args.dry_run,
        )
    finally:
        client.stop_serve()

    all_results = host_results + vault_results

    if args.json:
        print(json.dumps([r.__dict__ for r in all_results], indent=2))
        return 0

    _print_sync_results(all_results)
    return 0


def cmd_sync_host(args: argparse.Namespace) -> int:
    """Push local keys to vault (host → vault)."""
    verbose = _verbose_level(args)
    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()

        importer = Importer(client, name_prefix=args.name_prefix)
        ssh_dir = args.ssh_dir or os.path.expanduser("~/.ssh")
        _progress(f"  scanning {ssh_dir} …", verbose)

        if args.dry_run:
            _progress("  dry-run mode — no changes will be written", verbose)
            confirm = lambda p, r: False
        elif args.yes:
            confirm = lambda p, r: True
        else:
            confirm = _confirm_interactive

        results = importer.sync_directory(
            ssh_dir,
            confirm_update=confirm,
            dry_run=args.dry_run,
        )
    finally:
        client.stop_serve()

    if args.json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
        return 0

    _print_sync_results(results)
    return 0


def cmd_sync_vault(args: argparse.Namespace) -> int:
    """Pull vault keys to local disk (vault → host)."""
    verbose = _verbose_level(args)
    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()

        importer = Importer(client, name_prefix=args.name_prefix)
        ssh_dir = args.ssh_dir or os.path.expanduser("~/.ssh")
        _progress(f"  comparing vault keys against {ssh_dir} …", verbose)

        if args.dry_run:
            _progress("  dry-run mode — no files will be written", verbose)

        results = importer.sync_from_server(
            ssh_dir,
            confirm_overwrite=args.yes,
            dry_run=args.dry_run,
        )
    finally:
        client.stop_serve()

    if args.json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
        return 0

    _print_sync_results(results)
    return 0


def _print_gpg_sync_results(results: List[SyncResult]) -> None:
    for r in results:
        icon = {
            "created": "✓",
            "updated": "→",
            "unchanged": "=",
            "skipped": "~",
            "declined": "✗",
        }.get(r.action, "?")
        print(f"  {icon}  {r.name:<30s} {r.detail}")


def cmd_sync_gpg_host(args: argparse.Namespace) -> int:
    """Push local GPG keys to Bitwarden vault."""
    verbose = _verbose_level(args)
    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()

        importer = Importer(client, name_prefix=args.name_prefix)
        _progress("  scanning local GPG keyring …", verbose)

        results = importer.sync_gpg_to_vault(
            dry_run=args.dry_run,
        )
    finally:
        client.stop_serve()

    if args.json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
        return 0

    _print_gpg_sync_results(results)
    return 0


def cmd_sync_gpg_vault(args: argparse.Namespace) -> int:
    """Pull GPG keys from vault to local ``.asc`` files."""
    verbose = _verbose_level(args)
    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()

        importer = Importer(client, name_prefix=args.name_prefix)
        gpg_dir = args.gpg_dir or os.path.expanduser("~/.ssh")
        _progress(f"  comparing vault GPG notes against {gpg_dir} …", verbose)

        results = importer.sync_gpg_from_vault(
            gpg_dir,
            dry_run=args.dry_run,
        )
    finally:
        client.stop_serve()

    if args.json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
        return 0

    _print_gpg_sync_results(results)
    return 0


# --------------------------------------------------------------------------- #
# Account commands
# --------------------------------------------------------------------------- #


def cmd_account_create(args: argparse.Namespace) -> int:
    """Create a new git account: generate SSH key + create BW items."""
    platform = args.platform
    account_name = args.account_name
    email = args.email
    verbose = _verbose_level(args)

    if not email:
        print("error: --email is required", file=sys.stderr)
        return 1
    if not account_name:
        print("error: --account-name is required", file=sys.stderr)
        return 1

    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()

        _progress(f"  creating {platform} account '{account_name}' …", verbose)

        result = create_git_account(
            client,
            platform=platform,
            account_name=account_name,
            email=email,
            username=args.username or "",
            password=args.password or "",
            totp=args.totp or "",
            key_type=args.key_type,
            ssh_dir=args.ssh_dir,
            skip_login=args.no_login,
            skip_ssh_key=args.no_ssh_key,
            dry_run=args.dry_run,
        )

        if result.errors:
            for err in result.errors:
                print(f"error: {err}", file=sys.stderr)
            return 1

        if args.dry_run:
            key_name = f"id_ed25519-{email}"
            print(f"[dry-run] Would generate SSH key:  {key_name}")
            if not args.no_login:
                print(f"[dry-run] Would create login item: git: {platform}: {account_name}")
            if not args.no_ssh_key:
                print(f"[dry-run] Would create SSH key item: {key_name}")
            return 0

        print(f"\n  Account:       {platform}/{account_name}")
        print(f"  Email:         {email}")
        print(f"  SSH key:       {result.key_name}")
        print(f"  Fingerprint:   {result.key_fingerprint}")
        print(f"  Login item:    git: {platform}: {account_name}  (id: {result.login_item_id or 'skipped'})")
        print(f"  SSH key item:  {result.key_name}  (id: {result.ssh_key_item_id or 'skipped'})")
        print()
        print(f"  Public key to register on {platform}:")
        print(f"    {result.public_key}")
        print()
        if args.install_config:
            install_ssh_config_stanza(platform, account_name, result.key_name,
                                      ssh_config_path=args.ssh_config)
            print(f"  Installed stanza in SSH config.")
        else:
            print(f"  Add to ~/.ssh/config:")
            print(result.config_stanza)

    finally:
        client.stop_serve()

    return 0


def cmd_account_verify(args: argparse.Namespace) -> int:
    """Verify git accounts by testing SSH authentication."""
    verbose = _verbose_level(args)

    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()

        _progress("  loading git login items from vault …", verbose)
        logins = load_git_logins(client)
        ssh_keys = load_git_ssh_keys(client)

        if not logins:
            print("No git login items found in vault.")
            return 0

        results: List[AccountVerification] = []

        for item in logins:
            name = str(item.get("name", ""))
            parsed = parse_git_login_name(name)
            if not parsed:
                continue

            platform = parsed["platform"]
            account_name = parsed["account_name"]
            login = item.get("login") or {}
            email = login.get("username", "")

            # Find matching SSH key
            matching_keys = [
                k for k in ssh_keys
                if account_name.lower() in k.name.lower()
                or email.lower() in k.name.lower()
            ]

            # Filter by --platform / --account-name
            if args.platform and args.platform.lower() != platform.lower():
                continue
            if args.account_name and args.account_name.lower() not in account_name.lower():
                continue

            ssh_key_name = matching_keys[0].name if matching_keys else "(none)"
            ssh_host = ssh_host_for_account(platform, account_name)

            ver = AccountVerification(
                platform=platform,
                account_name=account_name,
                email=email,
                ssh_key_name=ssh_key_name,
                ssh_host=ssh_host,
            )

            if matching_keys:
                _progress(f"  testing SSH auth for {platform}/{account_name} → {ssh_host} …", verbose)
                ok, detail = try_ssh_auth(ssh_host)
                ver.auth_ok = ok
                if not ok:
                    ver.error = detail
            else:
                ver.auth_ok = None
                ver.error = "No matching SSH key in vault"

            results.append(ver)

        if not results:
            print("No matching accounts found.")
            return 1

        if args.json:
            print(json.dumps([
                {
                    "platform": r.platform,
                    "account_name": r.account_name,
                    "email": r.email,
                    "ssh_key_name": r.ssh_key_name,
                    "ssh_host": r.ssh_host,
                    "auth_ok": r.auth_ok,
                    "error": r.error,
                }
                for r in results
            ], indent=2))
            return 0

        for r in results:
            status = "✅" if r.auth_ok else ("❌" if r.auth_ok is False else "⚠️")
            print(f"  {status}  {r.platform:8s} {r.account_name:<24s} {r.email:<30s}  {r.ssh_key_name}")
            if r.error:
                print(f"          {r.error}")

    finally:
        client.stop_serve()

    return 0


# --------------------------------------------------------------------------- #
# Audit commands
# --------------------------------------------------------------------------- #


def cmd_audit_vault(args: argparse.Namespace) -> int:
    """Audit the Bitwarden vault for git account consistency."""
    verbose = _verbose_level(args)

    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()

        _progress("  auditing vault …", verbose)
        report = audit_git_vault(client)

        if args.json:
            print(json.dumps([
                {
                    "severity": f.severity,
                    "category": f.category,
                    "message": f.message,
                    "item_id": f.item_id,
                    "item_name": f.item_name,
                    "detail": f.detail,
                }
                for f in report.findings
            ], indent=2))
            return 0

        if report.total == 0:
            print("No issues found. Vault is consistent.")
            return 0

        for severity, label in [("error", "ERRORS"), ("warning", "WARNINGS"), ("info", "INFO")]:
            items = [f for f in report.findings if f.severity == severity]
            if not items:
                continue
            print(f"\n{label} ({len(items)}):")
            print("─" * 60)
            for f in items:
                tag = f.item_name or f.item_id or ""
                print(f"  [{f.category}] {f.message}")
                if tag:
                    print(f"           item: {tag}")

        print(f"\nTotal: {report.total} finding(s) — {len(report.errors)} error(s), {len(report.warnings)} warning(s), {len(report.infos)} info(s)")

    finally:
        client.stop_serve()

    return 1 if report.errors else 0


# --------------------------------------------------------------------------- #
# SSH config commands
# --------------------------------------------------------------------------- #


def cmd_config_list(args: argparse.Namespace) -> int:
    """List all Host stanzas in ~/.ssh/config."""
    stanzas = list_stanzas(args.ssh_config)

    if args.json:
        print(json.dumps([
            {
                "hosts": s.hosts,
                "options": [{"key": k, "value": v} for k, v in s.options],
            }
            for s in stanzas
        ], indent=2))
        return 0

    if not stanzas:
        print("No Host stanzas found in SSH config.")
        return 0

    print(f"  SSH config: {args.ssh_config or '~/.ssh/config'}")
    for s in stanzas:
        host_str = " ".join(s.hosts)
        identity = ""
        for k, v in s.options:
            if k.lower() == "identityfile":
                identity = v
                break
        hostname = ""
        for k, v in s.options:
            if k.lower() == "hostname":
                hostname = v
                break
        extra = f"  → {hostname}" if hostname else ""
        extra += f"  [{identity}]" if identity else ""
        print(f"    Host {host_str}{extra}")
    return 0


def cmd_config_show(args: argparse.Namespace) -> int:
    """Show a specific Host stanza."""
    stanzas = list_stanzas(args.ssh_config)
    host = args.host

    for s in stanzas:
        if s.hosts and s.hosts[0].lower() == host.lower():
            if args.json:
                print(json.dumps({
                    "hosts": s.hosts,
                    "options": [{"key": k, "value": v} for k, v in s.options],
                    "raw": s.raw,
                }, indent=2))
                return 0
            print(s.raw.rstrip())
            return 0

    print(f"No stanza found for host '{host}'.", file=sys.stderr)
    return 1


def cmd_config_install(args: argparse.Namespace) -> int:
    """Install (add or update) an SSH config stanza."""
    if args.platform and args.account_name and args.key_name:
        stanza = generate_git_stanza(
            args.platform, args.account_name, args.key_name,
        )
    elif args.host and args.hostname:
        stanza = make_stanza(
            host=args.host,
            hostname=args.hostname,
            user=args.user or "git",
            identity_file=args.identity_file or "",
            add_keys_to_agent=not args.no_add_keys_to_agent,
            identities_only=not args.no_identities_only,
            forward_agent=args.forward_agent,
            comment=args.comment or "",
        )
    else:
        print(
            "error: specify either --platform/--account-name/--key-name "
            "or --host/--hostname",
            file=sys.stderr,
        )
        return 1

    from .ssh_config import add_stanza as _add_stanza

    added = _add_stanza(stanza, path=args.ssh_config)
    if added:
        print(f"  Added Host stanza '{stanza.hosts[0]}' to SSH config.")
    else:
        print(f"  Updated Host stanza '{stanza.hosts[0]}' in SSH config.")
    return 0


def cmd_config_remove(args: argparse.Namespace) -> int:
    """Remove a Host stanza from SSH config."""
    if remove_stanza(args.host, path=args.ssh_config):
        print(f"  Removed Host stanza '{args.host}' from SSH config.")
        return 0
    print(f"No stanza found for host '{args.host}'.", file=sys.stderr)
    return 1


# --------------------------------------------------------------------------- #
# Key management commands
# --------------------------------------------------------------------------- #


def _resolve_key_token(args: argparse.Namespace, client: BitwardenClient) -> str:
    """Resolve a forge API token from args, env, or vault lookup."""
    token = args.token or os.environ.get("FORGE_TOKEN") or ""
    if not token and args.platform and args.account_name:
        token = resolve_forge_token(client, args.platform, args.account_name) or ""
    if not token:
        print("error: no forge API token available", file=sys.stderr)
        print("  Provide via --token, FORGE_TOKEN env var,", file=sys.stderr)
        print("  or store a Bitwarden login item named", file=sys.stderr)
        print(f"  'git: {args.platform}: {args.account_name}: pat'", file=sys.stderr)
        raise SystemExit(1)
    return token


def cmd_key_upload_ssh(args: argparse.Namespace) -> int:
    """Upload an SSH public key to a forge platform."""
    verbose = _verbose_level(args)
    client = _make_client(args)
    try:
        token = _resolve_key_token(args, client)
        if args.key_file:
            key_text = Path(args.key_file).read_text(encoding="utf-8").strip()
        else:
            print("error: --key-file is required", file=sys.stderr)
            return 1

        _progress(f"  uploading SSH key to {args.platform} …", verbose)
        result = upload_ssh_key_to_forge(
            args.platform, token, args.account_name, key_text,
            key_title=args.key_title,
            replace_existing=args.replace,
        )
        print(f"  SSH key upload: {result['status']} (id={result['key_id']})")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.stop_serve()


def cmd_key_upload_gpg(args: argparse.Namespace) -> int:
    """Upload an armored GPG public key to a forge platform."""
    verbose = _verbose_level(args)
    client = _make_client(args)
    try:
        token = _resolve_key_token(args, client)
        if args.key_file:
            key_text = Path(args.key_file).read_text(encoding="utf-8").strip()
        else:
            print("error: --key-file is required", file=sys.stderr)
            return 1

        _progress(f"  uploading GPG key to {args.platform} …", verbose)
        result = upload_gpg_key_to_forge(
            args.platform, token, args.account_name, key_text,
            replace_existing=args.replace,
        )
        print(f"  GPG key upload: {result['status']} (id={result['key_id']})")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.stop_serve()


def cmd_key_generate_gpg(args: argparse.Namespace) -> int:
    """Generate a new GPG key pair, optionally store in vault and upload."""
    verbose = _verbose_level(args)
    client = _make_client(args) if args.store or args.upload else None

    try:
        name = args.name or args.email
        _progress(f"  generating GPG key for '{name} <{args.email}>' …", verbose)
        result = generate_gpg_key(
            name=name or args.email,
            email=args.email,
            key_type=args.key_type,
        )

        if result.errors:
            for err in result.errors:
                print(f"error: {err}", file=sys.stderr)
            return 1

        print()
        print(f"  GPG key generated:")
        print(f"    Fingerprint:  {result.fingerprint}")
        print(f"    Key ID:       {result.key_id}")
        print(f"    Email:        {result.email}")
        print()

        if args.store and client:
            _progress("  storing in Bitwarden vault …", verbose)
            item_id = store_gpg_key_in_vault(client, result)
            if item_id:
                print(f"  Stored in vault: gpg: {result.email} (id={item_id})")
            else:
                print("warning: failed to store GPG key in vault", file=sys.stderr)

        if args.upload and client:
            token = _resolve_key_token(args, client)
            _progress(f"  uploading GPG key to {args.platform} …", verbose)
            up_result = upload_gpg_key_to_forge(
                args.platform, token, args.account_name,
                result.public_key_armored,
                replace_existing=args.replace,
            )
            print(f"  GPG key upload: {up_result['status']} (id={up_result['key_id']})")

    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if client:
            client.stop_serve()

    return 0


# --------------------------------------------------------------------------- #
# Argument parser
# --------------------------------------------------------------------------- #


def _add_ssh_config_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ssh-config",
        help="Path to SSH config file (default: ~/.ssh/config).",
    )


def _add_auth_args(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group("authentication / credentials")
    g.add_argument("--email", help="Bitwarden account email (env: BW_EMAIL).")
    g.add_argument(
        "--password",
        help="Master password (env: BW_PASSWORD).",
    )
    g.add_argument(
        "--session",
        help="Existing bw session key to reuse (env: BW_SESSION).",
    )
    g.add_argument(
        "--use-stored",
        action="store_true",
        help="Load credentials from OS keyring or encrypted file.",
    )
    g.add_argument(
        "--store-passphrase",
        help="Passphrase for encrypted credential file (env: BW_STORE_PASSPHRASE).",
    )
    g.add_argument(
        "--config-dir",
        help="Credential store directory (default: ~/.config/bwforgectl).",
    )
    g.add_argument(
        "--no-keyring",
        action="store_true",
        help="Force encrypted-file backend instead of OS keyring.",
    )
    g.add_argument(
        "--name-prefix",
        default="SSH: ",
        help="Prefix for SSH key item names in the vault (default: 'SSH: ').",
    )


def _add_sync_opts(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ssh-dir",
        help="Directory to scan for local keys (default: ~/.ssh).",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Auto-confirm all changes (non-interactive).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without applying changes.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bwforgectl",
        description="Sync local SSH key pairs (and PGP notes) with a Bitwarden vault.",
        add_help=False,  # we handle help ourselves
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --help flag
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        default=False,
        help="Show full help and exit.",
    )

    # Global options
    g_global = parser.add_argument_group("global options (before the group)")
    g_global.add_argument(
        "--bw-path",
        default="bw",
        help="Path to the bw executable (env: BW_PATH, default: bw).",
    )
    g_global.add_argument(
        "--use-serve",
        action="store_true",
        help="Use 'bw serve' REST API (faster for bulk operations).",
    )
    g_global.add_argument(
        "--serve-port",
        type=int,
        default=8087,
        help="Port for 'bw serve' (env: SERVE_PORT, default: 8087).",
    )
    g_global.add_argument(
        "--no-sync",
        action="store_true",
        help="Skip 'bw sync' before each operation (env: BW_NO_SYNC).",
    )
    g_global.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress/diagnostic output (env: BW_QUIET).",
    )
    g_global.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=1,
        help="Increase verbosity: -v = normal (default), -vv = diagnostics, -vvv = debug.",
    )

    # Groups
    sub = parser.add_subparsers(dest="group")

    # === credential ===
    p_cred = sub.add_parser("credential", help="Manage stored Bitwarden credentials.")
    cred_sub = p_cred.add_subparsers(dest="cred_cmd")

    p_store = cred_sub.add_parser("store", help="Save credentials to OS keyring or encrypted file.")
    _add_auth_args(p_store)
    p_store.set_defaults(func=cmd_credential_store)

    p_forget = cred_sub.add_parser("forget", help="Remove stored credentials.")
    _add_auth_args(p_forget)
    p_forget.set_defaults(func=cmd_credential_forget)

    # === host ===
    p_host = sub.add_parser("host", help="Inspect local SSH and GPG keys.")
    host_sub = p_host.add_subparsers(dest="host_cmd")

    p_host_list = host_sub.add_parser("list", help="List local SSH and GPG keys.")
    p_host_list.add_argument("--ssh-dir", help="Directory for SSH keys (default: ~/.ssh).")
    g = p_host_list.add_mutually_exclusive_group()
    g.add_argument("--ssh", action="store_true", help="Show only SSH keys.")
    g.add_argument("--gpg", action="store_true", help="Show only GPG keys.")
    p_host_list.add_argument("--md5", action="store_true", help="Show MD5 fingerprints instead of SHA256.")
    p_host_list.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_host_list.set_defaults(func=cmd_host_list)

    p_host_search = host_sub.add_parser("search", help="Fuzzy-search local keys by fingerprint or name.")
    p_host_search.add_argument("query", nargs="?", help="Fingerprint fragment or name to search for.")
    p_host_search.add_argument("--ssh-dir", help="Directory for SSH keys (default: ~/.ssh).")
    g2 = p_host_search.add_mutually_exclusive_group()
    g2.add_argument("--md5", action="store_true", help="Match against MD5 fingerprints only.")
    g2.add_argument("--sha256", action="store_true", help="Match against SHA256 fingerprints only.")
    p_host_search.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_host_search.set_defaults(func=cmd_host_search)

    # === vault ===
    p_vault = sub.add_parser("vault", help="Inspect and manage vault keys.")
    vault_sub = p_vault.add_subparsers(dest="vault_cmd")

    p_vault_list = vault_sub.add_parser("list", help="List SSH and/or PGP keys in the vault.")
    _add_auth_args(p_vault_list)
    g3 = p_vault_list.add_mutually_exclusive_group()
    g3.add_argument("--ssh", action="store_true", help="Show only SSH keys.")
    g3.add_argument("--gpg", action="store_true", help="Show only PGP/GPG notes.")
    p_vault_list.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_vault_list.set_defaults(func=cmd_vault_list)

    p_vault_search = vault_sub.add_parser("search", help="Fuzzy-search vault SSH keys.")
    p_vault_search.add_argument("query", nargs="?", help="Fingerprint fragment or name to search for.")
    _add_auth_args(p_vault_search)
    g4 = p_vault_search.add_mutually_exclusive_group()
    g4.add_argument("--md5", action="store_true", help="Match against MD5 fingerprints only.")
    g4.add_argument("--sha256", action="store_true", help="Match against SHA256 fingerprints only.")
    p_vault_search.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_vault_search.set_defaults(func=cmd_vault_search)

    p_vault_output = vault_sub.add_parser("output", help="Export vault keys to files or stdout.")
    _add_auth_args(p_vault_output)
    p_vault_output.add_argument("--type", choices=["ssh", "gpg"], default="ssh", help="Type (default: ssh).")
    p_vault_output.add_argument("--name", help="Only output items whose name contains this substring.")
    p_vault_output.add_argument("--out-dir", help="Write keys to files in this directory (else stdout).")
    p_vault_output.add_argument("--show-private", action="store_true", help="Include private key in stdout output.")
    p_vault_output.set_defaults(func=cmd_vault_output)

    p_vault_delete = vault_sub.add_parser("delete", help="Delete SSH key records from the vault.")
    _add_auth_args(p_vault_delete)
    p_vault_delete.add_argument("--id", help="Vault item ID to delete.")
    p_vault_delete.add_argument("--name", help="Item name (or bare key name without prefix).")
    p_vault_delete.add_argument("--permanent", action="store_true", help="Permanently purge (skip trash).")
    p_vault_delete.add_argument("--yes", action="store_true", help="Skip confirmation prompt.")
    p_vault_delete.set_defaults(func=cmd_vault_delete)

    # === account ===
    p_acct = sub.add_parser("account", help="Create and verify git accounts.")
    acct_sub = p_acct.add_subparsers(dest="acct_cmd")

    p_acct_create = acct_sub.add_parser("create", help="Create a new git account with SSH key + vault items.")
    _add_ssh_config_arg(p_acct_create)
    g_acct_auth = p_acct_create.add_argument_group("authentication / credentials")
    g_acct_auth.add_argument("--session", help="Existing bw session key to reuse (env: BW_SESSION).")
    g_acct_auth.add_argument("--use-stored", action="store_true",
                             help="Load credentials from OS keyring or encrypted file.")
    g_acct_auth.add_argument("--store-passphrase",
                             help="Passphrase for encrypted credential file (env: BW_STORE_PASSPHRASE).")
    g_acct_auth.add_argument("--config-dir", help="Credential store directory (default: ~/.config/bwforgectl).")
    g_acct_auth.add_argument("--no-keyring", action="store_true",
                             help="Force encrypted-file backend instead of OS keyring.")
    p_acct_create.add_argument("--platform", required=True, choices=["github", "gitlab"], help="Git platform.")
    p_acct_create.add_argument("--account-name", required=True, help="Account name (e.g., skp1964-dev).")
    p_acct_create.add_argument("--email", required=True, help="Registered email for the account.")
    p_acct_create.add_argument("--username", help="Git platform username (defaults to email).")
    p_acct_create.add_argument("--password", help="Account password (stored in BW login).")
    p_acct_create.add_argument("--totp", help="TOTP key (stored in BW login).")
    p_acct_create.add_argument("--key-type", choices=["ed25519", "rsa"], default="ed25519", help="SSH key type (default: ed25519).")
    p_acct_create.add_argument("--ssh-dir", help="SSH key directory (default: ~/.ssh).")
    p_acct_create.add_argument("--no-login", action="store_true", help="Skip creating login item.")
    p_acct_create.add_argument("--no-ssh-key", action="store_true", help="Skip creating SSH key item.")
    p_acct_create.add_argument("--dry-run", action="store_true", help="Report what would be done.")
    p_acct_create.add_argument("--install-config", action="store_true",
                               help="Install the SSH config stanza automatically.")
    p_acct_create.set_defaults(func=cmd_account_create)

    p_acct_verify = acct_sub.add_parser("verify", help="Verify git accounts via SSH authentication.")
    _add_auth_args(p_acct_verify)
    p_acct_verify.add_argument("--platform", choices=["github", "gitlab"], help="Filter by platform.")
    p_acct_verify.add_argument("--account-name", help="Filter by account name (substring match).")
    p_acct_verify.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_acct_verify.set_defaults(func=cmd_account_verify)

    # === audit ===
    p_audit = sub.add_parser("audit", help="Audit vault consistency for git accounts.")
    audit_sub = p_audit.add_subparsers(dest="audit_cmd")

    p_audit_vault = audit_sub.add_parser("vault", help="Audit Bitwarden vault for consistency issues.")
    _add_auth_args(p_audit_vault)
    p_audit_vault.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_audit_vault.set_defaults(func=cmd_audit_vault)

    # === config ===
    p_cfg = sub.add_parser("config", help="Manage ~/.ssh/config Host stanzas.")
    cfg_sub = p_cfg.add_subparsers(dest="cfg_cmd")

    p_cfg_list = cfg_sub.add_parser("list", help="List all Host stanzas.")
    _add_ssh_config_arg(p_cfg_list)
    p_cfg_list.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_cfg_list.set_defaults(func=cmd_config_list)

    p_cfg_show = cfg_sub.add_parser("show", help="Show a specific Host stanza.")
    _add_ssh_config_arg(p_cfg_show)
    p_cfg_show.add_argument("host", help="Host pattern to show.")
    p_cfg_show.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_cfg_show.set_defaults(func=cmd_config_show)

    p_cfg_install = cfg_sub.add_parser(
        "install",
        help="Add or update a Host stanza.",
    )
    _add_ssh_config_arg(p_cfg_install)
    g_cfg = p_cfg_install.add_argument_group("stanza options (git account)")
    g_cfg.add_argument("--platform", choices=["github", "gitlab"],
                       help="Git platform (use with --account-name and --key-name).")
    g_cfg.add_argument("--account-name", help="Account name for git stanza.")
    g_cfg.add_argument("--key-name", help="SSH key filename for git stanza.")
    g_cfg2 = p_cfg_install.add_argument_group("stanza options (manual)")
    g_cfg2.add_argument("--host", help="Host pattern.")
    g_cfg2.add_argument("--hostname", help="Actual hostname (HostName).")
    g_cfg2.add_argument("--user", default="git", help="SSH user (default: git).")
    g_cfg2.add_argument("--identity-file", help="Path to identity file.")
    g_cfg2.add_argument("--no-add-keys-to-agent", action="store_true",
                        help="Omit AddKeysToAgent yes.")
    g_cfg2.add_argument("--no-identities-only", action="store_true",
                        help="Omit IdentitiesOnly yes.")
    g_cfg2.add_argument("--forward-agent", action="store_true",
                        help="Add ForwardAgent yes.")
    g_cfg2.add_argument("--comment", help="Comment line above the stanza.")
    p_cfg_install.set_defaults(func=cmd_config_install)

    p_cfg_remove = cfg_sub.add_parser("remove", help="Remove a Host stanza.")
    _add_ssh_config_arg(p_cfg_remove)
    p_cfg_remove.add_argument("host", help="Host pattern to remove.")
    p_cfg_remove.set_defaults(func=cmd_config_remove)

    # === key ===
    p_key = sub.add_parser("key", help="Manage SSH and GPG keys on forge platforms.")
    key_sub = p_key.add_subparsers(dest="key_cmd")

    p_key_upload_ssh = key_sub.add_parser(
        "upload-ssh", help="Upload an SSH public key to GitHub/GitLab.",
    )
    _add_auth_args(p_key_upload_ssh)
    p_key_upload_ssh.add_argument("--platform", required=True, choices=["github", "gitlab"])
    p_key_upload_ssh.add_argument("--account-name", required=True)
    p_key_upload_ssh.add_argument("--key-file", required=True, help="Path to SSH public key file.")
    p_key_upload_ssh.add_argument("--token", help="Forge API token (env: FORGE_TOKEN).")
    p_key_upload_ssh.add_argument("--key-title", help="Title for the key on the platform.")
    p_key_upload_ssh.add_argument("--replace", action="store_true",
                                  help="Replace existing keys for this account.")
    p_key_upload_ssh.set_defaults(func=cmd_key_upload_ssh)

    p_key_upload_gpg = key_sub.add_parser(
        "upload-gpg", help="Upload an armored GPG public key to GitHub/GitLab.",
    )
    _add_auth_args(p_key_upload_gpg)
    p_key_upload_gpg.add_argument("--platform", required=True, choices=["github", "gitlab"])
    p_key_upload_gpg.add_argument("--account-name", required=True)
    p_key_upload_gpg.add_argument("--key-file", required=True, help="Path to armored GPG public key (.asc).")
    p_key_upload_gpg.add_argument("--token", help="Forge API token (env: FORGE_TOKEN).")
    p_key_upload_gpg.add_argument("--replace", action="store_true",
                                  help="Replace existing keys for this account.")
    p_key_upload_gpg.set_defaults(func=cmd_key_upload_gpg)

    p_key_gen_gpg = key_sub.add_parser(
        "generate-gpg", help="Generate a new GPG key pair.",
    )
    g_key_auth = p_key_gen_gpg.add_argument_group("authentication / credentials")
    g_key_auth.add_argument("--session", help="Existing bw session key to reuse (env: BW_SESSION).")
    g_key_auth.add_argument("--use-stored", action="store_true",
                            help="Load credentials from OS keyring or encrypted file.")
    g_key_auth.add_argument("--store-passphrase",
                            help="Passphrase for encrypted credential file (env: BW_STORE_PASSPHRASE).")
    g_key_auth.add_argument("--config-dir", help="Credential store directory (default: ~/.config/bwforgectl).")
    g_key_auth.add_argument("--no-keyring", action="store_true",
                            help="Force encrypted-file backend instead of OS keyring.")
    p_key_gen_gpg.add_argument("--name", help="Real name for the GPG key (default: email).")
    p_key_gen_gpg.add_argument("--email", required=True, help="Email for the GPG key.")
    p_key_gen_gpg.add_argument("--key-type", choices=["ed25519", "rsa4096"], default="ed25519",
                               help="Key type (default: ed25519).")
    p_key_gen_gpg.add_argument("--store", action="store_true",
                               help="Store the GPG key in Bitwarden vault as secure note.")
    p_key_gen_gpg.add_argument("--upload", action="store_true",
                               help="Upload the GPG key to a forge platform.")
    p_key_gen_gpg.add_argument("--platform", choices=["github", "gitlab"],
                               help="Forge platform (required with --upload).")
    p_key_gen_gpg.add_argument("--account-name", help="Forge account name (required with --upload).")
    p_key_gen_gpg.add_argument("--token", help="Forge API token (env: FORGE_TOKEN).")
    p_key_gen_gpg.add_argument("--replace", action="store_true",
                               help="Replace existing GPG key on the platform.")
    p_key_gen_gpg.set_defaults(func=cmd_key_generate_gpg)

    # === sync ===
    p_sync = sub.add_parser("sync", help="Synchronise local keys with the vault.")
    sync_sub = p_sync.add_subparsers(dest="sync_cmd")

    # sync (no subcommand) → bidirectional
    p_sync.set_defaults(func=cmd_sync_bidirectional)
    _add_auth_args(p_sync)
    _add_sync_opts(p_sync)

    # sync host
    p_sync_host = sync_sub.add_parser("host", help="Push local keys to the vault (host → vault).")
    _add_auth_args(p_sync_host)
    _add_sync_opts(p_sync_host)
    p_sync_host.set_defaults(func=cmd_sync_host)

    # sync vault
    p_sync_vault = sync_sub.add_parser("vault", help="Pull vault keys to local disk (vault → host).")
    _add_auth_args(p_sync_vault)
    _add_sync_opts(p_sync_vault)
    p_sync_vault.set_defaults(func=cmd_sync_vault)

    # sync gpg-host
    p_sync_gpg_host = sync_sub.add_parser(
        "gpg-host", help="Push local GPG keys to the vault (host → vault).",
    )
    _add_auth_args(p_sync_gpg_host)
    p_sync_gpg_host.add_argument("--dry-run", action="store_true", help="Report what would change.")
    p_sync_gpg_host.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_sync_gpg_host.set_defaults(func=cmd_sync_gpg_host)

    # sync gpg-vault
    p_sync_gpg_vault = sync_sub.add_parser(
        "gpg-vault", help="Pull GPG keys from vault to .asc files.",
    )
    _add_auth_args(p_sync_gpg_vault)
    p_sync_gpg_vault.add_argument("--gpg-dir", help="Directory for .asc files (default: ~/.ssh).")
    p_sync_gpg_vault.add_argument("--dry-run", action="store_true", help="Report what would change.")
    p_sync_gpg_vault.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_sync_gpg_vault.set_defaults(func=cmd_sync_gpg_vault)

    return parser


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()

    # If no arguments or just -h/--help, show full help
    args_list = argv if argv is not None else sys.argv[1:]
    if not args_list or args_list == ["-h"] or args_list == ["--help"]:
        print_full_help()
        return 0

    args = parser.parse_args(argv)

    # If -h/--help was passed after the parser already parsed, show full help
    if getattr(args, "help", False):
        print_full_help()
        return 0

    # Validate that group has a subcommand
    if args.group == "credential" and not getattr(args, "cred_cmd", None):
        parser.print_help()
        print("\nerror: missing credential subcommand (store or forget)", file=sys.stderr)
        return 1
    if args.group == "host" and not getattr(args, "host_cmd", None):
        parser.print_help()
        print("\nerror: missing host subcommand (list or search)", file=sys.stderr)
        return 1
    if args.group == "vault" and not getattr(args, "vault_cmd", None):
        parser.print_help()
        print("\nerror: missing vault subcommand (list, search, output, or delete)", file=sys.stderr)
        return 1
    if args.group == "account" and not getattr(args, "acct_cmd", None):
        parser.print_help()
        print("\nerror: missing account subcommand (create or verify)", file=sys.stderr)
        return 1
    if args.group == "audit" and not getattr(args, "audit_cmd", None):
        parser.print_help()
        print("\nerror: missing audit subcommand (vault)", file=sys.stderr)
        return 1
    if args.group == "config" and not getattr(args, "cfg_cmd", None):
        parser.print_help()
        print("\nerror: missing config subcommand (list, show, install, or remove)", file=sys.stderr)
        return 1
    if args.group == "key" and not getattr(args, "key_cmd", None):
        parser.print_help()
        print("\nerror: missing key subcommand (upload-ssh, upload-gpg, or generate-gpg)", file=sys.stderr)
        return 1

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except BitwardenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
