"""Command-line interface for ssh-bw.

Subcommand groups
-----------------
  ssh-bw credential store          Save Bitwarden credentials.
  ssh-bw credential forget         Remove stored credentials.
  ssh-bw host list                 List local SSH and GPG keys.
  ssh-bw host search <query>       Fuzzy-search local keys by fingerprint or name.
  ssh-bw vault list                List SSH / PGP keys in the Bitwarden vault.
  ssh-bw vault search <query>      Fuzzy-search vault keys.
  ssh-bw vault output              Export vault keys to files or stdout.
  ssh-bw vault delete              Remove keys from the vault.
  ssh-bw sync                      Bidirectional sync (interactive).
  ssh-bw sync host                 Push local keys to vault.
  ssh-bw sync vault                Pull vault keys to local disk.
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
from .hostscan import (
    HostKeyEntry,
    format_table,
    fuzzy_match_host,
    fuzzy_match_vault,
    scan_host_keys,
)
from .importer import (
    ACTION_CREATED,
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
# Full help text (shown for bare `ssh-bw` or `ssh-bw -h`)
# --------------------------------------------------------------------------- #

FULL_HELP = r"""ssh-bw — Sync local SSH key pairs (and PGP notes) with a Bitwarden vault.

Usage:
  ssh-bw [GLOBAL-OPTS] <group> <command> [AUTH-OPTS] [CMD-OPTS]

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
  --config-dir DIR    Credential store directory (default: ~/.config/ssh-bw).
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

    ssh-bw credential store
        Save your Bitwarden email and password to the OS keyring (or an
        encrypted file).  You will be prompted for any missing values.

        Options: --email, --password, --store-passphrase, --config-dir,
                 --no-keyring

    ssh-bw credential forget
        Remove previously stored credentials.

        Options: --config-dir, --no-keyring

   HOST — inspect local keys
   ──────────────────────────

     ssh-bw host list
         List SSH and GPG keys found on this machine.
         Shows SHA256 fingerprints by default.

         Options:
           --ssh        Show only SSH keys.
           --gpg        Show only GPG keys.
           --md5        Show MD5 fingerprints instead of SHA256.
           --json       Emit machine-readable JSON.

     ssh-bw host search <query>
         Fuzzy-search local keys by fingerprint (SHA256 by default) or name.
         Matches are case-insensitive and ignore colons / spaces / prefixes.

         Options:
           --md5        Match and display MD5 fingerprints only.
           --sha256     Match and display SHA256 fingerprints only.
           --json       Emit machine-readable JSON.

  VAULT — inspect and manage vault keys
  ──────────────────────────────────────

    ssh-bw vault list
        List SSH keys and/or PGP notes stored in the Bitwarden vault.

        Options:
          --ssh        Show only SSH keys.
          --gpg        Show only PGP/GPG notes.
          --json       Emit machine-readable JSON.
          (plus authentication options)

    ssh-bw vault search <query>
        Fuzzy-search vault SSH keys by fingerprint or name.

        Options:
          --md5        Match only against MD5 fingerprints.
          --sha256     Match only against SHA256 fingerprints.
          --json       Emit machine-readable JSON.
          (plus authentication options)

    ssh-bw vault output --name <name> [--out-dir <dir>]
        Export SSH keys or PGP notes from the vault to files or stdout.

        Options:
          --type TYPE          'ssh' (default) or 'gpg'.
          --name NAME          Only output items whose name contains this.
          --out-dir DIR        Write to files in this directory (else stdout).
          --show-private       Include the private key in stdout output.
          (plus authentication options)

    ssh-bw vault delete --name <name> [--id <id>]
        Remove an SSH key record from the vault (soft-delete by default).

        Options:
          --id ID          Vault item ID to delete.
          --name NAME      Item name (or bare key name without prefix).
          --permanent      Permanently purge (skip trash).
          --yes            Skip the interactive confirmation prompt.
          (plus authentication options)

  SYNC — synchronise local keys with the vault
  ─────────────────────────────────────────────

    ssh-bw sync
        Bidirectional sync — push new local keys to the vault and pull
        vault-only keys to disk.  Conflicts are resolved interactively.

    ssh-bw sync host
        Push local SSH keys to the vault (host → vault).
        Only keys in ~/.ssh that are new or changed are uploaded.
        Without --yes, you are prompted before each update.

    ssh-bw sync vault
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

  ssh-bw credential store --email you@example.com
      Save credentials for later use.

  ssh-bw host list
      Show all SSH and GPG keys on this machine.

   ssh-bw host search "SHA256:abc123"
       Find a local key by its SHA256 fingerprint (default).

   ssh-bw host search --md5 "MD5:aa:bb:cc"
       Find a local SSH key by its MD5 fingerprint.

   ssh-bw host list --md5
       List local keys showing MD5 fingerprints instead of SHA256.

  ssh-bw vault list --ssh
      List every SSH key stored in the vault.

  ssh-bw vault search "ed25519"
      Fuzzy-search vault keys matching 'ed25519'.

  ssh-bw vault output --name github --out-dir ./export
      Extract a specific vault key to files.

  ssh-bw vault delete --name old-key --yes
      Remove an SSH key record from the vault without confirmation.

  ssh-bw sync --dry-run
      Preview bidirectional sync without making changes.

  ssh-bw sync host --yes
      Push all local keys to the vault, auto-confirming changes.

  ssh-bw sync vault --yes
      Pull all vault keys to local disk, auto-confirming overwrites.
"""


def print_full_help(file=None):
    print(FULL_HELP, file=file or sys.stdout)


# --------------------------------------------------------------------------- #
# Credential resolution (shared)
# --------------------------------------------------------------------------- #


def _resolve_credentials(args: argparse.Namespace) -> Credentials:
    email = args.email or os.environ.get("BW_EMAIL")
    password = args.password or os.environ.get("BW_PASSWORD")

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


# --------------------------------------------------------------------------- #
# Argument parser
# --------------------------------------------------------------------------- #


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
        help="Credential store directory (default: ~/.config/ssh-bw).",
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
        prog="ssh-bw",
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
