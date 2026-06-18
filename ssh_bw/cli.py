"""Command-line interface for ssh_bw.

Examples
--------
    # Persist credentials securely (keyring or encrypted file)
    python -m ssh_bw store-credentials --email you@example.com

    # Scan ~/.ssh and import / update keys into Bitwarden
    python -m ssh_bw sync --update

    # List SSH keys and PGP notes held in the vault
    python -m ssh_bw list --type ssh
    python -m ssh_bw list --type pgp

    # Output (dump) a key/note to stdout or files
    python -m ssh_bw output --type ssh --name id_ed25519 --out-dir ./export

    # Delete an SSH record from the vault
    python -m ssh_bw delete --name id_ed25519
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
from .importer import Importer
from .pgp import is_pgp_note
from .sshscan import SSHKeyPair


def _progress(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Credential resolution
# --------------------------------------------------------------------------- #
def _resolve_credentials(args: argparse.Namespace) -> Credentials:
    """Resolve Bitwarden credentials from CLI / env / store / prompt."""
    email = args.email or os.environ.get("BW_EMAIL")
    password = args.password or os.environ.get("BW_PASSWORD")

    if (not password) and args.use_stored:
        store = CredentialStore(args.config_dir, prefer_keyring=not args.no_keyring)
        passphrase = None
        if store.backend == "encrypted-file":
            passphrase = args.store_passphrase or os.environ.get(
                "BW_STORE_PASSPHRASE"
            ) or getpass.getpass("Credential store passphrase: ")
        try:
            stored = store.load(store_passphrase=passphrase)
            email = email or stored.email
            password = password or stored.password
        except CredentialError as exc:
            print(f"warning: {exc}", file=sys.stderr)

    if not email:
        email = input("Bitwarden email: ").strip()
    if not password:
        password = getpass.getpass("Bitwarden master password: ")
    return Credentials(email=email, password=password)


def _make_client(args: argparse.Namespace, *, need_auth: bool = True) -> BitwardenClient:
    quiet = getattr(args, "quiet", False)
    creds = _resolve_credentials(args) if need_auth else None
    client = BitwardenClient(
        bw_path=args.bw_path,
        session=args.session or os.environ.get("BW_SESSION"),
        use_serve=args.use_serve,
        serve_port=args.serve_port,
        quiet=quiet,
        email=creds.email if creds else None,
        password=creds.password if creds else None,
    )
    if need_auth and not client.session:
        client.ensure_session(creds.email, creds.password)
    if args.use_serve:
        client.start_serve()
    return client


# --------------------------------------------------------------------------- #
# Sub-commands
# --------------------------------------------------------------------------- #
def cmd_store_credentials(args: argparse.Namespace) -> int:
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


def cmd_forget_credentials(args: argparse.Namespace) -> int:
    store = CredentialStore(args.config_dir, prefer_keyring=not args.no_keyring)
    removed = store.delete()
    print("Credentials removed." if removed else "No stored credentials found.")
    return 0


def _confirm_update_interactive(pair: SSHKeyPair, record) -> bool:
    print(f"\n  Key '{pair.name}' (fp {pair.fingerprint or '?'}) differs from vault "
          f"entry '{record.name}'.")
    answer = input("  Update the vault entry? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def cmd_sync(args: argparse.Namespace) -> int:
    quiet = getattr(args, "quiet", False)
    client = _make_client(args)
    try:
        if not args.no_sync:
            client.sync()
        importer = Importer(client, name_prefix=args.name_prefix)

        ssh_dir = args.ssh_dir or os.path.expanduser("~/.ssh")
        _progress(f"  scanning {ssh_dir} …", quiet)

        if args.update and args.yes:
            confirm = lambda p, r: True  # noqa: E731
        elif args.update:
            confirm = _confirm_update_interactive
        else:
            confirm = lambda p, r: False  # noqa: E731

        results = importer.sync_directory(
            args.ssh_dir,
            confirm_update=confirm,
            derive_missing_public=not args.no_derive,
        )
    finally:
        client.stop_serve()

    if args.json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
        return 0

    for r in results:
        print(f"[{r.action:<9}] {r.name}  ({r.detail})")
    counts: dict = {}
    for r in results:
        counts[r.action] = counts.get(r.action, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"\nDone. {summary or 'no keys found'}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    quiet = getattr(args, "quiet", False)
    client = _make_client(args)
    try:
        if not args.no_sync:
            client.sync()
        importer = Importer(client, name_prefix=args.name_prefix)
        _progress("  loading items from vault …", quiet)
        ssh_records = importer.load_ssh_records() if args.type in ("ssh", "all") else []
        pgp_notes = importer.load_pgp_notes() if args.type in ("pgp", "all") else []
    finally:
        client.stop_serve()

    if args.json:
        out = {
            "ssh": [
                {"id": r.id, "name": r.name, "fingerprint": r.fingerprint}
                for r in ssh_records
            ],
            "pgp": [{"id": n.get("id"), "name": n.get("name")} for n in pgp_notes],
        }
        print(json.dumps(out, indent=2))
        return 0

    if args.type in ("ssh", "all"):
        print(f"SSH keys ({len(ssh_records)}):")
        for r in ssh_records:
            print(f"  {r.id}  {r.name}  [{r.fingerprint}]")
    if args.type in ("pgp", "all"):
        print(f"PGP notes ({len(pgp_notes)}):")
        for n in pgp_notes:
            print(f"  {n.get('id')}  {n.get('name')}")
    return 0


def cmd_output(args: argparse.Namespace) -> int:
    quiet = getattr(args, "quiet", False)
    client = _make_client(args)
    try:
        if not args.no_sync:
            client.sync()
        importer = Importer(client, name_prefix=args.name_prefix)
        out_dir = Path(args.out_dir).expanduser() if args.out_dir else None
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)

        _progress(f"  exporting {args.type} items …", quiet)
        if args.type == "ssh":
            count = _output_ssh(importer, args, out_dir)
        else:
            count = _output_pgp(importer, args, out_dir)
    finally:
        client.stop_serve()
    if count == 0:
        print("No matching items found.", file=sys.stderr)
        return 1
    _progress(f"  exported {count} item(s)", quiet)
    return 0


def _matches(name_filter: Optional[str], name: str) -> bool:
    return name_filter is None or name_filter.lower() in (name or "").lower()


def _output_ssh(importer: Importer, args: argparse.Namespace, out_dir) -> int:
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


def _output_pgp(importer: Importer, args: argparse.Namespace, out_dir) -> int:
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


def cmd_delete(args: argparse.Namespace) -> int:
    quiet = getattr(args, "quiet", False)
    identifier = args.id or args.name
    if not identifier:
        print("error: provide --id or --name", file=sys.stderr)
        return 1
    client = _make_client(args)
    try:
        if not args.no_sync:
            client.sync()
        importer = Importer(client, name_prefix=args.name_prefix)
        _progress("  locating matching items …", quiet)
        # Resolve targets first for confirmation.
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
        _progress(f"  deleting {len(targets)} item(s) …", quiet)
        results = importer.delete_ssh(identifier, permanent=args.permanent)
    finally:
        client.stop_serve()
    for r in results:
        print(f"[deleted] {r.name}  ({r.detail})")
    return 0


# --------------------------------------------------------------------------- #
# Argument parser
# --------------------------------------------------------------------------- #
def _add_auth_args(parser: argparse.ArgumentParser) -> None:
    """Add credential-related arguments to a subparser."""
    g = parser.add_argument_group("auth / credentials")
    g.add_argument("--email", help="Bitwarden account email.")
    g.add_argument("--password", help="Master password (insecure on shared hosts).")
    g.add_argument("--session", help="Existing BW_SESSION key to reuse.")
    g.add_argument("--use-stored", action="store_true",
                   help="Load saved credentials from the secure store.")
    g.add_argument("--store-passphrase",
                   help="Passphrase for the encrypted-file credential store.")
    g.add_argument("--config-dir", help="Credential-store directory.")
    g.add_argument("--no-keyring", action="store_true",
                   help="Do not use the OS keyring; use the encrypted file backend.")
    g.add_argument("--name-prefix", default="SSH: ",
                   help="Prefix used for SSH key item names in the vault.")


def _add_common_opts(parser: argparse.ArgumentParser) -> None:
    """Add general CLI options to a subparser (used by vault-ops subcommands)."""
    g = parser.add_argument_group("options")
    g.add_argument("--json", action="store_true", help="Emit JSON output.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh_bw",
        description="Sync local ~/.ssh key pairs (and inspect PGP notes) with Bitwarden.",
    )

    # Global CLI options (must come BEFORE the subcommand in argv).
    parser.add_argument("--bw-path", default="bw", help="Path to the bw executable.")
    parser.add_argument("--use-serve", action="store_true",
                        help="Use 'bw serve' REST API for vault operations.")
    parser.add_argument("--serve-port", type=int, default=8087, help="bw serve port.")
    parser.add_argument("--no-sync", action="store_true",
                        help="Skip 'bw sync' before operating.")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress progress messages on stderr.")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("store-credentials",
                       help="Persist credentials securely.")
    _add_auth_args(p)
    p.set_defaults(func=cmd_store_credentials)

    p = sub.add_parser("forget-credentials",
                       help="Remove stored credentials.")
    _add_auth_args(p)
    p.set_defaults(func=cmd_forget_credentials)

    p = sub.add_parser("sync",
                       help="Scan ~/.ssh and import/update keys into Bitwarden.")
    _add_auth_args(p)
    _add_common_opts(p)
    p.add_argument("--ssh-dir", help="Directory to scan (default ~/.ssh).")
    p.add_argument("--update", action="store_true",
                   help="Offer to update entries that differ.")
    p.add_argument("--yes", action="store_true",
                   help="Assume yes to update prompts (non-interactive).")
    p.add_argument("--no-derive", action="store_true",
                   help="Do not derive a missing public key from the private key.")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("list",
                       help="List SSH keys and/or PGP notes in the vault.")
    _add_auth_args(p)
    _add_common_opts(p)
    p.add_argument("--type", choices=["ssh", "pgp", "all"], default="all")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("output",
                       help="Output (dump) SSH keys or PGP notes.")
    _add_auth_args(p)
    _add_common_opts(p)
    p.add_argument("--type", choices=["ssh", "pgp"], default="ssh")
    p.add_argument("--name", help="Filter by (substring of) item name.")
    p.add_argument("--out-dir", help="Write files here instead of stdout.")
    p.add_argument("--show-private", action="store_true",
                   help="Also print private keys to stdout (ssh only).")
    p.set_defaults(func=cmd_output)

    p = sub.add_parser("delete",
                       help="Delete an SSH record from the vault.")
    _add_auth_args(p)
    _add_common_opts(p)
    p.add_argument("--id", help="Item id to delete.")
    p.add_argument("--name", help="Item name (or bare key name) to delete.")
    p.add_argument("--permanent", action="store_true",
                   help="Permanently delete instead of moving to trash.")
    p.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    p.set_defaults(func=cmd_delete)

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BitwardenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
