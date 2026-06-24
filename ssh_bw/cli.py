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


def _verbose_level(args: argparse.Namespace) -> int:
    """Resolve verbosity: --quiet / BW_QUIET → 0, -v count → N, default 1."""
    if getattr(args, "quiet", False) or os.environ.get("BW_QUIET"):
        return 0
    return getattr(args, "verbose", 1)


def _no_sync(args: argparse.Namespace) -> bool:
    """Resolve --no-sync / BW_NO_SYNC."""
    return getattr(args, "no_sync", False) or bool(os.environ.get("BW_NO_SYNC"))


def _progress(msg: str, verbose: int = 1, level: int = 1) -> None:
    if verbose >= level:
        print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Credential resolution
# --------------------------------------------------------------------------- #
def _resolve_credentials(args: argparse.Namespace) -> Credentials:
    """Resolve Bitwarden credentials from CLI / env / store / prompt."""
    email = args.email or os.environ.get("BW_EMAIL")
    password = args.password or os.environ.get("BW_PASSWORD")

    should_try_store = (
        args.use_stored
        or os.environ.get("BW_STORE_PASSPHRASE")
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

    # If the store was attempted but failed and we just got fresh credentials
    # from the interactive prompt, offer to update the store.
    if store_failed and prompted and store is not None:
        answer = input(
            "Update the credential store with these credentials? [y/N] "
        ).strip().lower()
        if answer in {"y", "yes"}:
            p = args.store_passphrase or os.environ.get("BW_STORE_PASSPHRASE")
            if store.backend == "encrypted-file" and not p:
                p = getpass.getpass("Choose a credential-store passphrase: ")
                confirm = getpass.getpass("Confirm passphrase: ")
                if p != confirm:
                    print("error: passphrases do not match, store not updated",
                          file=sys.stderr)
                    return creds
            store.save(creds, store_passphrase=p)
            print(f"Credential store updated using the '{store.backend}' backend.",
                  file=sys.stderr)

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


def _shorten_detail(detail: str, width: int = 80) -> str:
    """Truncate long base64 payloads in error messages for readable display."""
    import re
    # Replace long base64 strings (>=40 chars) with a placeholder.
    shortened = re.sub(
        r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
        lambda m: f"…({len(m.group(0))}b base64)…",
        detail,
    )
    if len(shortened) > width:
        shortened = shortened[:width] + "…"
    return shortened


def cmd_sync(args: argparse.Namespace) -> int:
    verbose = _verbose_level(args)
    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()
        importer = Importer(client, name_prefix=args.name_prefix)

        from_server = getattr(args, "from_server", False)
        explicit = args.update or args.yes
        dry_run = not explicit

        if from_server:
            _progress(f"  pulling keys from vault …", verbose)
            results = importer.sync_from_server(
                args.ssh_dir,
                confirm_overwrite=args.yes,
                dry_run=dry_run,
            )
        else:
            ssh_dir = args.ssh_dir or os.path.expanduser("~/.ssh")
            _progress(f"  scanning {ssh_dir} …", verbose)

            if dry_run:
                confirm = lambda p, r: False  # noqa: E731
            elif args.yes:
                confirm = lambda p, r: True  # noqa: E731
            else:
                confirm = _confirm_update_interactive

            results = importer.sync_directory(
                args.ssh_dir,
                confirm_update=confirm,
                derive_missing_public=not args.no_derive,
                dry_run=dry_run,
            )
    finally:
        client.stop_serve()

    if args.json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
        return 0

    for r in results:
        action_color = ""
        suffix = ""
        if r.action == "unchanged":
            action_color = "  "
            detail = r.detail
        elif r.action == "created":
            action_color = "+ "
            detail = r.detail
        elif r.action == "updated":
            action_color = "~ "
            detail = r.detail
        elif r.action == "skipped":
            action_color = "- "
            detail = _shorten_detail(r.detail, width=100)
        elif r.action == "declined":
            action_color = "! "
            detail = r.detail
        else:
            action_color = "? "
            detail = r.detail
        print(f"{action_color}{r.name:<52s} {detail}")
    counts: dict = {}
    for r in results:
        counts[r.action] = counts.get(r.action, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"\nDone. {summary or 'no keys found'}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    verbose = _verbose_level(args)
    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()
        importer = Importer(client, name_prefix=args.name_prefix)
        _progress("  loading items from vault …", verbose)
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
    verbose = _verbose_level(args)
    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()
        importer = Importer(client, name_prefix=args.name_prefix)
        out_dir = Path(args.out_dir).expanduser() if args.out_dir else None
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)

        _progress(f"  exporting {args.type} items …", verbose)
        if args.type == "ssh":
            count = _output_ssh(importer, args, out_dir)
        else:
            count = _output_pgp(importer, args, out_dir)
    finally:
        client.stop_serve()
    if count == 0:
        print("No matching items found.", file=sys.stderr)
        return 1
    _progress(f"  exported {count} item(s)", verbose)
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
    verbose = _verbose_level(args)
    identifier = args.id or args.name
    if not identifier:
        print("error: provide --id or --name", file=sys.stderr)
        return 1
    client = _make_client(args)
    try:
        if not _no_sync(args):
            client.sync()
        importer = Importer(client, name_prefix=args.name_prefix)
        _progress("  locating matching items …", verbose)
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
        _progress(f"  deleting {len(targets)} item(s) …", verbose)
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
    g = parser.add_argument_group("authentication / credentials")
    g.add_argument("--email",
                   help="Bitwarden account email (env: BW_EMAIL).")
    g.add_argument("--password",
                   help="Master password (insecure on shared hosts; "
                        "use --use-stored or env: BW_PASSWORD).")
    g.add_argument("--session",
                   help="Existing bw session key to reuse (env: BW_SESSION).")
    g.add_argument("--use-stored", action="store_true",
                   help="Load credentials previously saved with 'store-credentials' subcommand.")
    g.add_argument("--store-passphrase",
                   help="Passphrase protecting the encrypted credential file "
                        "(env: BW_STORE_PASSPHRASE; required when --no-keyring "
                        "and no OS keyring available).")
    g.add_argument("--config-dir",
                   help="Directory for the credential store (default: ~/.config/ssh_bw).")
    g.add_argument("--no-keyring", action="store_true",
                   help="Force encrypted-file backend instead of the OS keyring.")
    g.add_argument("--name-prefix", default="SSH: ",
                   help="Prefix for SSH key item names in the vault (default: 'SSH: ').")


def _add_common_opts(parser: argparse.ArgumentParser) -> None:
    """Add general CLI options to a subparser (used by vault-ops subcommands)."""
    g = parser.add_argument_group("output options")
    g.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of human-friendly text.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-bw",
        description="Sync local ~/.ssh key pairs (and inspect PGP notes) with Bitwarden.",
        epilog=(
            "Environment variables:\n"
            "  BW_EMAIL             Bitwarden account email (alternative to --email).\n"
            "  BW_PASSWORD          Master password (alternative to --password).\n"
            "  BW_SESSION           Existing bw session key (alternative to --session).\n"
            "  BW_STORE_PASSPHRASE  Passphrase for the encrypted credential store.\n"
            "  BW_PATH              Path to the bw executable (default: bw).\n"
            "  BW_NO_SYNC           Set to 1 to skip 'bw sync' before each operation.\n"
            "  BW_QUIET             Set to 1 to suppress progress/diagnostic output.\n"
            "  SERVE_PORT           Port for 'bw serve' when --use-serve is active (default: 8087).\n"
            "\n"
            "Examples:\n"
            "  ssh-bw store-credentials --email you@example.com\n"
            "    Save your credentials for later use (OS keyring or encrypted file).\n\n"
            "  ssh-bw sync\n"
            "    Compare local keys with the vault (dry run; no changes made).\n\n"
            "  ssh-bw sync --update\n"
            "    Interactive: prompt before updating the vault for changed keys.\n\n"
            "  ssh-bw sync --yes\n"
            "    Auto-upload all new/changed local keys to the vault.\n\n"
            "  ssh-bw sync --from-server --yes\n"
            "    Pull all vault SSH keys onto local disk (overwriting existing).\n\n"
            "  ssh-bw list --type ssh\n"
            "    List every SSH key stored in the vault.\n\n"
            "  ssh-bw output --type ssh --name github --out-dir ./export\n"
            "    Extract a specific vault SSH key to a file.\n\n"
            "  ssh-bw delete --name id_ed25519\n"
            "    Remove an SSH key record from the vault.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global CLI options (must come BEFORE the subcommand in argv).
    parser.add_argument("--bw-path", default="bw",
                        help="Path (or name on PATH) of the Bitwarden CLI executable "
                             "(env: BW_PATH, default: bw).")
    parser.add_argument("--use-serve", action="store_true",
                        help="Use 'bw serve' REST API for vault operations "
                             "(faster after initial handshake).")
    parser.add_argument("--serve-port", type=int, default=8087,
                        help="Port for 'bw serve' when --use-serve is active "
                             "(env: SERVE_PORT, default: 8087).")
    parser.add_argument("--no-sync", action="store_true",
                        help="Skip 'bw sync' before each operation "
                             "(env: BW_NO_SYNC, useful when you synced recently).")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress all progress and diagnostic output "
                             "(env: BW_QUIET, sets verbose=0).")
    parser.add_argument("--verbose", "-v", action="count", default=1,
                        help="Increase verbosity:  -v = progress (default), "
                             "-vv = diagnostics, -vvv = debug (raw bw output).")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("store-credentials",
                       help="Save Bitwarden credentials to OS keyring (or encrypted file) "
                            "for later use with --use-stored.")
    _add_auth_args(p)
    p.set_defaults(func=cmd_store_credentials)

    p = sub.add_parser("forget-credentials",
                       help="Remove previously stored credentials from the keyring/encrypted file.")
    _add_auth_args(p)
    p.set_defaults(func=cmd_forget_credentials)

    p = sub.add_parser("sync",
                        help="Compare SSH key pairs between ~/.ssh and the Bitwarden vault. "
                             "Without --update or --yes, only reports differences (dry run).")
    _add_auth_args(p)
    _add_common_opts(p)
    p.add_argument("--ssh-dir",
                   help="Directory to scan for local keys (default: ~/.ssh).")
    direction = p.add_mutually_exclusive_group()
    direction.add_argument("--from-disk", action="store_true", dest="from_disk",
                           help="Push local SSH keys into the vault (default).")
    direction.add_argument("--from-server", action="store_true", dest="from_server",
                           help="Pull SSH keys from the vault onto local disk.")
    p.add_argument("--update", action="store_true",
                   help="When a local key differs from its vault entry, prompt interactively "
                        "before updating the vault.")
    p.add_argument("--yes", action="store_true",
                   help="Non-interactive mode: auto-confirm all changes "
                        "(updates for --from-disk, overwrites for --from-server).")
    p.add_argument("--no-derive", action="store_true",
                   help="Skip deriving the public key from the private key when only "
                        "a private key is found.")
    p.set_defaults(func=cmd_sync, from_disk=True, from_server=False)

    p = sub.add_parser("list",
                       help="List SSH keys and/or PGP notes stored in the vault.")
    _add_auth_args(p)
    _add_common_opts(p)
    p.add_argument("--type", choices=["ssh", "pgp", "all"], default="all",
                   help="Type of items to show (default: all).")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("output",
                       help="Dump SSH keys or PGP notes to stdout or files.")
    _add_auth_args(p)
    _add_common_opts(p)
    p.add_argument("--type", choices=["ssh", "pgp"], default="ssh",
                   help="Type of items to output (default: ssh).")
    p.add_argument("--name",
                   help="Only output items whose name contains this substring.")
    p.add_argument("--out-dir",
                   help="Write each key/note to a separate file in this directory "
                        "instead of printing to stdout.")
    p.add_argument("--show-private", action="store_true",
                   help="Also include the private key when writing to stdout "
                        "(only relevant for --type ssh).")
    p.set_defaults(func=cmd_output)

    p = sub.add_parser("delete",
                       help="Delete an SSH key record from the vault.")
    _add_auth_args(p)
    _add_common_opts(p)
    p.add_argument("--id",
                   help="Vault item id of the record to delete.")
    p.add_argument("--name",
                   help="Item name (or bare key name without the 'SSH: ' prefix) to delete.")
    p.add_argument("--permanent", action="store_true",
                   help="Permanently purge the item instead of soft-deleting (moving to trash).")
    p.add_argument("--yes", action="store_true",
                   help="Skip the interactive confirmation prompt.")
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
