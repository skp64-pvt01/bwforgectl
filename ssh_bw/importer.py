"""Core synchronisation logic between local SSH keys and a Bitwarden vault."""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .bwclient import TYPE_SSH_KEY, BitwardenClient
from .pgp import is_pgp_note
from .sshscan import SSHKeyPair, _normalize, scan_ssh_dir

# Action constants returned in SyncResult.action
ACTION_CREATED = "created"
ACTION_UPDATED = "updated"
ACTION_SKIPPED = "skipped"
ACTION_UNCHANGED = "unchanged"
ACTION_DECLINED = "declined"


@dataclass
class SyncResult:
    name: str
    fingerprint: str
    action: str
    item_id: Optional[str] = None
    detail: str = ""


@dataclass
class SSHRecord:
    """An SSH key item as stored in Bitwarden."""

    id: str
    name: str
    private_key: str
    public_key: str
    fingerprint: str
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)


# A confirmation callback: (pair, existing_record) -> bool
ConfirmFn = Callable[[SSHKeyPair, SSHRecord], bool]


def _always_yes(pair: SSHKeyPair, record: SSHRecord) -> bool:
    return True


def _always_no(pair: SSHKeyPair, record: SSHRecord) -> bool:
    return False


def _compare_keys(local: SSHKeyPair, vault: SSHRecord) -> Dict[str, str]:
    """Compare a local key pair against a vault record.

    Returns a dict with per-field comparison diffs.
    """
    result: Dict[str, str] = {}
    norm_priv_local = local.normalized_private()
    norm_priv_vault = _normalize(vault.private_key)
    norm_pub_local = local.normalized_public()
    norm_pub_vault = _normalize(vault.public_key)

    if norm_priv_local != norm_priv_vault:
        result["private_key"] = "DIFFERS"
    if norm_pub_local != norm_pub_vault:
        result["public_key"] = "DIFFERS"
    if local.fingerprint and vault.fingerprint and local.fingerprint != vault.fingerprint:
        result["fingerprint"] = "DIFFERS"
    return result


def _diagnose_ssh_line(
    prefix: str, local_fp: str, vault_fp: str, vault_id: str, diffs: Dict[str, str]
) -> str:
    parts = []
    line = f"  {prefix}  local fp: {local_fp or '?'}  vault fp: {vault_fp or '?'}  (item: {vault_id})"
    if diffs:
        line += f"\n  {' ' * len(prefix)}  diff: {', '.join(f'{k} {v}' for k, v in diffs.items())}"
    return line


class Importer:
    """Orchestrates scanning and Bitwarden synchronisation."""

    def __init__(self, client: BitwardenClient, *, name_prefix: str = "SSH: ") -> None:
        self.client = client
        self.name_prefix = name_prefix

    def _progress(self, msg: str) -> None:
        if self.client.verbose >= 1:
            print(msg, file=sys.stderr, flush=True)

    def _diagnostic(self, msg: str) -> None:
        if self.client.verbose >= 2:
            print(msg, file=sys.stderr, flush=True)

    # ------------------------------------------------------------------ #
    # Reading from the vault
    # ------------------------------------------------------------------ #
    def load_ssh_records(self) -> List[SSHRecord]:
        records: List[SSHRecord] = []
        for item in self.client.list_items():
            if item.get("type") != TYPE_SSH_KEY:
                continue
            sk = item.get("sshKey") or {}
            records.append(
                SSHRecord(
                    id=item.get("id", ""),
                    name=item.get("name", ""),
                    private_key=sk.get("privateKey", "") or "",
                    public_key=sk.get("publicKey", "") or "",
                    fingerprint=sk.get("keyFingerprint", "") or "",
                    raw=item,
                )
            )
        self._progress(f"  loaded {len(records)} SSH key record(s) from vault")
        return records

    def load_pgp_notes(self) -> List[Dict[str, Any]]:
        notes = [item for item in self.client.list_items() if is_pgp_note(item)]
        self._progress(f"  found {len(notes)} PGP note(s) in vault")
        return notes

    # ------------------------------------------------------------------ #
    # Matching
    # ------------------------------------------------------------------ #
    def _find_match(
        self, pair: SSHKeyPair, records: List[SSHRecord]
    ) -> Optional[SSHRecord]:
        # Prefer fingerprint match (stable identity)...
        if pair.fingerprint:
            for rec in records:
                if rec.fingerprint and rec.fingerprint == pair.fingerprint:
                    return rec
        # ...then fall back to the item name.
        target = self._item_name(pair)
        for rec in records:
            if rec.name == target:
                return rec
        # ...then private-key body match.
        for rec in records:
            if rec.private_key and _normalize(rec.private_key) == pair.normalized_private():
                return rec
        return None

    def _item_name(self, pair: SSHKeyPair) -> str:
        return f"{self.name_prefix}{pair.name}"

    def _build_item(
        self, pair: SSHKeyPair, template: Dict[str, Any], item_id: Optional[str] = None
    ) -> Dict[str, Any]:
        item = dict(template)
        item["type"] = TYPE_SSH_KEY
        item["name"] = self._item_name(pair)
        item["login"] = None
        item["secureNote"] = None
        item["card"] = None
        item["identity"] = None
        item["sshKey"] = {
            "privateKey": pair.private_key,
            "publicKey": pair.public_key,
            "keyFingerprint": pair.fingerprint,
        }
        if item_id:
            item["id"] = item_id
        return item

    # ------------------------------------------------------------------ #
    # Sync
    # ------------------------------------------------------------------ #
    def sync_pair(
        self,
        pair: SSHKeyPair,
        records: List[SSHRecord],
        template: Dict[str, Any],
        *,
        confirm_update: ConfirmFn = _always_no,
    ) -> SyncResult:
        match = self._find_match(pair, records)
        if match is None:
            self._diagnostic(
                f"    new key — no matching vault entry found for '{pair.name}'"
            )
            item = self._build_item(pair, template)
            created = self.client.create_item(item)
            return SyncResult(
                name=self._item_name(pair),
                fingerprint=pair.fingerprint,
                action=ACTION_CREATED,
                item_id=created.get("id"),
                detail="created new SSH key item",
            )

        # Already present - identical?
        if pair.matches(match.private_key, match.public_key):
            return SyncResult(
                name=match.name,
                fingerprint=pair.fingerprint,
                action=ACTION_UNCHANGED,
                item_id=match.id,
                detail="identical to vault entry",
            )

        # Differs — emit comparison diagnostics
        diffs = _compare_keys(pair, match)
        self._diagnostic(
            _diagnose_ssh_line("diff", pair.fingerprint, match.fingerprint, match.id, diffs)
        )

        if not confirm_update(pair, match):
            return SyncResult(
                name=match.name,
                fingerprint=pair.fingerprint,
                action=ACTION_DECLINED,
                item_id=match.id,
                detail="differs from vault entry; update declined",
            )

        item = self._build_item(pair, template, item_id=match.id)
        self.client.edit_item(match.id, item)
        return SyncResult(
            name=match.name,
            fingerprint=pair.fingerprint,
            action=ACTION_UPDATED,
            item_id=match.id,
            detail="updated existing SSH key item",
        )

    def sync_directory(
        self,
        ssh_dir: Optional[str] = None,
        *,
        confirm_update: ConfirmFn = _always_no,
        derive_missing_public: bool = True,
    ) -> List[SyncResult]:
        pairs = scan_ssh_dir(ssh_dir, derive_missing_public=derive_missing_public)
        self._progress(f"  found {len(pairs)} key pair(s) on disk")
        records = self.load_ssh_records()
        template = self.client.get_template("item")
        results: List[SyncResult] = []
        for i, pair in enumerate(pairs, 1):
            self._progress(f"  [{i}/{len(pairs)}] processing {pair.name} …")
            self._diagnostic(
                f"    local fp: {pair.fingerprint or '?'}  encrypted: {pair.encrypted}"
            )
            results.append(
                self.sync_pair(pair, records, template, confirm_update=confirm_update)
            )
            # Refresh local view so a freshly created item is matched next time.
            if results[-1].action == ACTION_CREATED and results[-1].item_id:
                records.append(
                    SSHRecord(
                        id=results[-1].item_id,
                        name=self._item_name(pair),
                        private_key=pair.private_key,
                        public_key=pair.public_key,
                        fingerprint=pair.fingerprint,
                    )
                )
        return results

    def sync_from_server(
        self,
        ssh_dir: Optional[str] = None,
        *,
        confirm_overwrite: bool = False,
    ) -> List[SyncResult]:
        """Pull SSH keys from the vault and write them to *ssh_dir*.

        Returns a list of SyncResult describing what was done.
        """
        directory = Path(ssh_dir).expanduser() if ssh_dir else Path.home() / ".ssh"
        self._progress(f"  writing keys to {directory} …")
        records = self.load_ssh_records()
        if not records:
            self._progress("  no SSH records in vault")
            return []

        results: List[SyncResult] = []
        for rec in records:
            bare = rec.name.replace(self.name_prefix, "").replace("/", "_")
            priv_path = directory / bare
            pub_path = directory / f"{bare}.pub"

            self._progress(f"  processing {bare} …")
            self._diagnostic(
                f"    vault fp: {rec.fingerprint or '?'}  item: {rec.id}"
            )

            # Check if local files exist and compare
            priv_exists = priv_path.is_file()
            pub_exists = pub_path.is_file()
            local_private = priv_path.read_text(encoding="utf-8", errors="ignore") if priv_exists else ""
            local_public = pub_path.read_text(encoding="utf-8", errors="ignore") if pub_exists else ""
            local_private_norm = _normalize(local_private)
            local_public_norm = _normalize(local_public)
            vault_private_norm = _normalize(rec.private_key)
            vault_public_norm = _normalize(rec.public_key)

            priv_diff = local_private_norm != vault_private_norm
            pub_diff = local_public_norm != vault_public_norm

            if not priv_exists and not pub_exists:
                # New key from vault
                self._diagnostic(f"    new key — not present on disk")
                priv_path.parent.mkdir(parents=True, exist_ok=True)
                priv_path.write_text(rec.private_key)
                os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
                if rec.public_key:
                    pub_path.write_text(rec.public_key)
                results.append(SyncResult(
                    name=bare,
                    fingerprint=rec.fingerprint,
                    action=ACTION_CREATED,
                    item_id=rec.id,
                    detail="written from vault",
                ))
                continue

            if not priv_diff and not pub_diff:
                # Identical
                results.append(SyncResult(
                    name=bare,
                    fingerprint=rec.fingerprint,
                    action=ACTION_UNCHANGED,
                    item_id=rec.id,
                    detail="identical to local key",
                ))
                continue

            # Differs
            diff_fields = []
            if priv_diff:
                diff_fields.append("private key")
            if pub_diff:
                diff_fields.append("public key")
            diffs = ", ".join(diff_fields)
            self._diagnostic(f"    {diffs} differ from vault copy")

            if not confirm_overwrite:
                results.append(SyncResult(
                    name=bare,
                    fingerprint=rec.fingerprint,
                    action=ACTION_DECLINED,
                    item_id=rec.id,
                    detail=f"differs from local key; overwrite declined",
                ))
                continue

            priv_path.write_text(rec.private_key)
            os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)
            if rec.public_key:
                pub_path.write_text(rec.public_key)
            results.append(SyncResult(
                name=bare,
                fingerprint=rec.fingerprint,
                action=ACTION_UPDATED,
                item_id=rec.id,
                detail=f"overwritten from vault ({diffs})",
            ))

        return results

    # ------------------------------------------------------------------ #
    # Delete
    # ------------------------------------------------------------------ #
    def delete_ssh(
        self, identifier: str, *, permanent: bool = False
    ) -> List[SyncResult]:
        """Delete SSH item(s) matching *identifier* (id, name, or fingerprint)."""
        records = self.load_ssh_records()
        targets = [
            r
            for r in records
            if identifier in (r.id, r.name, r.fingerprint)
            or identifier == r.name.replace(self.name_prefix, "")
        ]
        self._progress(f"  found {len(targets)} item(s) to delete")
        results: List[SyncResult] = []
        for rec in targets:
            self._progress(f"  deleting {rec.name} …")
            self._diagnostic(
                f"    item: {rec.id}  fp: {rec.fingerprint or '?'}"
            )
            self.client.delete_item(rec.id, permanent=permanent)
            results.append(
                SyncResult(
                    name=rec.name,
                    fingerprint=rec.fingerprint,
                    action="deleted",
                    item_id=rec.id,
                    detail="permanent" if permanent else "moved to trash",
                )
            )
        return results
