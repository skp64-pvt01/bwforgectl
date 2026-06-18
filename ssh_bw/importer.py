"""Core synchronisation logic between local SSH keys and a Bitwarden vault."""

from __future__ import annotations

from dataclasses import dataclass, field
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


class Importer:
    """Orchestrates scanning and Bitwarden synchronisation."""

    def __init__(self, client: BitwardenClient, *, name_prefix: str = "SSH: ") -> None:
        self.client = client
        self.name_prefix = name_prefix

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
        return records

    def load_pgp_notes(self) -> List[Dict[str, Any]]:
        return [item for item in self.client.list_items() if is_pgp_note(item)]

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

        # Differs - ask for confirmation.
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
        records = self.load_ssh_records()
        template = self.client.get_template("item")
        results: List[SyncResult] = []
        for pair in pairs:
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
        results: List[SyncResult] = []
        for rec in targets:
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
