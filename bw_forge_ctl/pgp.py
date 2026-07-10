"""Helpers for recognising PGP key material stored as Bitwarden secure notes."""

from __future__ import annotations

from typing import Any, Dict

PGP_MARKERS = (
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    "-----BEGIN PGP MESSAGE-----",
)


def text_contains_pgp(text: str) -> bool:
    if not text:
        return False
    return any(marker in text for marker in PGP_MARKERS)


def is_pgp_note(item: Dict[str, Any]) -> bool:
    """True when *item* is a secure note whose body looks like a PGP block.

    Also matches items whose name strongly suggests PGP/GPG so that
    armored exports are still discoverable even with custom formatting.
    """
    if item.get("type") != 2:  # secure note
        return False
    notes = item.get("notes") or ""
    if text_contains_pgp(notes):
        return True
    name = (item.get("name") or "").lower()
    return "pgp" in name or "gpg" in name
