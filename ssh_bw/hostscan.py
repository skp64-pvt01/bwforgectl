"""Scan the local host for SSH and GPG key material.

Provides host-level scanning that combines SSH key discovery (delegated to
:mod:`sshscan`) with GPG key discovery via ``gpg`` CLI, plus fingerprint
matching utilities for fuzzy search.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .sshscan import SSHKeyPair, _normalize, scan_ssh_dir

# --------------------------------------------------------------------------- #
# GPG key discovery
# --------------------------------------------------------------------------- #


@dataclass
class GPGKey:
    """A GPG key discovered on the local host."""

    key_id: str          # short key ID (last 8 hex chars of fingerprint)
    fingerprint: str     # full fingerprint (40 hex chars, no spaces)
    user_ids: List[str]  # UID strings (name + email)
    has_secret: bool     # True for private keys, False for public-only
    key_type: str = ""   # e.g. "ed25519", "rsa4096"
    created: str = ""    # creation date string

    @property
    def fingerprint_md5(self) -> str:
        """GPG doesn't use MD5 fingerprints; return empty."""
        return ""

    @property
    def fingerprint_sha256(self) -> str:
        """Return the GPG fingerprint formatted with spaces (standard display)."""
        fp = self.fingerprint.upper()
        return " ".join(fp[i:i+4] for i in range(0, len(fp), 4))

    @property
    def display_name(self) -> str:
        """Best human-readable label for this key."""
        if self.user_ids:
            return self.user_ids[0]
        return self.key_id


# A unified type for host key listing
def _extract_public_key_body(public_key_text: str) -> str:
    """Extract the base64 key body from an SSH public key line.

    An SSH public key looks like: ``ssh-ed25519 AAAAC3Nza... comment``.
    Returns the base64-encoded key material (the second field), or empty string.
    """
    if not public_key_text:
        return ""
    parts = public_key_text.strip().split()
    if len(parts) >= 2:
        # Filter out algorithm identifiers (ssh-rsa, ssh-ed25519, etc.)
        algo = parts[0].lower()
        if algo.startswith("ssh-") or algo.startswith("ecdsa-") or algo.startswith("sk-"):
            return parts[1]
        # If it doesn't look like an algo prefix, return the first base64-ish token
        if len(parts[0]) > 20 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in parts[0]):
            return parts[0]
    # Single token — it might be the raw base64 body
    stripped = public_key_text.strip()
    if len(stripped) > 20 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in stripped):
        return stripped
    return ""


@dataclass
class HostKeyEntry:
    """A unified entry for host key listing — either SSH or GPG."""

    name: str
    key_type: str          # "ssh" or "gpg"
    fingerprint: str       # primary fingerprint (SHA256 for SSH, hex for GPG)
    fingerprint_md5: str   # MD5 fingerprint (SSH only)
    fingerprint_sha256: str  # SHA256 fingerprint (SSH only)
    public_key_body: str = ""  # base64 key material (for fragment search)
    comment: str = ""
    encrypted: bool = False
    source_path: str = ""  # file path for SSH, "gpg" for GPG
    extra: str = ""        # additional info (key ID for GPG, etc.)

    @classmethod
    def from_ssh_pair(cls, pair: SSHKeyPair, md5_fp: str = "") -> "HostKeyEntry":
        return cls(
            name=pair.name,
            key_type="ssh",
            fingerprint=pair.fingerprint or "",
            fingerprint_md5=md5_fp,
            fingerprint_sha256=pair.fingerprint or "",
            public_key_body=_extract_public_key_body(pair.public_key),
            comment=pair.comment,
            encrypted=pair.encrypted,
            source_path=str(pair.private_path),
        )

    @classmethod
    def from_gpg_key(cls, gpg: GPGKey) -> "HostKeyEntry":
        return cls(
            name=gpg.display_name,
            key_type="gpg",
            fingerprint=gpg.fingerprint,
            fingerprint_md5="",
            fingerprint_sha256="",
            public_key_body="",
            comment=", ".join(gpg.user_ids),
            source_path="gpg",
            extra=gpg.key_id,
        )


def _run_gpg_colons(args: List[str]) -> str:
    """Run gpg --with-colons and return stdout, or empty string on failure."""
    try:
        proc = subprocess.run(
            ["gpg"] + args,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    return proc.stdout


def _parse_gpg_colons(output: str, secret_only: bool = True) -> List[GPGKey]:
    """Parse gpg --with-colons output into GPGKey objects.

    The --with-colons format:
      sec:...  — secret key record
      pub:...  — public key record
      fpr:...  — fingerprint record (field 9 = full fingerprint)
      uid:...  — user ID record (field 9 = display name)
    """
    keys: dict = {}  # keygrip -> partial GPGKey
    result: List[GPGKey] = []
    current_keygrip: Optional[str] = None

    for line in output.strip().split("\n"):
        if not line:
            continue
        fields = line.split(":")
        record_type = fields[0]

        if record_type == "sec":
            # Secret key
            key_id = fields[4] if len(fields) > 4 else ""
            key_type = f"{fields[3]}{fields[2]}" if len(fields) > 3 else ""
            created = fields[5] if len(fields) > 5 else ""
            current_keygrip = key_id
            keys[current_keygrip] = GPGKey(
                key_id=key_id,
                fingerprint="",
                user_ids=[],
                has_secret=True,
                key_type=key_type,
                created=created,
            )
        elif record_type == "pub" and not secret_only:
            key_id = fields[4] if len(fields) > 4 else ""
            key_type = f"{fields[3]}{fields[2]}" if len(fields) > 3 else ""
            created = fields[5] if len(fields) > 5 else ""
            current_keygrip = key_id
            if key_id not in keys:
                key_current_keygrip = key_id
                keys[key_current_keygrip] = GPGKey(
                    key_id=key_id,
                    fingerprint="",
                    user_ids=[],
                    has_secret=False,
                    key_type=key_type,
                    created=created,
                )
        elif record_type == "fpr":
            fp = fields[9] if len(fields) > 9 else ""
            # Associate with the most recent key record
            if current_keygrip and current_keygrip in keys:
                keys[current_keygrip].fingerprint = fp
            else:
                # fpr without preceding sec/pub — find by key ID
                kid = fields[4] if len(fields) > 4 else ""
                if kid and kid in keys:
                    keys[kid].fingerprint = fp
        elif record_type == "uid":
            uid = fields[9] if len(fields) > 9 else ""
            uid = _decode_gpg_uid(uid)
            if current_keygrip and current_keygrip in keys:
                keys[current_keygrip].user_ids.append(uid)

    # Return only keys that have a fingerprint
    return [k for k in keys.values() if k.fingerprint]


def _decode_gpg_uid(encoded: str) -> str:
    """Decode a GPG colon-escaped UID string (hex-encoded UTF-8)."""
    if not encoded:
        return ""
    # GPG encodes some characters as hex escapes like \x3a
    # Simple approach: try to decode directly; the raw string is usually usable
    try:
        # It may contain escape sequences; replace common ones
        decoded = encoded
        # Replace \xHH with actual character
        decoded = re.sub(
            r"\\x([0-9a-fA-F]{2})",
            lambda m: chr(int(m.group(1), 16)),
            decoded,
        )
        return decoded
    except (ValueError, TypeError):
        return encoded


def scan_gpg_keys(secret_only: bool = True) -> List[GPGKey]:
    """Scan the local GPG keyring for keys.

    Args:
        secret_only: If True, only return keys with a secret (private) key.

    Returns:
        List of GPGKey objects.
    """
    args = [
        "--list-secret-keys" if secret_only else "--list-keys",
        "--with-colons",
        "--fingerprint",
    ]
    output = _run_gpg_colons(args)
    if not output:
        return []
    return _parse_gpg_colons(output, secret_only=secret_only)


# --------------------------------------------------------------------------- #
# SSH fingerprint helpers
# --------------------------------------------------------------------------- #


def _ssh_md5_fingerprint(public_key_text: str) -> str:
    """Compute the MD5 fingerprint of an SSH public key."""
    try:
        proc = subprocess.run(
            ["ssh-keygen", "-l", "-E", "md5", "-f", "-"],
            input=public_key_text,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    if proc.returncode != 0:
        return ""
    # Output format: "2048 MD5:xx:xx:... comment (RSA)"
    parts = proc.stdout.strip().split()
    for part in parts:
        if part.startswith("MD5:"):
            return part
    return ""


def _ssh_sha256_fingerprint(public_key_text: str) -> str:
    """Compute the SHA256 fingerprint of an SSH public key."""
    try:
        proc = subprocess.run(
            ["ssh-keygen", "-l", "-f", "-"],
            input=public_key_text,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    if proc.returncode != 0:
        return ""
    # Output: "256 SHA256:xxxx... comment (ED25519)"
    parts = proc.stdout.strip().split()
    if len(parts) >= 2:
        return parts[1]
    return ""


# --------------------------------------------------------------------------- #
# Unified host scan
# --------------------------------------------------------------------------- #


def scan_host_keys(
    ssh_dir: Optional[str] = None,
    *,
    include_ssh: bool = True,
    include_gpg: bool = True,
) -> List[HostKeyEntry]:
    """Scan local host for SSH and/or GPG keys.

    Returns a unified list of HostKeyEntry objects.
    """
    entries: List[HostKeyEntry] = []

    if include_ssh:
        pairs = scan_ssh_dir(ssh_dir)
        for pair in pairs:
            md5_fp = ""
            if pair.public_key:
                md5_fp = _ssh_md5_fingerprint(pair.public_key)
            elif pair.private_key:
                # Try to derive public key first
                from .sshscan import _derive_public_from_private_text
                pub = _derive_public_from_private_text(pair.private_key)
                if pub:
                    md5_fp = _ssh_md5_fingerprint(pub)
            entries.append(HostKeyEntry.from_ssh_pair(pair, md5_fp))

    if include_gpg:
        gpg_keys = scan_gpg_keys(secret_only=True)
        for gk in gpg_keys:
            entries.append(HostKeyEntry.from_gpg_key(gk))

    return entries


# --------------------------------------------------------------------------- #
# Fuzzy search
# --------------------------------------------------------------------------- #


def _normalize_fingerprint_query(query: str) -> str:
    """Normalize a fingerprint query for loose matching.

    Strips colons, spaces, 'MD5:', 'SHA256:', '0x' prefixes, and lowercases.
    """
    q = query.strip().lower()
    # Remove common prefixes
    for prefix in ("md5:", "sha256:", "0x"):
        if q.startswith(prefix):
            q = q[len(prefix):]
    # Remove colons, spaces, hyphens
    q = re.sub(r"[:\s-]", "", q)
    return q


def fuzzy_match_host(
    entries: List[HostKeyEntry],
    query: str,
    *,
    prefer_md5: bool = False,
    prefer_sha256: bool = False,
) -> List[HostKeyEntry]:
    """Fuzzy-match host key entries against a query string.

    Matching is case-insensitive and strips formatting from fingerprints.
    Matches against: name, comment, fingerprint (MD5 and SHA256).

    Args:
        entries: List of host key entries to search.
        query: Search query (name, comment, or fingerprint fragment).
        prefer_md5: If True, only match against MD5 fingerprints.
        prefer_sha256: If True, only match against SHA256 fingerprints.
            (default: match both).

    Returns:
        Matching entries ordered by relevance (exact fingerprint > name match > comment match).
    """
    q = query.strip().lower()
    q_norm = _normalize_fingerprint_query(query)

    # Score each entry
    scored: List[tuple] = []  # (score, entry)
    for entry in entries:
        score = 0
        # Exact fingerprint match is strongest
        if prefer_md5 and entry.fingerprint_md5:
            fp_norm = _normalize_fingerprint_query(entry.fingerprint_md5)
            if q_norm and q_norm in fp_norm:
                score = 100
        elif prefer_sha256 and entry.fingerprint_sha256:
            fp_norm = _normalize_fingerprint_query(entry.fingerprint_sha256)
            if q_norm and q_norm in fp_norm:
                score = 100
        else:
            # Match all fingerprints
            for fp in (entry.fingerprint_md5, entry.fingerprint_sha256):
                if not fp:
                    continue
                fp_norm = _normalize_fingerprint_query(fp)
                if q_norm and q_norm in fp_norm:
                    score = max(score, 100)
                    break

        # Name match (substring)
        if q in entry.name.lower():
            score = max(score, 50)
        # Comment match
        if entry.comment and q in entry.comment.lower():
            score = max(score, 30)
        # Extra field match
        if entry.extra and q in entry.extra.lower():
            score = max(score, 20)
        # Public key body match (base64 fragment)
        if entry.public_key_body and q in entry.public_key_body:
            score = max(score, 35)
        elif entry.public_key_body and entry.public_key_body in q:
            score = max(score, 25)
        # Fuzzy: query is a substring of fingerprint or vice versa
        if score == 0:
            for fp in (entry.fingerprint, entry.fingerprint_md5, entry.fingerprint_sha256):
                fp_norm = _normalize_fingerprint_query(fp)
                if fp_norm and (q_norm in fp_norm or fp_norm in q_norm):
                    score = 10
                    break

        if score > 0:
            scored.append((score, entry))

    # Sort by score descending
    scored.sort(key=lambda x: x[0], reverse=True)
    return [entry for _, entry in scored]


def fuzzy_match_vault(
    records: list,
    query: str,
    *,
    prefer_md5: bool = False,
    prefer_sha256: bool = False,
) -> list:
    """Fuzzy-match vault SSH records against a query string.

    Args:
        records: List of SSHRecord objects (from importer).
        query: Search query.
        prefer_md5 / prefer_sha256: Filter by fingerprint type.

    Returns:
        Matching records ordered by relevance.
    """
    q = query.strip().lower()
    q_norm = _normalize_fingerprint_query(query)

    scored = []
    for rec in records:
        score = 0
        # Fingerprint match
        fp = getattr(rec, "fingerprint", "")
        if fp:
            fp_norm = _normalize_fingerprint_query(fp)
            if q_norm and q_norm in fp_norm:
                score = 100
        # Name match
        name = getattr(rec, "name", "")
        if name and q in name.lower():
            score = max(score, 50)
        # ID match
        rid = getattr(rec, "id", "")
        if rid and q in rid.lower():
            score = max(score, 40)
        # Public key body match
        pub_key = getattr(rec, "public_key", "") or ""
        if pub_key:
            body = _extract_public_key_body(pub_key)
            if body and q in body:
                score = max(score, 35)
            elif body and body in q:
                score = max(score, 25)
        # Fuzzy fingerprint substring
        if score == 0 and fp:
            fp_norm = _normalize_fingerprint_query(fp)
            if fp_norm and (q_norm in fp_norm or fp_norm in q_norm):
                score = 10

        if score > 0:
            scored.append((score, rec))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [r for _, r in scored]


# --------------------------------------------------------------------------- #
# Table formatter
# --------------------------------------------------------------------------- #


def format_table(
    headers: List[str],
    rows: List[List[str]],
    *,
    min_gap: int = 3,
) -> str:
    """Format data as an aligned table with consistent column widths.

    Args:
        headers: Column header strings.
        rows: Data rows, each a list of strings matching the header count.
        min_gap: Minimum spaces between columns.

    Returns:
        Formatted table string.
    """
    if not headers:
        return ""

    ncols = len(headers)
    # Pad rows to match header count
    padded_rows: List[List[str]] = []
    for row in rows:
        padded = list(row)
        while len(padded) < ncols:
            padded.append("")
        padded_rows.append(padded[:ncols])

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in padded_rows:
        for i, cell in enumerate(row):
            if i < ncols:
                widths[i] = max(widths[i], len(str(cell)))

    # Build the table
    lines: List[str] = []

    # Header
    header_line = ""
    for i, h in enumerate(headers):
        header_line += h.ljust(widths[i])
        if i < ncols - 1:
            header_line += " " * min_gap
    lines.append(header_line)

    # Separator
    sep_line = ""
    for i in range(ncols):
        sep_line += "-" * widths[i]
        if i < ncols - 1:
            sep_line += " " * min_gap
    lines.append(sep_line)

    # Data rows
    for row in padded_rows:
        row_line = ""
        for i, cell in enumerate(row):
            row_line += str(cell).ljust(widths[i])
            if i < ncols - 1:
                row_line += " " * min_gap
        lines.append(row_line)

    return "\n".join(lines)
