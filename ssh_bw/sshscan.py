"""Scan a directory (default ``~/.ssh``) for SSH key pairs.

A key pair is identified by a private key file together with its matching
``.pub`` public key file.  When the public key is missing it can optionally
be derived from the private key with ``ssh-keygen -y`` (only works for keys
without a passphrase).
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# First line markers that identify an OpenSSH / PEM private key file.
PRIVATE_KEY_MARKERS = (
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
)

# Files in ~/.ssh that are never SSH key material.
NON_KEY_NAMES = {
    "config",
    "known_hosts",
    "known_hosts.old",
    "authorized_keys",
    "authorized_keys2",
    "environment",
    "rc",
}

# A public key line looks like: "ssh-ed25519 AAAA... comment"
_PUBLIC_KEY_RE = re.compile(
    r"^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+)\s+[A-Za-z0-9+/=]+",
)


@dataclass
class SSHKeyPair:
    """A discovered SSH key pair on disk."""

    name: str
    private_path: Path
    public_path: Optional[Path]
    private_key: str
    public_key: str
    fingerprint: str
    comment: str = ""
    encrypted: bool = False
    derived_public: bool = field(default=False, repr=False)

    def normalized_private(self) -> str:
        return _normalize(self.private_key)

    def normalized_public(self) -> str:
        return _normalize(self.public_key)

    def matches(self, private_key: str, public_key: str) -> bool:
        """Return True when the supplied material is identical to this pair."""
        return (
            _normalize(private_key) == self.normalized_private()
            and _normalize(public_key) == self.normalized_public()
        )


def _normalize(text: Optional[str]) -> str:
    """Normalise key text for comparison (strip trailing whitespace/newlines)."""
    if not text:
        return ""
    # Compare line-by-line with trailing whitespace removed and no trailing
    # blank lines, so a stray newline does not look like a difference.
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def is_private_key_file(path: Path) -> bool:
    """Return True if *path* looks like an SSH/PEM private key."""
    if path.name in NON_KEY_NAMES or path.suffix == ".pub":
        return False
    if not path.is_file():
        return False
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            first = fh.readline().strip()
    except OSError:
        return False
    return any(first.startswith(m) for m in PRIVATE_KEY_MARKERS)


def is_public_key_text(text: str) -> bool:
    return bool(_PUBLIC_KEY_RE.match(text.strip()))


def _is_encrypted_private(text: str) -> bool:
    head = text[:512]
    if "ENCRYPTED" in head and "BEGIN" in head:
        return True
    if "Proc-Type: 4,ENCRYPTED" in head:
        return True
    # OpenSSH format: cipher name is in the base64-decoded header.
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in text:
        try:
            lines = text.strip().split("\n")
            body = "".join(
                ln.strip() for ln in lines
                if ln.strip() and "OPENSSH PRIVATE KEY" not in ln
            )
            import struct
            raw = base64.b64decode(body)
            # Format: magic (15 bytes) | cipher_len (uint32 BE) | cipher | ...
            clen = struct.unpack(">I", raw[15:19])[0]
            cipher = raw[19:19 + clen].decode("ascii", errors="replace")
            return cipher != "none"
        except Exception:
            return False
    return False


def _fingerprint_from_public(public_path: Path) -> str:
    """Return the SHA256 fingerprint via ssh-keygen, or '' on failure."""
    try:
        out = subprocess.run(
            ["ssh-keygen", "-lf", str(public_path)],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    parts = out.stdout.split()
    return parts[1] if len(parts) >= 2 else ""


def _fingerprint_from_public_text(public_text: str) -> str:
    try:
        out = subprocess.run(
            ["ssh-keygen", "-lf", "-"],
            input=public_text,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    parts = out.stdout.split()
    return parts[1] if len(parts) >= 2 else ""


def _derive_public_from_private(private_path: Path) -> str:
    """Try to derive the public key from a private key (passphrase-less only)."""
    try:
        out = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(private_path)],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    return out.stdout.strip()


def _derive_public_from_private_text(private_key: str, passphrase: str = "") -> str:
    """Derive the public key from private key content.

    Writes the key to a temp file and runs ``ssh-keygen -y`` on it, which is
    more reliable than piping via stdin.  *passphrase* defaults to empty
    (unencrypted key); pass the actual passphrase for encrypted keys.
    """
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".tmpkey", delete=False) as tmp:
            tmp.write(private_key)
            tmp_path = tmp.name
        try:
            out = subprocess.run(
                ["ssh-keygen", "-y", "-P", passphrase, "-f", tmp_path],
                capture_output=True,
                text=True,
                check=True,
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return ""
    return out.stdout.strip()


def _comment_from_public(public_text: str) -> str:
    parts = public_text.strip().split(None, 2)
    return parts[2] if len(parts) >= 3 else ""


def scan_ssh_dir(
    ssh_dir: Optional[os.PathLike] = None,
    *,
    derive_missing_public: bool = True,
) -> List[SSHKeyPair]:
    """Scan *ssh_dir* and return a list of :class:`SSHKeyPair`.

    Parameters
    ----------
    ssh_dir:
        Directory to scan (defaults to ``~/.ssh``).
    derive_missing_public:
        When True and a public key file is missing, attempt to derive it from
        the private key (only succeeds for passphrase-less keys).
    """
    directory = Path(ssh_dir).expanduser() if ssh_dir else Path.home() / ".ssh"
    pairs: List[SSHKeyPair] = []
    if not directory.is_dir():
        return pairs

    for entry in sorted(directory.iterdir()):
        if not is_private_key_file(entry):
            continue
        try:
            private_text = entry.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        encrypted = _is_encrypted_private(private_text)

        # The public key, if present, is always "<private name>.pub".
        pub_path: Optional[Path] = entry.parent / (entry.name + ".pub")
        public_text = ""
        derived = False
        if pub_path and pub_path.is_file():
            public_text = pub_path.read_text(encoding="utf-8", errors="ignore").strip()
        elif derive_missing_public and not encrypted:
            public_text = _derive_public_from_private(entry)
            if public_text:
                derived = True
                pub_path = None
            else:
                pub_path = None
        else:
            pub_path = None

        # Fingerprint
        if pub_path and pub_path.is_file():
            fingerprint = _fingerprint_from_public(pub_path)
        elif public_text:
            fingerprint = _fingerprint_from_public_text(public_text)
        else:
            fingerprint = ""

        pairs.append(
            SSHKeyPair(
                name=entry.name,
                private_path=entry,
                public_path=pub_path,
                private_key=private_text.strip() + "\n",
                public_key=public_text.strip() + ("\n" if public_text else ""),
                fingerprint=fingerprint,
                comment=_comment_from_public(public_text),
                encrypted=encrypted,
                derived_public=derived,
            )
        )

    return pairs
