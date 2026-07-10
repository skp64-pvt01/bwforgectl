"""Secure storage for the Bitwarden e-mail/username and master password.

Two backends are supported, selected automatically:

1. **keyring** - the OS secret service (GNOME Keyring / KWallet / macOS
   Keychain / Windows Credential Manager) when the ``keyring`` package is
   importable.  Nothing is written to disk in plaintext.

2. **encrypted file** - a fallback that stores the credentials in
    ``~/.config/bwforgectl/credentials.enc`` encrypted with AES (Fernet).  The
   encryption key is derived (PBKDF2-HMAC-SHA256) from a *store passphrase*
   the user provides; the passphrase itself is never written to disk.

Credentials may always be supplied at run time (prompt / CLI / env var)
without persisting them at all.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:  # optional dependency
    import keyring  # type: ignore

    _HAS_KEYRING = True
except Exception:  # pragma: no cover - depends on environment
    keyring = None  # type: ignore
    _HAS_KEYRING = False

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
SERVICE_NAME = "bwforgectl"

_DEFAULT_CONFIG_DIR = Path.home() / ".config" / "bwforgectl"
_KDF_ITERATIONS = 390_000


@dataclass
class Credentials:
    """Bitwarden account credentials."""

    email: str
    password: str

    def is_complete(self) -> bool:
        return bool(self.email and self.password)


class CredentialError(Exception):
    """Raised when stored credentials cannot be read/decrypted."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


class CredentialStore:
    """Persist / retrieve :class:`Credentials` securely.

    Parameters
    ----------
    config_dir:
        Directory for the encrypted fallback file.
    prefer_keyring:
        Use the OS keyring when available (default True).
    """

    def __init__(
        self,
        config_dir: Optional[os.PathLike] = None,
        *,
        prefer_keyring: bool = True,
    ) -> None:
        self.config_dir = Path(config_dir).expanduser() if config_dir else _DEFAULT_CONFIG_DIR
        self.enc_path = self.config_dir / "credentials.enc"
        self.use_keyring = bool(prefer_keyring and _HAS_KEYRING)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    @property
    def backend(self) -> str:
        return "keyring" if self.use_keyring else "encrypted-file"

    def has_credentials(self) -> bool:
        if self.use_keyring:
            try:
                return keyring.get_password(SERVICE_NAME, "email") is not None
            except Exception:
                return False
        return self.enc_path.is_file()

    def save(self, creds: Credentials, *, store_passphrase: Optional[str] = None) -> None:
        """Persist *creds*.

        ``store_passphrase`` is required for the encrypted-file backend and
        ignored for the keyring backend.
        """
        if self.use_keyring:
            keyring.set_password(SERVICE_NAME, "email", creds.email)
            keyring.set_password(SERVICE_NAME, "password", creds.password)
            return

        if not store_passphrase:
            raise CredentialError(
                "A store passphrase is required to encrypt credentials on disk."
            )
        self.config_dir.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(16)
        key = _derive_key(store_passphrase, salt)
        token = Fernet(key).encrypt(
            json.dumps({"email": creds.email, "password": creds.password}).encode("utf-8")
        )
        payload = {
            "version": 1,
            "salt": base64.b64encode(salt).decode("ascii"),
            "token": token.decode("ascii"),
        }
        tmp = self.enc_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload))
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        tmp.replace(self.enc_path)
        os.chmod(self.enc_path, stat.S_IRUSR | stat.S_IWUSR)

    def load(self, *, store_passphrase: Optional[str] = None) -> Credentials:
        """Load persisted credentials.

        ``store_passphrase`` is required for the encrypted-file backend.
        """
        if self.use_keyring:
            email = keyring.get_password(SERVICE_NAME, "email")
            password = keyring.get_password(SERVICE_NAME, "password")
            if not email or not password:
                raise CredentialError("No credentials stored in the system keyring.")
            return Credentials(email=email, password=password)

        if not self.enc_path.is_file():
            raise CredentialError(f"No stored credentials at {self.enc_path}.")
        if not store_passphrase:
            raise CredentialError("A store passphrase is required to decrypt credentials.")
        try:
            payload = json.loads(self.enc_path.read_text())
            salt = base64.b64decode(payload["salt"])
            key = _derive_key(store_passphrase, salt)
            raw = Fernet(key).decrypt(payload["token"].encode("ascii"))
        except (InvalidToken, KeyError, ValueError) as exc:
            raise CredentialError(
                "Could not decrypt stored credentials (wrong passphrase?)."
            ) from exc
        data = json.loads(raw.decode("utf-8"))
        return Credentials(email=data["email"], password=data["password"])

    def delete(self) -> bool:
        """Remove any persisted credentials. Returns True if something was removed."""
        removed = False
        if self.use_keyring:
            for key in ("email", "password"):
                try:
                    if keyring.get_password(SERVICE_NAME, key) is not None:
                        keyring.delete_password(SERVICE_NAME, key)
                        removed = True
                except Exception:
                    pass
            return removed
        if self.enc_path.is_file():
            self.enc_path.unlink()
            removed = True
        return removed
