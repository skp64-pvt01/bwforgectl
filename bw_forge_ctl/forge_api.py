"""REST API clients for GitHub and GitLab to manage SSH and GPG keys.

Uses only the Python standard library (``urllib.request``) so no additional
dependencies are needed beyond what ``bwforgectl`` already requires.
"""

from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #


class ForgeError(Exception):
    """Base exception for forge API operations."""


class ForgeAuthError(ForgeError):
    """Authentication failed (401)."""


class ForgeRateLimitError(ForgeError):
    """Rate limit exceeded (403 with rate-limit headers)."""


class ForgeValidationError(ForgeError):
    """Request validation failed (422)."""


class ForgeNotFoundError(ForgeError):
    """Resource not found (404)."""


# --------------------------------------------------------------------------- #
# Data
# --------------------------------------------------------------------------- #


@dataclass
class ForgeSSHKey:
    id: int
    title: str
    key: str
    fingerprint: str = ""


@dataclass
class ForgeGPGKey:
    id: int
    key_id: str  # long key ID (hex)
    public_key: str  # armored ASCII
    emails: List[str] = None


# --------------------------------------------------------------------------- #
# Token resolution from Bitwarden
# --------------------------------------------------------------------------- #

TOKEN_NAME_RE = re.compile(
    r"^git:\s+(github|gitlab):\s+(.+?):\s+(pat|token|api)\s*$", re.IGNORECASE
)


def resolve_forge_token(
    client: Any,
    platform: str,
    account_name: str,
) -> Optional[str]:
    """Look up a forge API token from the Bitwarden vault.

    Searches for items matching the naming convention
    ``git: <platform>: <account-name>: pat`` and returns the password
    field of the first match.
    """
    for item in client.list_items():
        name = str(item.get("name", ""))
        m = TOKEN_NAME_RE.match(name)
        if not m:
            continue
        if m.group(1).lower() == platform.lower() and m.group(2).strip().lower() == account_name.lower():
            login = item.get("login") or {}
            password = login.get("password", "")
            if password:
                return password
    return None


# --------------------------------------------------------------------------- #
# Forge API client
# --------------------------------------------------------------------------- #


class ForgeAPI:
    """REST API client for GitHub or GitLab.

    Uses ``Authorization: Bearer`` for GitHub and ``PRIVATE-TOKEN`` for
    GitLab.  All methods raise :class:`ForgeError` subclasses on failure.
    """

    def __init__(self, platform: str, token: str, hostname: Optional[str] = None):
        self.platform = platform.lower()
        self.token = token
        if self.platform == "github":
            base = hostname or "api.github.com"
            self.base_url = f"https://{base}"
        elif self.platform == "gitlab":
            base = hostname or "gitlab.com"
            self.base_url = f"https://{base}/api/v4"
        else:
            raise ForgeError(f"Unsupported platform: {platform}")

    def _headers(self) -> Dict[str, str]:
        h = {
            "Accept": "application/json",
            "User-Agent": "bwforgectl/1.0",
        }
        if self.platform == "github":
            h["Authorization"] = f"Bearer {self.token}"
            h["X-GitHub-Api-Version"] = "2022-11-28"
        elif self.platform == "gitlab":
            h["PRIVATE-TOKEN"] = self.token
        return h

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(
            url,
            data=data,
            headers=self._headers(),
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            status = exc.code
            body_text = exc.read().decode("utf-8", errors="replace")
            if status == 401:
                raise ForgeAuthError(
                    f"Authentication failed (401): {body_text}"
                ) from exc
            if status == 403:
                raise ForgeRateLimitError(
                    f"Rate limited or forbidden (403): {body_text}"
                ) from exc
            if status == 404:
                raise ForgeNotFoundError(
                    f"Not found (404): {body_text}"
                ) from exc
            if status == 422:
                raise ForgeValidationError(
                    f"Validation error (422): {body_text}"
                ) from exc
            raise ForgeError(
                f"HTTP {status} on {method} {path}: {body_text}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ForgeError(f"Request failed: {exc.reason}") from exc

    # ------------------------------------------------------------------ #
    # SSH keys
    # ------------------------------------------------------------------ #

    def list_ssh_keys(self) -> List[ForgeSSHKey]:
        data = self._request("GET", "/user/keys")
        return [
            ForgeSSHKey(
                id=item["id"],
                title=item.get("title", "") or "",
                key=item.get("key", "") or "",
                fingerprint=self._extract_ssh_fingerprint(item),
            )
            for item in (data or [])
        ]

    def add_ssh_key(self, title: str, key: str) -> ForgeSSHKey:
        data = self._request("POST", "/user/keys", {"title": title, "key": key})
        return ForgeSSHKey(
            id=data["id"],
            title=data.get("title", "") or "",
            key=data.get("key", "") or "",
        )

    def delete_ssh_key(self, key_id: int) -> bool:
        self._request("DELETE", f"/user/keys/{key_id}")
        return True

    def replace_ssh_key(self, old_key_id: int, title: str, key: str) -> ForgeSSHKey:
        self.delete_ssh_key(old_key_id)
        return self.add_ssh_key(title, key)

    # ------------------------------------------------------------------ #
    # GPG keys
    # ------------------------------------------------------------------ #

    def list_gpg_keys(self) -> List[ForgeGPGKey]:
        data = self._request("GET", "/user/gpg_keys")
        return [
            ForgeGPGKey(
                id=item["id"],
                key_id=item.get("key_id", "") or "",
                public_key=item.get("public_key", "") or "",
                emails=[e.get("email", "") for e in (item.get("emails") or [])],
            )
            for item in (data or [])
        ]

    def add_gpg_key(self, armored_public_key: str) -> ForgeGPGKey:
        data = self._request(
            "POST",
            "/user/gpg_keys",
            {"armored_public_key": armored_public_key},
        )
        return ForgeGPGKey(
            id=data["id"],
            key_id=data.get("key_id", "") or "",
            public_key=data.get("public_key", "") or "",
            emails=[e.get("email", "") for e in (data.get("emails") or [])],
        )

    def delete_gpg_key(self, key_id: int) -> bool:
        self._request("DELETE", f"/user/gpg_keys/{key_id}")
        return True

    def replace_gpg_key(self, old_key_id: int, armored_public_key: str) -> ForgeGPGKey:
        self.delete_gpg_key(old_key_id)
        return self.add_gpg_key(armored_public_key)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_ssh_fingerprint(item: Dict[str, Any]) -> str:
        raw = item.get("key", "")
        if not raw:
            return ""
        try:
            parts = raw.strip().split()
            if len(parts) >= 2:
                fp = subprocess.run(
                    ["ssh-keygen", "-lf", "-"],
                    input=f"{parts[0]} {parts[1]}\n",
                    capture_output=True,
                    text=True,
                )
                if fp.returncode == 0 and fp.stdout:
                    fp_parts = fp.stdout.split()
                    return fp_parts[1] if len(fp_parts) >= 2 else ""
        except Exception:
            pass
        return ""


def forge_key_name(
    platform: str,
    account_name: str,
    key_type: str = "ssh",
) -> str:
    """Generate a descriptive key title for the forge platform."""
    host = f"github.{account_name}.com" if platform == "github" else f"gitlab.{account_name}.com"
    return f"{key_type.upper()} key for {host} — bwforgectl"
