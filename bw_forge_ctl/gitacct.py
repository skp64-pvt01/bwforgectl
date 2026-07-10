"""Git account management: create, verify, and audit Git platform
(GitHub / GitLab) accounts managed in a Bitwarden vault.

Naming conventions (from the bwforgectl AGENTS.md):

    +------------------------+------------------------------------+
    | Item type              | Name pattern                       |
    +------------------------+------------------------------------+
    | Login credentials      | ``git: <platform>: <account-name>``|
    | SSH key (type 5)       | ``id_ed25519-<email>``             |
    | Personal Access Token  | ``git: <platform>: <acct>: <type>``|
    | Self-hosted login      | ``git: <hostname>: <username>``    |
    +------------------------+------------------------------------+

    SSH config hosts:
        GitHub:  ``git.<account-name>.com``
        GitLab:  ``gitlab.<account-name>.com``
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .bwclient import TYPE_LOGIN, TYPE_SECURE_NOTE, TYPE_SSH_KEY, BitwardenClient, BitwardenError
from .importer import SSHRecord
from .ssh_config import add_stanza, generate_git_stanza
from .sshscan import SSHKeyPair

# --------------------------------------------------------------------------- #
# Naming conventions (mirrors AGENTS.md)
# --------------------------------------------------------------------------- #

LOGIN_NAME_RE = re.compile(r"^git:\s+(github|gitlab):\s+(.+)$")
SELF_HOSTED_RE = re.compile(r"^git:\s+(.+?):\s+(.+)$")
TOKEN_NAME_RE = re.compile(r"^git:\s+(github|gitlab):\s+(.+?):\s+(.+)$")
SSH_KEY_PREFIX = "id_ed25519-"

DEFAULT_GITHUB_HOST = "github.com"

# --------------------------------------------------------------------------- #
# Audit data
# --------------------------------------------------------------------------- #


@dataclass
class AuditFinding:
    severity: str  # "error" | "warning" | "info"
    category: str
    message: str
    item_id: Optional[str] = None
    item_name: Optional[str] = None
    detail: str = ""


@dataclass
class AuditReport:
    findings: List[AuditFinding] = field(default_factory=list)

    @property
    def errors(self) -> List[AuditFinding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> List[AuditFinding]:
        return [f for f in self.findings if f.severity == "warning"]

    @property
    def infos(self) -> List[AuditFinding]:
        return [f for f in self.findings if f.severity == "info"]

    @property
    def total(self) -> int:
        return len(self.findings)


@dataclass
class AccountVerification:
    platform: str
    account_name: str
    email: str
    ssh_key_name: str
    ssh_host: str
    auth_ok: Optional[bool] = None
    error: str = ""


# --------------------------------------------------------------------------- #
# SSH key generation
# --------------------------------------------------------------------------- #


def generate_ssh_key(
    name: str,
    ssh_dir: Optional[str] = None,
    *,
    key_type: str = "ed25519",
    comment: str = "",
) -> SSHKeyPair:
    """Generate a new SSH key pair using ``ssh-keygen``.

    Returns an :class:`SSHKeyPair` representing the generated key.
    Raises ``FileExistsError`` if the key file already exists.
    """
    directory = Path(ssh_dir).expanduser() if ssh_dir else Path.home() / ".ssh"
    directory.mkdir(parents=True, exist_ok=True)

    priv_path = directory / name
    pub_path = directory / f"{name}.pub"

    if priv_path.exists():
        raise FileExistsError(f"SSH key already exists: {priv_path}")

    cmd = ["ssh-keygen", "-t", key_type, "-f", str(priv_path), "-N", ""]
    if comment:
        cmd += ["-C", comment]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ssh-keygen failed: {result.stderr.strip()}")

    private_text = priv_path.read_text(encoding="utf-8").strip() + "\n"
    public_text = pub_path.read_text(encoding="utf-8").strip()

    fp_result = subprocess.run(
        ["ssh-keygen", "-lf", str(pub_path)],
        capture_output=True,
        text=True,
    )
    fingerprint = ""
    if fp_result.returncode == 0:
        parts = fp_result.stdout.split()
        if len(parts) >= 2:
            fingerprint = parts[1]

    return SSHKeyPair(
        name=name,
        private_path=priv_path,
        public_path=pub_path,
        private_key=private_text,
        public_key=public_text + "\n",
        fingerprint=fingerprint,
        comment=comment or name,
        encrypted=False,
    )


# --------------------------------------------------------------------------- #
# Bitwarden item creation helpers
# --------------------------------------------------------------------------- #


def build_login_item(
    client: BitwardenClient,
    platform: str,
    account_name: str,
    email: str,
    *,
    username: str = "",
    password: str = "",
    totp: str = "",
) -> Dict[str, Any]:
    """Build a Bitwarden login item dict for a git account.

    Item name: ``git: <platform>: <account-name>`` (type 1).
    """
    template = client.get_template("item")
    item = dict(template)
    item["type"] = TYPE_LOGIN
    item["name"] = f"git: {platform}: {account_name}"
    item["login"] = {
        "username": username or email,
        "password": password,
        "totp": totp,
    }
    item["secureNote"] = None
    item["card"] = None
    item["identity"] = None
    return item


def build_ssh_key_item(
    client: BitwardenClient,
    pair: SSHKeyPair,
    *,
    name_prefix: str = "",
) -> Dict[str, Any]:
    """Build a Bitwarden SSH key item dict.

    Item name matches the key filename (type 5).
    """
    template = client.get_template("item")
    item = dict(template)
    ssh_key_name = f"{name_prefix}{pair.name}"
    item["type"] = TYPE_SSH_KEY
    item["name"] = ssh_key_name
    item["login"] = None
    item["secureNote"] = None
    item["card"] = None
    item["identity"] = None
    item["sshKey"] = {
        "privateKey": pair.private_key.strip(),
        "publicKey": pair.public_key.strip(),
        "keyFingerprint": pair.fingerprint or "",
    }
    return item


def create_git_login(
    client: BitwardenClient,
    platform: str,
    account_name: str,
    email: str,
    *,
    username: str = "",
    password: str = "",
    totp: str = "",
) -> Dict[str, Any]:
    """Create a Bitwarden login item for a git account."""
    item = build_login_item(
        client, platform, account_name, email,
        username=username, password=password, totp=totp,
    )
    return client.create_item(item)


def create_ssh_key_vault_item(
    client: BitwardenClient,
    pair: SSHKeyPair,
    *,
    name_prefix: str = "",
) -> Dict[str, Any]:
    """Create a Bitwarden SSH key item for an SSH key pair."""
    item = build_ssh_key_item(client, pair, name_prefix=name_prefix)
    return client.create_item(item)


# --------------------------------------------------------------------------- #
# SSH config stanza generation
# --------------------------------------------------------------------------- #


def generate_ssh_config_stanza(platform: str, account_name: str, key_name: str) -> str:
    """Generate an SSH config Host stanza for the account."""
    if platform == "github":
        host = f"github.{account_name}.com"
        hostname = "github.com"
    else:
        host = f"gitlab.{account_name}.com"
        hostname = "gitlab.com"

    return (
        f"# {platform}: {account_name}\n"
        f"Host {host}\n"
        f"  HostName {hostname}\n"
        f"  User git\n"
        f"  IdentityFile ~/.ssh/{key_name}\n"
        f"  AddKeysToAgent yes\n"
        f"  IdentitiesOnly yes\n"
    )


def install_ssh_config_stanza(
    platform: str, account_name: str, key_name: str,
    ssh_config_path: Optional[str] = None,
) -> bool:
    """Install (add or update) an SSH config stanza for a git account.

    Returns ``True`` if a new stanza was appended, ``False`` if an
    existing one was updated in place.
    """
    stanza = generate_git_stanza(platform, account_name, key_name)
    return add_stanza(stanza, path=ssh_config_path)


# --------------------------------------------------------------------------- #
# Vault item loading & parsing
# --------------------------------------------------------------------------- #


def load_git_logins(client: BitwardenClient) -> List[Dict[str, Any]]:
    """Load all git-related login items (name starts with ``git:``)."""
    items = client.list_items()
    return [
        item for item in items
        if item.get("type") == TYPE_LOGIN
        and str(item.get("name", "")).startswith("git:")
    ]


def load_git_ssh_keys(client: BitwardenClient) -> List[SSHRecord]:
    """Load SSH key items that look git-related.

    Includes keys named ``id_ed25519-*`` (the convention for git account keys).
    """
    records: List[SSHRecord] = []
    for item in client.list_items():
        if item.get("type") != TYPE_SSH_KEY:
            continue
        sk = item.get("sshKey") or {}
        name = str(item.get("name", ""))
        records.append(SSHRecord(
            id=item.get("id", ""),
            name=name,
            private_key=sk.get("privateKey", "") or "",
            public_key=sk.get("publicKey", "") or "",
            fingerprint=sk.get("keyFingerprint", "") or "",
            raw=item,
        ))
    return records


def parse_git_login_name(name: str) -> Optional[Dict[str, str]]:
    """Parse a ``git: <platform>: <account-name>`` item name.

    Returns ``{"platform": …, "account_name": …}`` or ``None``.
    """
    m = LOGIN_NAME_RE.match(name)
    if m:
        return {"platform": m.group(1), "account_name": m.group(2).strip()}
    m = SELF_HOSTED_RE.match(name)
    if m:
        return {"platform": m.group(1), "account_name": m.group(2).strip()}
    return None


# --------------------------------------------------------------------------- #
# Account creation (high-level orchestration)
# --------------------------------------------------------------------------- #


@dataclass
class AccountCreateResult:
    platform: str
    account_name: str
    email: str
    key_name: str
    key_fingerprint: str
    public_key: str
    login_item_id: Optional[str] = None
    ssh_key_item_id: Optional[str] = None
    config_stanza: str = ""
    errors: List[str] = field(default_factory=list)


def create_git_account(
    client: BitwardenClient,
    platform: str,
    account_name: str,
    email: str,
    *,
    username: str = "",
    password: str = "",
    totp: str = "",
    key_type: str = "ed25519",
    ssh_dir: Optional[str] = None,
    skip_login: bool = False,
    skip_ssh_key: bool = False,
    dry_run: bool = False,
) -> AccountCreateResult:
    """Create a complete git account: generate SSH key, create BW items.

    Steps
    -----
    1. Generate an SSH key pair named ``id_ed25519-<email>``.
    2. Create a BW login item ``git: <platform>: <account-name>``.
    3. Create a BW SSH key item ``id_ed25519-<email>``.
    """
    result = AccountCreateResult(
        platform=platform,
        account_name=account_name,
        email=email,
        key_name="",
        key_fingerprint="",
        public_key="",
    )

    key_name = f"id_ed25519-{email}"

    # Step 1: generate SSH key
    try:
        pair = generate_ssh_key(key_name, ssh_dir, key_type=key_type, comment=email)
        result.key_name = pair.name
        result.key_fingerprint = pair.fingerprint or ""
        result.public_key = pair.public_key.strip()
    except (FileExistsError, RuntimeError) as exc:
        result.errors.append(str(exc))
        return result

    if dry_run:
        return result

    # Step 2: create login item
    if not skip_login:
        try:
            login_name = f"git: {platform}: {account_name}"
            created = create_git_login(
                client, platform, account_name, email,
                username=username, password=password, totp=totp,
            )
            result.login_item_id = created.get("id")
        except BitwardenError as exc:
            result.errors.append(f"Failed to create login item: {exc}")

    # Step 3: create SSH key item
    if not skip_ssh_key:
        try:
            created = create_ssh_key_vault_item(client, pair)
            result.ssh_key_item_id = created.get("id")
        except BitwardenError as exc:
            result.errors.append(f"Failed to create SSH key item: {exc}")

    # Config stanza
    result.config_stanza = generate_ssh_config_stanza(
        platform, account_name, key_name,
    )

    return result


# --------------------------------------------------------------------------- #
# SSH authentication verification
# --------------------------------------------------------------------------- #


def try_ssh_auth(host: str, timeout: float = 10.0) -> Tuple[bool, str]:
    """Try SSH authentication against *host*.

    Returns ``(ok, detail)`` where *ok* is True if authentication succeeded.
    """
    try:
        result = subprocess.run(
            [
                "ssh", "-T",
                "-o", "BatchMode=yes",
                "-o", f"ConnectTimeout={int(timeout)}",
                f"git@{host}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        output = result.stdout + result.stderr
        output_lower = output.lower()

        if result.returncode in (0, 1):
            if "permission denied" in output_lower:
                return False, output.strip()
            if "successfully authenticated" in output_lower:
                return True, _extract_auth_message(output)
            return True, output.strip()
        if result.returncode == 255:
            return False, "Connection failed (exit 255)"
        return False, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Connection timed out"
    except FileNotFoundError:
        return False, "ssh not found on PATH"
    except OSError as exc:
        return False, str(exc)


def _extract_auth_message(output: str) -> str:
    for line in output.split("\n"):
        s = line.strip()
        if s and "authenticated" in s.lower():
            return s
    return output.strip()


def ssh_host_for_account(platform: str, account_name: str) -> str:
    """Return the SSH config host for a git account."""
    if platform == "github":
        return f"github.{account_name}.com"
    return f"gitlab.{account_name}.com"


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


def audit_git_vault(client: BitwardenClient) -> AuditReport:
    """Audit the Bitwarden vault for consistency with git account conventions.

    Checks performed
    ----------------
    1. Duplicate login items (same name appearing multiple times).
    2. Duplicate SSH key items.
    3. Login items missing required fields (password, username).
    4. SSH key items missing key material.
    5. Orphan logins — login items with no matching SSH key.
    6. Orphan SSH keys — SSH keys with no matching login.
    7. Naming convention compliance for login items.
    """
    report = AuditReport()
    all_items = client.list_items()

    # Categorise
    logins: List[Dict[str, Any]] = []
    ssh_keys: List[Dict[str, Any]] = []
    for item in all_items:
        name = str(item.get("name", ""))
        t = item.get("type")
        if t == TYPE_LOGIN and name.startswith("git:"):
            logins.append(item)
        elif t == TYPE_SSH_KEY:
            ssh_keys.append(item)

    # ---- 1. Duplicate logins ----
    _check_duplicates(report, logins, "duplicate_login", "Login")

    # ---- 2. Duplicate SSH keys ----
    _check_duplicates(report, ssh_keys, "duplicate_ssh_key", "SSH key")

    # ---- 3. Login missing fields ----
    for item in logins:
        name = str(item.get("name", ""))
        login = item.get("login") or {}
        missing = []
        if not login.get("password"):
            missing.append("password")
        if not login.get("username"):
            missing.append("username")
        if missing:
            report.findings.append(AuditFinding(
                severity="warning",
                category="missing_login_field",
                message=f"Login '{name}' missing: {', '.join(missing)}",
                item_id=item.get("id"),
                item_name=name,
            ))

    # ---- 4. SSH key missing material ----
    for item in ssh_keys:
        name = str(item.get("name", ""))
        sk = item.get("sshKey") or {}
        missing = []
        if not sk.get("privateKey"):
            missing.append("privateKey")
        if not sk.get("publicKey"):
            missing.append("publicKey")
        if missing:
            report.findings.append(AuditFinding(
                severity="error",
                category="incomplete_ssh_key",
                message=f"SSH key '{name}' missing: {', '.join(missing)}",
                item_id=item.get("id"),
                item_name=name,
            ))

    # ---- 5. Orphan logins (no matching SSH key) ----
    ssh_key_names = {str(item.get("name", "")) for item in ssh_keys}
    for item in logins:
        name = str(item.get("name", ""))
        parsed = parse_git_login_name(name)
        if not parsed:
            continue
        acct = parsed["account_name"].lower()
        matched = any(acct in skn.lower() for skn in ssh_key_names)
        if not matched:
            email = ((item.get("login") or {}).get("username") or "").lower()
            email_match = any(email in skn.lower() for skn in ssh_key_names) if email else False
            if not email_match:
                report.findings.append(AuditFinding(
                    severity="warning",
                    category="orphan_login",
                    message=f"Login '{name}' has no matching SSH key",
                    item_id=item.get("id"),
                    item_name=name,
                ))

    # ---- 6. Orphan SSH keys (no matching login) ----
    login_info: List[Tuple[str, str]] = []
    for item in logins:
        login_info.append((
            str(item.get("name", "")),
            ((item.get("login") or {}).get("username") or "").lower(),
        ))
    for item in ssh_keys:
        name = str(item.get("name", ""))
        key_name_lower = name.lower()
        matched = False
        for ln_name, ln_email in login_info:
            if key_name_lower in ln_name.lower() or ln_name.lower() in key_name_lower:
                matched = True
                break
            if ln_email and ln_email in key_name_lower:
                matched = True
                break
        if not matched:
            report.findings.append(AuditFinding(
                severity="info",
                category="orphan_ssh_key",
                message=f"SSH key '{name}' has no matching login item",
                item_id=item.get("id"),
                item_name=name,
            ))

    # ---- 7. Naming convention ----
    for item in logins:
        name = str(item.get("name", ""))
        if not LOGIN_NAME_RE.match(name) and not SELF_HOSTED_RE.match(name):
            report.findings.append(AuditFinding(
                severity="warning",
                category="naming_convention",
                message=f"Login '{name}' does not follow naming convention",
                item_id=item.get("id"),
                item_name=name,
            ))

    return report


def _check_duplicates(
    report: AuditReport,
    items: List[Dict[str, Any]],
    category: str,
    label: str,
) -> None:
    names: Dict[str, List[str]] = {}
    for item in items:
        n = str(item.get("name", ""))
        names.setdefault(n, []).append(str(item.get("id", "")))
    for name, ids in names.items():
        if len(ids) > 1:
            report.findings.append(AuditFinding(
                severity="error",
                category=category,
                message=f"{label} '{name}' appears {len(ids)} times",
                item_id=ids[0],
                item_name=name,
                detail=f"IDs: {', '.join(ids)}",
            ))


# --------------------------------------------------------------------------- #
# GPG key generation
# --------------------------------------------------------------------------- #


@dataclass
class GPGKeyResult:
    fingerprint: str
    key_id: str
    public_key_armored: str
    private_key_armored: str
    name: str
    email: str
    errors: List[str] = field(default_factory=list)


def generate_gpg_key(
    name: str,
    email: str,
    *,
    key_type: str = "ed25519",
    passphrase: str = "",
    expire_date: str = "0",
) -> GPGKeyResult:
    """Generate a new GPG key pair using ``gpg --batch --gen-key``.

    Returns a :class:`GPGKeyResult` with fingerprint, key ID, and
    armored key material.  Raises ``RuntimeError`` if ``gpg`` is not
    available or key generation fails.
    """
    if key_type == "ed25519":
        batch = (
            f"Key-Type: ed25519\n"
            f"Key-Curve: Ed25519\n"
            f"Key-Usage: sign\n"
            f"Subkey-Type: cv25519\n"
            f"Subkey-Usage: encrypt\n"
        )
    else:
        batch = (
            f"Key-Type: RSA\n"
            f"Key-Length: {key_type.removeprefix('rsa') or '4096'}\n"
            f"Key-Usage: sign\n"
            f"Subkey-Type: RSA\n"
            f"Subkey-Length: {key_type.removeprefix('rsa') or '4096'}\n"
            f"Subkey-Usage: encrypt\n"
        )
    batch += (
        f"Name-Real: {name}\n"
        f"Name-Email: {email}\n"
        f"Expire-Date: {expire_date}\n"
    )
    if passphrase:
        batch += f"Passphrase: {passphrase}\n"
    else:
        batch += "%no-protection\n"
    batch += "%commit\n"

    try:
        result = subprocess.run(
            ["gpg", "--batch", "--gen-key"],
            input=batch,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("gpg not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("gpg --gen-key timed out") from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"gpg --gen-key failed: {result.stderr.strip()}"
        )

    # Extract fingerprint from stderr: "gpg: key <hex> marked as ultimately trusted"
    stderr = result.stderr
    fp_match = re.search(r"gpg:\s+key\s+([0-9A-Fa-f]+)\s+marked", stderr)
    if not fp_match:
        fp_match = re.search(r"gpg:\s+key\s+([0-9A-Fa-f]+):", stderr)
    if not fp_match:
        raise RuntimeError(
            f"Could not determine GPG key fingerprint from output:\n{stderr}"
        )

    key_id = fp_match.group(1).upper()
    long_fp = _get_gpg_fingerprint(key_id)

    # Export keys
    public_armored = _gpg_export(f"--armor --export {key_id}")
    private_armored = _gpg_export(f"--armor --export-secret-keys {key_id}")

    return GPGKeyResult(
        fingerprint=long_fp or key_id,
        key_id=key_id,
        public_key_armored=public_armored,
        private_key_armored=private_armored,
        name=name,
        email=email,
    )


def _get_gpg_fingerprint(key_id: str) -> str:
    try:
        result = subprocess.run(
            ["gpg", "--fingerprint", "--with-colons", key_id],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 10 and parts[0] == "fpr":
                return parts[9] if len(parts) > 9 else key_id
    except Exception:
        pass
    return key_id


def _gpg_export(cmd_str: str) -> str:
    try:
        result = subprocess.run(
            ["gpg"] + cmd_str.split(),
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return ""


def store_gpg_key_in_vault(
    client: BitwardenClient,
    gpg_key: GPGKeyResult,
) -> Optional[str]:
    """Store a GPG key as a secure note in the Bitwarden vault.

    The note body contains the armored private key and the item name
    follows the convention ``gpg: <email>``.
    Returns the item ID or ``None`` on failure.
    """
    template = client.get_template("item")
    item = dict(template)
    item["type"] = TYPE_SECURE_NOTE
    item["name"] = f"gpg: {gpg_key.email}"

    note_parts = [
        f"GPG Key: {gpg_key.email}",
        f"Fingerprint: {gpg_key.fingerprint}",
        f"Key ID: {gpg_key.key_id}",
        "",
        gpg_key.private_key_armored,
    ]
    item["notes"] = "\n".join(note_parts)
    item["login"] = None
    item["secureNote"] = {"type": 0}
    item["card"] = None
    item["identity"] = None
    for f in ("fields", "attachments", "collectionIds"):
        item.pop(f, None)

    try:
        created = client.create_item(item)
        return created.get("id")
    except BitwardenError as exc:
        return None


def load_gpg_notes(client: BitwardenClient) -> List[Dict[str, Any]]:
    """Load secure-note items whose name starts with ``gpg:``."""
    from .pgp import text_contains_pgp

    items = []
    for item in client.list_items():
        name = str(item.get("name", ""))
        if item.get("type") != TYPE_SECURE_NOTE:
            continue
        if name.startswith("gpg:") or text_contains_pgp(item.get("notes") or ""):
            items.append(item)
    return items


# --------------------------------------------------------------------------- #
# Forge upload helpers
# --------------------------------------------------------------------------- #


def upload_ssh_key_to_forge(
    platform: str,
    token: str,
    account_name: str,
    public_key: str,
    key_title: Optional[str] = None,
    *,
    replace_existing: bool = False,
) -> Dict[str, Any]:
    """Upload an SSH public key to GitHub or GitLab.

    Returns ``{"status": "created"|"replaced"|"exists", "key_id": int}``.
    """
    from .forge_api import ForgeAPI, forge_key_name

    api = ForgeAPI(platform, token)
    title = key_title or forge_key_name(platform, account_name, "ssh")

    # Check if key already exists
    existing = api.list_ssh_keys()
    for ek in existing:
        if public_key.strip() in ek.key:
            return {"status": "exists", "key_id": ek.id}

    # Delete matching if replacing
    if replace_existing:
        for ek in existing:
            if account_name.lower() in ek.title.lower() or platform in ek.title.lower():
                api.delete_ssh_key(ek.id)

    created = api.add_ssh_key(title, public_key.strip())
    return {"status": "replaced" if replace_existing else "created", "key_id": created.id}


def upload_gpg_key_to_forge(
    platform: str,
    token: str,
    account_name: str,
    armored_public_key: str,
    *,
    replace_existing: bool = False,
) -> Dict[str, Any]:
    """Upload an armored GPG public key to GitHub or GitLab.

    Returns ``{"status": "created"|"replaced"|"exists", "key_id": int}``.
    """
    from .forge_api import ForgeAPI

    api = ForgeAPI(platform, token)

    # Check if key already exists
    existing = api.list_gpg_keys()
    armored_stripped = armored_public_key.strip()
    for ek in existing:
        if ek.public_key.strip() == armored_stripped:
            return {"status": "exists", "key_id": ek.id}

    if replace_existing and existing:
        for ek in existing:
            api.delete_gpg_key(ek.id)

    created = api.add_gpg_key(armored_public_key)
    return {"status": "replaced" if (replace_existing and existing) else "created", "key_id": created.id}
