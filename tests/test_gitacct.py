"""Tests for :mod:`bw_forge_ctl.gitacct`."""

import json
from pathlib import Path

from bw_forge_ctl.bwclient import TYPE_LOGIN, TYPE_SSH_KEY, BitwardenClient
from bw_forge_ctl.gitacct import (
    AuditReport,
    build_login_item,
    build_ssh_key_item,
    create_git_account,
    generate_ssh_config_stanza,
    load_git_logins,
    load_git_ssh_keys,
    parse_git_login_name,
    ssh_host_for_account,
    audit_git_vault,
)
from bw_forge_ctl.importer import ACTION_CREATED
from bw_forge_ctl.sshscan import SSHKeyPair

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_PRIVATE = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2g\n"
    "FAKEKEYDATA1234567890==\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
SAMPLE_PUBLIC = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMMu2ws76gNisO5t30kw7eShE8AIZjqouXmCf0jJqJ31 "
    "tester@example.com\n"
)


def _client(bw_path: str) -> BitwardenClient:
    return BitwardenClient(bw_path=bw_path, session=None)


def _make_pair(name: str, comment: str = "") -> SSHKeyPair:
    return SSHKeyPair(
        name=name,
        private_path=Path(f"/fake/{name}"),
        public_path=Path(f"/fake/{name}.pub"),
        private_key=SAMPLE_PRIVATE,
        public_key=SAMPLE_PUBLIC,
        fingerprint="SHA256:abc123",
        comment=comment or name,
        encrypted=False,
    )


# --------------------------------------------------------------------------- #
# Pure function tests
# --------------------------------------------------------------------------- #


class TestParseGitLoginName:
    def test_github_pattern(self):
        result = parse_git_login_name("git: github: skp1964-dev")
        assert result == {"platform": "github", "account_name": "skp1964-dev"}

    def test_gitlab_pattern(self):
        result = parse_git_login_name("git: gitlab: skpproj01")
        assert result == {"platform": "gitlab", "account_name": "skpproj01"}

    def test_self_hosted(self):
        result = parse_git_login_name("git: gitlab.pilakkat.freeddns.org: root")
        assert result == {"platform": "gitlab.pilakkat.freeddns.org", "account_name": "root"}

    def test_with_extra_colon(self):
        result = parse_git_login_name("git: github: skp1964-dev: pat")
        assert result == {"platform": "github", "account_name": "skp1964-dev: pat"}

    def test_no_match(self):
        assert parse_git_login_name("some random name") is None
        assert parse_git_login_name("SSH: id_ed25519-test") is None


class TestSshHostForAccount:
    def test_github(self):
        assert ssh_host_for_account("github", "skp1964-dev") == "github.skp1964-dev.com"

    def test_gitlab(self):
        assert ssh_host_for_account("gitlab", "skpproj01") == "gitlab.skpproj01.com"


class TestSshConfigStanza:
    def test_github(self):
        stanza = generate_ssh_config_stanza("github", "skp1964-dev", "id_ed25519-dev@outlook.com")
        assert "Host github.skp1964-dev.com" in stanza
        assert "HostName github.com" in stanza
        assert "IdentityFile ~/.ssh/id_ed25519-dev@outlook.com" in stanza
        assert "User git" in stanza
        assert "AddKeysToAgent yes" in stanza
        assert "IdentitiesOnly yes" in stanza

    def test_gitlab(self):
        stanza = generate_ssh_config_stanza("gitlab", "skp64prj", "id_ed25519-skp64prj@gmail.com")
        assert "Host gitlab.skp64prj.com" in stanza
        assert "HostName gitlab.com" in stanza
        assert "IdentityFile ~/.ssh/id_ed25519-skp64prj@gmail.com" in stanza


class TestBuildLoginItem:
    def test_minimal(self, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        item = build_login_item(client, "github", "test-acct", "test@example.com")
        assert item["type"] == TYPE_LOGIN
        assert item["name"] == "git: github: test-acct"
        assert item["login"]["username"] == "test@example.com"
        assert item["login"]["password"] == ""
        assert item["login"]["totp"] == ""

    def test_with_all_fields(self, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        item = build_login_item(
            client, "gitlab", "my-acct", "me@example.com",
            username="myuser", password="secret123", totp="TOTPKEY",
        )
        assert item["name"] == "git: gitlab: my-acct"
        assert item["login"]["username"] == "myuser"
        assert item["login"]["password"] == "secret123"
        assert item["login"]["totp"] == "TOTPKEY"

    def test_none_fields_cleared(self, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        item = build_login_item(client, "github", "a", "a@b.com")
        assert item["secureNote"] is None
        assert item["card"] is None
        assert item["identity"] is None


class TestBuildSshKeyItem:
    def test_builds_correctly(self, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        pair = _make_pair("id_ed25519-test@example.com")
        item = build_ssh_key_item(client, pair)
        assert item["type"] == TYPE_SSH_KEY
        assert item["name"] == "id_ed25519-test@example.com"
        assert item["sshKey"]["privateKey"] == SAMPLE_PRIVATE.strip()
        assert item["sshKey"]["publicKey"] == SAMPLE_PUBLIC.strip()
        assert item["sshKey"]["keyFingerprint"] == "SHA256:abc123"

    def test_with_name_prefix(self, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        pair = _make_pair("mykey")
        item = build_ssh_key_item(client, pair, name_prefix="SSH: ")
        assert item["name"] == "SSH: mykey"


# --------------------------------------------------------------------------- #
# Integration tests (with fake vault)
# --------------------------------------------------------------------------- #


class TestCreateGitAccount:
    def test_create_with_login_and_key(self, fake_vault, fake_bw_path, tmp_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        ssh_dir = tmp_path / "dotssh"
        ssh_dir.mkdir()
        result = create_git_account(
            client,
            platform="github",
            account_name="test-user",
            email="test@example.com",
            ssh_dir=str(ssh_dir),
            skip_ssh_key=False,
            skip_login=False,
        )
        assert result.platform == "github"
        assert result.account_name == "test-user"
        assert not result.errors, f"Errors: {result.errors}"
        assert result.login_item_id is not None
        assert result.ssh_key_item_id is not None
        assert result.config_stanza != ""

        # Verify items exist in vault
        logins = load_git_logins(client)
        assert any(l.get("name") == "git: github: test-user" for l in logins)

        ssh_keys = load_git_ssh_keys(client)
        assert any(k.name == "id_ed25519-test@example.com" for k in ssh_keys)

    def test_skip_login(self, fake_vault, fake_bw_path, tmp_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        ssh_dir = tmp_path / "dotssh"
        ssh_dir.mkdir()
        result = create_git_account(
            client,
            platform="github",
            account_name="test-user-2",
            email="test2@example.com",
            ssh_dir=str(ssh_dir),
            skip_login=True,
            skip_ssh_key=False,
        )
        assert result.login_item_id is None
        assert not result.errors, f"Errors: {result.errors}"
        assert result.ssh_key_item_id is not None

    def test_skip_ssh_key(self, fake_vault, fake_bw_path, tmp_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        ssh_dir = tmp_path / "dotssh"
        ssh_dir.mkdir()
        result = create_git_account(
            client,
            platform="github",
            account_name="test-user-3",
            email="test3@example.com",
            ssh_dir=str(ssh_dir),
            skip_login=False,
            skip_ssh_key=True,
        )
        assert not result.errors, f"Errors: {result.errors}"
        assert result.login_item_id is not None
        assert result.ssh_key_item_id is None

    def test_dry_run(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        result = create_git_account(
            client,
            platform="github",
            account_name="dry-run-test",
            email="dry@example.com",
            dry_run=True,
        )
        assert result.login_item_id is None
        assert result.ssh_key_item_id is None
        # No items should have been created in vault
        logins = load_git_logins(client)
        assert len(logins) == 0


# --------------------------------------------------------------------------- #
# Vault loading tests
# --------------------------------------------------------------------------- #


class TestLoadGitLogins:
    def test_filters_correctly(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")

        # Create a git login and a non-git item
        template = client.get_template("item")
        git_item = dict(template)
        git_item["type"] = TYPE_LOGIN
        git_item["name"] = "git: github: test-acct"
        git_item["login"] = {"username": "test@example.com", "password": "pw"}
        client.create_item(git_item)

        other_item = dict(template)
        other_item["type"] = TYPE_LOGIN
        other_item["name"] = "Personal Email"
        client.create_item(other_item)

        logins = load_git_logins(client)
        assert len(logins) == 1
        assert logins[0]["name"] == "git: github: test-acct"


class TestLoadGitSshKeys:
    def test_loads_all_ssh_keys(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")

        template = client.get_template("item")
        key_item = dict(template)
        key_item["type"] = TYPE_SSH_KEY
        key_item["name"] = "id_ed25519-test@example.com"
        key_item["sshKey"] = {
            "privateKey": SAMPLE_PRIVATE,
            "publicKey": SAMPLE_PUBLIC,
            "keyFingerprint": "SHA256:abc",
        }
        client.create_item(key_item)

        keys = load_git_ssh_keys(client)
        assert len(keys) == 1
        assert keys[0].name == "id_ed25519-test@example.com"


# --------------------------------------------------------------------------- #
# Audit tests
# --------------------------------------------------------------------------- #


class TestAuditVault:
    def test_clean_vault(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        report = audit_git_vault(client)
        assert report.total == 0

    def test_duplicate_login_detected(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")

        template = client.get_template("item")
        for _ in range(2):
            item = dict(template)
            item["type"] = TYPE_LOGIN
            item["name"] = "git: github: dup-acct"
            item["login"] = {"username": "a@b.com", "password": "x"}
            client.create_item(item)

        report = audit_git_vault(client)
        errors = report.errors
        dup = [f for f in errors if f.category == "duplicate_login"]
        assert len(dup) == 1
        assert "dup-acct" in dup[0].message

    def test_duplicate_ssh_key_detected(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")

        template = client.get_template("item")
        for _ in range(2):
            item = dict(template)
            item["type"] = TYPE_SSH_KEY
            item["name"] = "id_ed25519-dup@example.com"
            item["sshKey"] = {"privateKey": "x", "publicKey": "y", "keyFingerprint": "fp"}
            client.create_item(item)

        report = audit_git_vault(client)
        dup = [f for f in report.errors if f.category == "duplicate_ssh_key"]
        assert len(dup) == 1

    def test_missing_login_password(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")

        template = client.get_template("item")
        item = dict(template)
        item["type"] = TYPE_LOGIN
        item["name"] = "git: github: no-pass"
        item["login"] = {"username": "u", "password": ""}
        client.create_item(item)

        report = audit_git_vault(client)
        missing = [f for f in report.warnings if f.category == "missing_login_field"]
        assert len(missing) >= 1
        assert "password" in missing[0].message

    def test_orphan_login_no_key(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")

        template = client.get_template("item")
        item = dict(template)
        item["type"] = TYPE_LOGIN
        item["name"] = "git: github: orphan-acct"
        item["login"] = {"username": "orphan@example.com", "password": "x"}
        client.create_item(item)

        report = audit_git_vault(client)
        orphan = [f for f in report.warnings if f.category == "orphan_login"]
        assert len(orphan) >= 1

    def test_incomplete_ssh_key_detected(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")

        template = client.get_template("item")
        item = dict(template)
        item["type"] = TYPE_SSH_KEY
        item["name"] = "id_ed25519-broken@example.com"
        item["sshKey"] = {"privateKey": "", "publicKey": "", "keyFingerprint": ""}
        client.create_item(item)

        report = audit_git_vault(client)
        incomplete = [f for f in report.errors if f.category == "incomplete_ssh_key"]
        assert len(incomplete) >= 1


class TestAuditReport:
    def test_properties(self):
        report = AuditReport()
        assert report.total == 0
        assert report.errors == []
        assert report.warnings == []
        assert report.infos == []
