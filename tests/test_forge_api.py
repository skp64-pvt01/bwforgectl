"""Tests for :mod:`bw_forge_ctl.forge_api` — mock HTTP via urllib."""

import json
import urllib.error
import urllib.request
from unittest.mock import patch

import pytest

from bw_forge_ctl.forge_api import (
    ForgeAPI,
    ForgeAuthError,
    ForgeError,
    ForgeGPGKey,
    ForgeRateLimitError,
    ForgeSSHKey,
    ForgeValidationError,
    forge_key_name,
    resolve_forge_token,
)


# --------------------------------------------------------------------------- #
# Mock helpers
# --------------------------------------------------------------------------- #


class _MockResponse:
    def __init__(self, data, status=200):
        self._data = json.dumps(data).encode("utf-8") if data is not None else b""

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _MockHTTPError(urllib.error.HTTPError):
    def __init__(self, code, body=""):
        self.code = code
        self._body = body.encode("utf-8")
        super().__init__(
            f"http://mock/{code}", code, f"Error {code}", {}, None,
        )

    def read(self):
        return self._body


def _mock_urlopen(side_effect):
    """Context manager that patches urllib.request.urlopen."""
    def wrapper(*args, **kwargs):
        return side_effect(*args, **kwargs)
    return patch.object(urllib.request, "urlopen", side_effect=wrapper)


# --------------------------------------------------------------------------- #
# ForgeAPI – SSH keys
# --------------------------------------------------------------------------- #


SAMPLE_SSH_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMdGVRJQCpLOEuq5y0ETBimJmYtIa"
    "Z1vHcJ0oVdUOHE test@example.com"
)


class TestForgeAPISSH:
    def _mock_ok(self, data):
        def inner(*args, **kwargs):
            return _MockResponse(data)
        return inner

    def test_list_ssh_keys_empty(self):
        api = ForgeAPI("github", "ghp_test")
        with _mock_urlopen(self._mock_ok([])):
            keys = api.list_ssh_keys()
        assert keys == []

    def test_list_ssh_keys(self):
        api = ForgeAPI("github", "ghp_test")
        resp_data = [
            {"id": 1, "title": "my-key", "key": SAMPLE_SSH_KEY},
            {"id": 2, "title": "other-key", "key": SAMPLE_SSH_KEY},
        ]
        with _mock_urlopen(self._mock_ok(resp_data)):
            keys = api.list_ssh_keys()
        assert len(keys) == 2
        assert keys[0].id == 1
        assert keys[0].title == "my-key"

    def test_add_ssh_key(self):
        api = ForgeAPI("github", "ghp_test")
        resp_data = {"id": 42, "title": "new-key", "key": SAMPLE_SSH_KEY}

        def check_request(*args, **kwargs):
            req = args[0]
            body = json.loads(req.data)
            assert body["title"] == "new-key"
            assert body["key"] == SAMPLE_SSH_KEY
            return _MockResponse(resp_data)

        with _mock_urlopen(check_request):
            key = api.add_ssh_key("new-key", SAMPLE_SSH_KEY)
        assert key.id == 42
        assert key.title == "new-key"

    def test_delete_ssh_key(self):
        api = ForgeAPI("github", "ghp_test")
        with _mock_urlopen(self._mock_ok(None)):
            result = api.delete_ssh_key(42)
        assert result is True

    def test_replace_ssh_key(self):
        api = ForgeAPI("github", "ghp_test")
        calls = []

        def side_effect(*args, **kwargs):
            req = args[0]
            calls.append(req.method)
            if req.method == "DELETE":
                return _MockResponse(None)
            return _MockResponse({"id": 99, "title": "replaced", "key": SAMPLE_SSH_KEY})

        with _mock_urlopen(side_effect):
            key = api.replace_ssh_key(42, "replaced", SAMPLE_SSH_KEY)
        assert calls == ["DELETE", "POST"]
        assert key.id == 99


# --------------------------------------------------------------------------- #
# ForgeAPI – GPG keys
# --------------------------------------------------------------------------- #


SAMPLE_GPG_ARMOR = """-----BEGIN PGP PUBLIC KEY BLOCK-----
mQENBGY...
-----END PGP PUBLIC KEY BLOCK-----"""


class TestForgeAPIGPG:
    def _mock_ok(self, data):
        def inner(*args, **kwargs):
            return _MockResponse(data)
        return inner

    def test_list_gpg_keys(self):
        api = ForgeAPI("gitlab", "glpat_test")
        resp_data = [{
            "id": 7,
            "key_id": "A1B2C3D4",
            "public_key": SAMPLE_GPG_ARMOR,
            "emails": [{"email": "test@example.com"}],
        }]
        with _mock_urlopen(self._mock_ok(resp_data)):
            keys = api.list_gpg_keys()
        assert len(keys) == 1
        assert keys[0].id == 7
        assert keys[0].key_id == "A1B2C3D4"

    def test_add_gpg_key(self):
        api = ForgeAPI("github", "ghp_test")
        resp_data = {
            "id": 10,
            "key_id": "E5F6G7H8",
            "public_key": SAMPLE_GPG_ARMOR,
            "emails": [{"email": "me@example.com"}],
        }

        def check_request(*args, **kwargs):
            req = args[0]
            body = json.loads(req.data)
            assert "armored_public_key" in body
            return _MockResponse(resp_data)

        with _mock_urlopen(check_request):
            key = api.add_gpg_key(SAMPLE_GPG_ARMOR)
        assert key.id == 10
        assert key.key_id == "E5F6G7H8"
        assert key.emails == ["me@example.com"]

    def test_delete_gpg_key(self):
        api = ForgeAPI("gitlab", "glpat_test")
        with _mock_urlopen(self._mock_ok(None)):
            result = api.delete_gpg_key(5)
        assert result is True


# --------------------------------------------------------------------------- #
# Error handling
# --------------------------------------------------------------------------- #


class TestForgeAPIErrors:
    def _mock_error(self, exc):
        def inner(*args, **kwargs):
            raise exc
        return inner

    def test_401_auth_error(self):
        api = ForgeAPI("github", "bad_token")
        with _mock_urlopen(self._mock_error(
            _MockHTTPError(401, '{"message":"Bad credentials"}'),
        )):
            with pytest.raises(ForgeAuthError, match="Authentication failed"):
                api.list_ssh_keys()

    def test_403_rate_limit(self):
        api = ForgeAPI("github", "token")
        with _mock_urlopen(self._mock_error(
            _MockHTTPError(403, '{"message":"Rate limit exceeded"}'),
        )):
            with pytest.raises(ForgeRateLimitError, match="Rate limited"):
                api.list_ssh_keys()

    def test_422_validation(self):
        api = ForgeAPI("github", "token")
        with _mock_urlopen(self._mock_error(
            _MockHTTPError(422, '{"message":"Validation failed"}'),
        )):
            with pytest.raises(ForgeValidationError, match="Validation error"):
                api.add_gpg_key("bad-key")

    def test_unsupported_platform(self):
        with pytest.raises(ForgeError, match="Unsupported platform"):
            ForgeAPI("bitbucket", "token")


# --------------------------------------------------------------------------- #
# forge_key_name
# --------------------------------------------------------------------------- #


class TestForgeKeyName:
    def test_github(self):
        name = forge_key_name("github", "skp1964-dev", "ssh")
        assert "SSH" in name
        assert "skp1964-dev" in name

    def test_gitlab(self):
        name = forge_key_name("gitlab", "skp64prj", "gpg")
        assert "GPG" in name
        assert "skp64prj" in name


# --------------------------------------------------------------------------- #
# resolve_forge_token
# --------------------------------------------------------------------------- #


class TestResolveForgeToken:
    def test_token_found(self, fake_vault, fake_bw_path):
        from bw_forge_ctl.bwclient import BitwardenClient

        client = BitwardenClient(bw_path=fake_bw_path, session=None)
        client.unlock("testpw")

        template = client.get_template("item")
        item = dict(template)
        item["type"] = 1
        item["name"] = "git: github: my-acct: pat"
        item["login"] = {"username": "u", "password": "ghp_abc123"}
        client.create_item(item)

        token = resolve_forge_token(client, "github", "my-acct")
        assert token == "ghp_abc123"

    def test_token_not_found(self, fake_vault, fake_bw_path):
        from bw_forge_ctl.bwclient import BitwardenClient

        client = BitwardenClient(bw_path=fake_bw_path, session=None)
        client.unlock("testpw")
        token = resolve_forge_token(client, "github", "unknown")
        assert token is None
