"""Tests for :mod:`ssh_bw.bwclient` using the fake bw CLI."""

from ssh_bw.bwclient import TYPE_SSH_KEY, BitwardenClient


def _client(bw_path: str) -> BitwardenClient:
    return BitwardenClient(bw_path=bw_path, session=None)


class TestAuth:
    def test_status_unauthenticated(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        st = client.status()
        assert st["status"] == "unauthenticated"

    def test_unlock(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        session = client.unlock("testpw")
        assert session
        assert client.session == session

    def test_lock(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        assert client.status()["status"] == "unlocked"
        client.lock()
        st = client.status()
        assert st["status"] == "locked"


class TestCrud:
    def test_create_and_list(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        items = client.list_items()
        assert items == []

        template = client.get_template("item")
        template["type"] = TYPE_SSH_KEY
        template["name"] = "SSH: test-key"
        template["sshKey"] = {
            "privateKey": "priv",
            "publicKey": "pub",
            "keyFingerprint": "fp",
        }
        created = client.create_item(template)
        assert created.get("id") is not None

        items = client.list_items()
        assert len(items) == 1
        assert items[0]["sshKey"]["publicKey"] == "pub"

    def test_edit_item(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")

        template = client.get_template("item")
        template["type"] = TYPE_SSH_KEY
        template["name"] = "SSH: edit-me"
        template["sshKey"] = {"privateKey": "old", "publicKey": "oldpub", "keyFingerprint": "fp"}
        created = client.create_item(template)
        item_id = created["id"]

        new_item = dict(created)
        new_item["sshKey"]["publicKey"] = "newpub"
        updated = client.edit_item(item_id, new_item)
        assert updated["sshKey"]["publicKey"] == "newpub"

    def test_delete_item(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")

        template = client.get_template("item")
        template["type"] = TYPE_SSH_KEY
        template["name"] = "SSH: delete-me"
        template["sshKey"] = {"privateKey": "x", "publicKey": "y", "keyFingerprint": "z"}
        created = client.create_item(template)
        item_id = created["id"]

        client.delete_item(item_id)
        items = client.list_items()
        assert len(items) == 0

    def test_search(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")

        template = client.get_template("item")
        template["type"] = TYPE_SSH_KEY
        template["name"] = "SSH: unique-search-key"
        template["sshKey"] = {"privateKey": "a", "publicKey": "b", "keyFingerprint": "c"}
        client.create_item(template)

        items = client.list_items(search="unique-search")
        assert len(items) == 1

        items = client.list_items(search="no-match")
        assert items == []
