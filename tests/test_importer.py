"""Tests for :mod:`ssh_bw.importer`."""

from ssh_bw.bwclient import BitwardenClient
from ssh_bw.importer import Importer, _always_yes, _always_no, ACTION_CREATED, ACTION_UNCHANGED, ACTION_DECLINED, ACTION_UPDATED


def _client(bw_path: str) -> BitwardenClient:
    return BitwardenClient(bw_path=bw_path, session=None)


class TestImporter:
    def test_sync_creates_new_key(self, fake_vault, ssh_dir, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        imp = Importer(client)
        results = imp.sync_directory(ssh_dir)
        assert len(results) == 1
        assert results[0].action == ACTION_CREATED

        # Now list from vault
        records = imp.load_ssh_records()
        assert len(records) == 1

    def test_sync_skips_identical(self, fake_vault, ssh_dir, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        imp = Importer(client)
        results = imp.sync_directory(ssh_dir)
        assert results[0].action == ACTION_CREATED

        # Second sync should be unchanged
        results = imp.sync_directory(ssh_dir)
        assert results[0].action == ACTION_UNCHANGED

    def test_update_declined_by_default(self, fake_vault, ssh_dir, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        imp = Importer(client)
        imp.sync_directory(ssh_dir)

        # Modify local key content
        pub_file = ssh_dir / "id_ed25519.pub"
        pub_file.write_text("ssh-rsa DIFFERENT comment\n")
        results = imp.sync_directory(ssh_dir)
        assert results[0].action == ACTION_DECLINED

    def test_update_confirmed(self, fake_vault, ssh_dir, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        imp = Importer(client)
        imp.sync_directory(ssh_dir)

        pub_file = ssh_dir / "id_ed25519.pub"
        pub_file.write_text("ssh-rsa DIFFERENT comment\n")
        results = imp.sync_directory(ssh_dir, confirm_update=lambda p, r: True)
        assert results[0].action == ACTION_UPDATED

        # Verify update persisted
        records = imp.load_ssh_records()
        assert "DIFFERENT" in records[0].public_key

    def test_delete_by_name(self, fake_vault, ssh_dir, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        imp = Importer(client)
        imp.sync_directory(ssh_dir)

        results = imp.delete_ssh("SSH: id_ed25519")
        assert len(results) == 1
        assert results[0].action == "deleted"
        assert imp.load_ssh_records() == []

    def test_delete_by_bare_name(self, fake_vault, ssh_dir, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        imp = Importer(client)
        imp.sync_directory(ssh_dir)

        results = imp.delete_ssh("id_ed25519")
        assert len(results) == 1

    def test_no_ssh_keys_no_issue(self, fake_vault, fake_bw_path, tmp_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        empty_dir = tmp_path / "empty_ssh"
        empty_dir.mkdir()
        imp = Importer(client)
        results = imp.sync_directory(empty_dir)
        assert results == []

    def test_pgp_note_detection(self, fake_vault, fake_bw_path):
        client = _client(fake_bw_path)
        client.unlock("testpw")
        imp = Importer(client)

        pgp_text = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nfake-pgp-data\n-----END PGP PRIVATE KEY BLOCK-----\n"
        template = client.get_template("item")
        template["type"] = 2
        template["name"] = "PGP: My GPG Key"
        template["notes"] = pgp_text
        client.create_item(template)

        pgp_notes = imp.load_pgp_notes()
        assert len(pgp_notes) == 1
        assert pgp_notes[0]["name"] == "PGP: My GPG Key"
