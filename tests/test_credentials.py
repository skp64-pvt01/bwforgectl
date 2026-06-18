"""Tests for :mod:`ssh_bw.credentials` using the encrypted-file backend."""

import pytest
from pathlib import Path

from ssh_bw.credentials import CredentialError, Credentials, CredentialStore


class TestEncryptedFileStore:
    def test_save_and_load(self, tmp_path):
        store = CredentialStore(tmp_path, prefer_keyring=False)
        assert store.backend == "encrypted-file"

        creds = Credentials(email="test@example.com", password="s3cret!")
        store.save(creds, store_passphrase="my-passphrase")

        loaded = store.load(store_passphrase="my-passphrase")
        assert loaded.email == "test@example.com"
        assert loaded.password == "s3cret!"

    def test_wrong_passphrase_fails(self, tmp_path):
        store = CredentialStore(tmp_path, prefer_keyring=False)
        store.save(Credentials("a@b.com", "pw"), store_passphrase="correct")

        with pytest.raises(CredentialError):
            store.load(store_passphrase="wrong")

    def test_no_passphrase_fails(self, tmp_path):
        store = CredentialStore(tmp_path, prefer_keyring=False)
        store.save(Credentials("a@b.com", "pw"), store_passphrase="x")

        with pytest.raises(CredentialError):
            store.load()

    def test_load_from_missing_file(self, tmp_path):
        store = CredentialStore(tmp_path, prefer_keyring=False)
        with pytest.raises(CredentialError):
            store.load(store_passphrase="x")

    def test_has_credentials(self, tmp_path):
        store = CredentialStore(tmp_path, prefer_keyring=False)
        assert store.has_credentials() is False
        store.save(Credentials("a@b.com", "pw"), store_passphrase="x")
        assert store.has_credentials() is True

    def test_delete(self, tmp_path):
        store = CredentialStore(tmp_path, prefer_keyring=False)
        assert store.delete() is False
        store.save(Credentials("a@b.com", "pw"), store_passphrase="x")
        assert store.delete() is True
        assert store.has_credentials() is False

    def test_not_complete(self):
        assert Credentials(email="", password="pw").is_complete() is False
        assert Credentials(email="a@b.com", password="").is_complete() is False
        assert Credentials(email="a@b.com", password="pw").is_complete() is True
