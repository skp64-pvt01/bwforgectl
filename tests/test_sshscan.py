"""Tests for :mod:`ssh_bw.sshscan`."""

from pathlib import Path

from ssh_bw.sshscan import (
    SSHKeyPair,
    is_private_key_file,
    scan_ssh_dir,
)


class TestIsPrivateKeyFile:
    def test_private_key_marker(self, ssh_dir):
        key = ssh_dir / "id_ed25519"
        assert is_private_key_file(key) is True

    def test_public_key_is_not_private(self, ssh_dir):
        pub = ssh_dir / "id_ed25519.pub"
        assert is_private_key_file(pub) is False

    def test_config_file_excluded(self, ssh_dir):
        assert is_private_key_file(ssh_dir / "config") is False

    def test_known_hosts_excluded(self, ssh_dir):
        assert is_private_key_file(ssh_dir / "known_hosts") is False

    def test_nonexistent_file(self, ssh_dir):
        assert is_private_key_file(ssh_dir / "nope") is False


class TestScanSshDir:
    def test_returns_pairs(self, ssh_dir):
        pairs = scan_ssh_dir(ssh_dir)
        assert len(pairs) >= 1

    def test_pair_fields(self, ssh_dir):
        pairs = scan_ssh_dir(ssh_dir)
        pair = pairs[0]
        assert pair.name == "id_ed25519"
        assert pair.private_path == ssh_dir / "id_ed25519"
        assert pair.public_path == ssh_dir / "id_ed25519.pub"
        assert pair.private_key
        assert pair.public_key
        assert pair.fingerprint.startswith("SHA256:")

    def test_empty_dir(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert scan_ssh_dir(empty) == []

    def test_nonexistent_dir(self, tmp_path):
        assert scan_ssh_dir(tmp_path / "nope") == []

    def test_normalized(self):
        pair = SSHKeyPair(
            name="test",
            private_path=Path("/dev/null"),
            public_path=Path("/dev/null"),
            private_key="a\nb\n",
            public_key="c\n",
            fingerprint="fp",
        )
        assert pair.normalized_private() == "a\nb"
        assert pair.normalized_public() == "c"

        assert pair.matches("a\nb", "c") is True
        assert pair.matches("a\nb", "d") is False
        assert pair.matches("a\nb\n\n", "c\n\n\n") is True
