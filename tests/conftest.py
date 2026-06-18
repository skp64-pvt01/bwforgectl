import os
import stat
import sys
from pathlib import Path

import pytest

# Make the package importable when tests are run from anywhere.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FAKE_BW = Path(__file__).resolve().parent / "fake_bw.py"

# Sample passphrase-less ed25519-style material is not valid crypto, but the
# scanner only needs the PEM markers + a public line for structure tests.
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


@pytest.fixture
def fake_bw_path() -> str:
    """Path to the executable fake bw CLI."""
    FAKE_BW.chmod(FAKE_BW.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return str(FAKE_BW)


@pytest.fixture
def fake_vault(tmp_path, monkeypatch):
    vault = tmp_path / "fake_vault.json"
    monkeypatch.setenv("FAKE_BW_VAULT", str(vault))
    monkeypatch.setenv("FAKE_BW_PASSWORD", "testpw")
    return vault


@pytest.fixture
def ssh_dir(tmp_path):
    d = tmp_path / "dotssh"
    d.mkdir()
    (d / "id_ed25519").write_text(SAMPLE_PRIVATE)
    os.chmod(d / "id_ed25519", 0o600)
    (d / "id_ed25519.pub").write_text(SAMPLE_PUBLIC)
    # Noise files that must be ignored.
    (d / "config").write_text("Host github.com\n")
    (d / "known_hosts").write_text("github.com ssh-ed25519 AAAA...\n")
    (d / "authorized_keys").write_text(SAMPLE_PUBLIC)
    return d
