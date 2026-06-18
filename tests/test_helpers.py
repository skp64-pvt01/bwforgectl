"""Shared test constants and helpers."""

from pathlib import Path

FAKE_BW = Path(__file__).resolve().parent / "fake_bw.py"

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
