"""ssh_bw - Sync local SSH key pairs (and PGP notes) with a Bitwarden vault.

Public surface:
    from ssh_bw.sshscan import scan_ssh_dir, SSHKeyPair
    from ssh_bw.bwclient import BitwardenClient
    from ssh_bw.credentials import CredentialStore
    from ssh_bw.importer import Importer
"""

__version__ = "1.0.0"

__all__ = [
    "__version__",
]
