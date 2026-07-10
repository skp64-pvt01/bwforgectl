"""BwForgeCtl - Manage SSH keys and Git credentials via a Bitwarden vault.

Public surface:
    from bw_forge_ctl.sshscan import scan_ssh_dir, SSHKeyPair
    from bw_forge_ctl.bwclient import BitwardenClient
    from bw_forge_ctl.credentials import CredentialStore
    from bw_forge_ctl.importer import Importer
    from bw_forge_ctl.hostscan import scan_host_keys, format_table, fuzzy_match_host
"""

__version__ = "1.0.0"

__all__ = [
    "__version__",
]
