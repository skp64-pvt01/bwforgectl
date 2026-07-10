"""SSH config file management for bwforgectl.

Parse, read, write, and modify ``~/.ssh/config`` with full preservation of
comments and formatting for unmodified stanzas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

DEFAULT_SSH_CONFIG = Path.home() / ".ssh" / "config"
HOST_RE = re.compile(r"^\s*[Hh][Oo][Ss][Tt]\s+(.+)$")
OPTION_RE = re.compile(r"^(\s+)(\S+)\s+(.+)$")


@dataclass
class SshConfigStanza:
    hosts: List[str] = field(default_factory=list)
    options: List[Tuple[str, str]] = field(default_factory=list)
    raw: str = ""
    modified: bool = False


def parse_config(config_text: str) -> Tuple[str, List[SshConfigStanza]]:
    """Parse SSH config text into (preamble, stanzas).

    *preamble* is any text before the first ``Host`` directive (global
    comments, blank lines, ``Include`` directives, etc.).
    *stanzas* is the list of parsed :class:`SshConfigStanza` objects, each
    carrying its original *raw* text for roundtrip fidelity.
    """
    stanzas: List[SshConfigStanza] = []
    lines = config_text.splitlines(keepends=True)

    first_host = -1
    for i, line in enumerate(lines):
        if HOST_RE.match(line):
            first_host = i
            break

    if first_host == -1:
        return config_text, []

    preamble = "".join(lines[:first_host])

    start = first_host
    for i in range(first_host + 1, len(lines)):
        if HOST_RE.match(lines[i]):
            stanzas.append(_parse_stanza(lines, start, i))
            start = i
    stanzas.append(_parse_stanza(lines, start, len(lines)))

    return preamble, stanzas


def _parse_stanza(lines: List[str], start: int, end: int) -> SshConfigStanza:
    stanza = SshConfigStanza()
    stanza.raw = "".join(lines[start:end])

    for line in lines[start:end]:
        m = HOST_RE.match(line)
        if m:
            stanza.hosts = m.group(1).strip().split()
            continue
        m = OPTION_RE.match(line)
        if m:
            stanza.options.append((m.group(2).strip(), m.group(3).strip()))

    return stanza


def format_stanza(stanza: SshConfigStanza, indent: str = "    ") -> str:
    """Return the SSH config text for *stanza*.

    If the stanza was not modified, the original raw text is returned,
    preserving comments and formatting exactly.
    """
    if not stanza.modified:
        return stanza.raw

    lines: List[str] = []

    comment_start = stanza.raw.find("#")
    if comment_start >= 0:
        comment_end = stanza.raw.find("\n", comment_start)
        if comment_end >= 0:
            preceding = stanza.raw[: comment_end + 1]
            for cl in preceding.splitlines(keepends=True):
                if cl.strip().startswith("#") or cl.strip() == "":
                    lines.append(cl)

    lines.append(f"Host {' '.join(stanza.hosts)}\n")
    for key, value in stanza.options:
        lines.append(f"{indent}{key} {value}\n")
    return "".join(lines)


def read_config(
    path: Optional[str] = None,
) -> Tuple[str, List[SshConfigStanza]]:
    """Read and parse an SSH config file.

    Returns ``(preamble, stanzas)``. If the file does not exist, returns
    an empty preamble and empty list.
    """
    config_path = Path(path) if path else DEFAULT_SSH_CONFIG
    if not config_path.exists():
        return "", []
    return parse_config(config_path.read_text(encoding="utf-8"))


def write_config(
    preamble: str,
    stanzas: List[SshConfigStanza],
    path: Optional[str] = None,
) -> None:
    """Write stanzas back to an SSH config file."""
    config_path = Path(path) if path else DEFAULT_SSH_CONFIG
    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    parts: List[str] = []
    if preamble:
        parts.append(preamble)
    for stanza in stanzas:
        parts.append(format_stanza(stanza))

    config_path.write_text("".join(parts), encoding="utf-8")


def find_stanza_index(
    stanzas: List[SshConfigStanza], host: str
) -> Optional[int]:
    """Return the index of the stanza whose first host pattern matches *host*.

    The match is case-insensitive. Returns ``None`` if not found.
    """
    host_lower = host.lower()
    for i, stanza in enumerate(stanzas):
        p = stanza.hosts[0] if stanza.hosts else ""
        if p.lower() == host_lower:
            return i
    return None


def add_stanza(
    stanza: SshConfigStanza, path: Optional[str] = None
) -> bool:
    """Add a new stanza or update an existing one by host pattern.

    Returns ``True`` if a *new* stanza was appended, ``False`` if an
    existing stanza was replaced.
    """
    preamble, stanzas = read_config(path)
    idx = find_stanza_index(stanzas, stanza.hosts[0] if stanza.hosts else "")
    stanza.modified = True
    if idx is not None:
        stanzas[idx] = stanza
        write_config(preamble, stanzas, path)
        return False
    stanzas.append(stanza)
    write_config(preamble, stanzas, path)
    return True


def remove_stanza(host: str, path: Optional[str] = None) -> bool:
    """Remove a stanza matching *host*. Returns ``True`` if removed."""
    preamble, stanzas = read_config(path)
    idx = find_stanza_index(stanzas, host)
    if idx is not None:
        stanzas.pop(idx)
        write_config(preamble, stanzas, path)
        return True
    return False


def list_stanzas(
    path: Optional[str] = None,
) -> List[SshConfigStanza]:
    """Return every stanza in the config file."""
    _, stanzas = read_config(path)
    return stanzas


def make_stanza(
    host: str,
    hostname: str,
    user: str = "git",
    identity_file: str = "",
    add_keys_to_agent: bool = True,
    identities_only: bool = True,
    forward_agent: bool = False,
    comment: str = "",
) -> SshConfigStanza:
    """Build a :class:`SshConfigStanza` from explicit parameters.

    The returned stanza is marked as *modified* so ``format_stanza`` will
    always regenerate its text.
    """
    stanza = SshConfigStanza(hosts=[host], modified=True)
    stanza.options.append(("HostName", hostname))
    stanza.options.append(("User", user))
    if identity_file:
        if "/" in identity_file:
            stanza.options.append(("IdentityFile", identity_file))
        else:
            stanza.options.append(("IdentityFile", f"~/.ssh/{identity_file}"))
    if add_keys_to_agent:
        stanza.options.append(("AddKeysToAgent", "yes"))
    if identities_only:
        stanza.options.append(("IdentitiesOnly", "yes"))
    if forward_agent:
        stanza.options.append(("ForwardAgent", "yes"))

    raw_parts: List[str] = []
    if comment:
        for cl in comment.strip().split("\n"):
            raw_parts.append(f"# {cl}\n")
    raw_parts.append(f"Host {' '.join(stanza.hosts)}\n")
    for key, value in stanza.options:
        raw_parts.append(f"    {key} {value}\n")
    stanza.raw = "".join(raw_parts)
    return stanza


def generate_git_stanza(
    platform: str,
    account_name: str,
    key_name: str,
    add_keys_to_agent: bool = True,
) -> SshConfigStanza:
    """Generate an SSH config stanza for a git platform account.

    Produces a host pattern of ``github.<account>.com`` or
    ``gitlab.<account>.com``, matching the project's naming convention.
    """
    if platform == "github":
        host = f"github.{account_name}.com"
        hostname = "github.com"
    else:
        host = f"gitlab.{account_name}.com"
        hostname = "gitlab.com"

    return make_stanza(
        host=host,
        hostname=hostname,
        user="git",
        identity_file=key_name,
        add_keys_to_agent=add_keys_to_agent,
        identities_only=True,
        comment=f"{platform}: {account_name}",
    )
