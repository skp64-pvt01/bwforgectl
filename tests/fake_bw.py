#!/usr/bin/env python3
"""A minimal fake implementation of the Bitwarden ``bw`` CLI.

It is just complete enough to exercise :mod:`bw_forge_ctl.bwclient` end-to-end
without touching a real vault or the network.  Vault state is persisted as
JSON at ``$FAKE_BW_VAULT`` (default ./fake_vault.json).

Supported:
    status, login, unlock, lock, sync,
    list items [--search S], get template item,
    encode (stdin -> base64), create item <b64>,
    edit item <id> <b64>, delete item <id> [--permanent]
"""

from __future__ import annotations

import base64
import json
import os
import sys
import uuid
from pathlib import Path

VAULT = Path(os.environ.get("FAKE_BW_VAULT", "fake_vault.json"))
PASSWORD = os.environ.get("FAKE_BW_PASSWORD", "testpw")
SESSION = "FAKE_SESSION_KEY"


def _load() -> dict:
    if VAULT.is_file():
        return json.loads(VAULT.read_text())
    return {"status": "unauthenticated", "items": []}


def _save(state: dict) -> None:
    VAULT.write_text(json.dumps(state))


def _strip_session(argv: list) -> list:
    out = []
    skip = False
    for i, a in enumerate(argv):
        if skip:
            skip = False
            continue
        if a == "--session":
            skip = True
            continue
        if a in ("--raw", "--pretty", "--response", "--nointeraction", "--quiet"):
            continue
        out.append(a)
    return out


TEMPLATE = {
    "organizationId": None,
    "collectionIds": None,
    "folderId": None,
    "type": 1,
    "name": "Item name",
    "notes": None,
    "favorite": False,
    "fields": [],
    "login": None,
    "secureNote": None,
    "card": None,
    "identity": None,
    "sshKey": None,
    "reprompt": 0,
}


def main(argv: list) -> int:
    args = _strip_session(argv)
    state = _load()

    if not args:
        print("usage: fake_bw <command>", file=sys.stderr)
        return 1

    cmd = args[0]

    if cmd == "status":
        print(json.dumps({
            "serverUrl": None,
            "lastSync": "2026-01-01T00:00:00.000Z",
            "userEmail": "test@example.com",
            "status": state.get("status", "unauthenticated"),
        }))
        return 0

    if cmd == "login":
        # login <email> <password>
        state["status"] = "unlocked"
        _save(state)
        print(SESSION)
        return 0

    if cmd == "unlock":
        pw = args[1] if len(args) > 1 else ""
        if pw != PASSWORD:
            print("Invalid master password.", file=sys.stderr)
            return 1
        state["status"] = "unlocked"
        _save(state)
        print(SESSION)
        return 0

    if cmd == "lock":
        state["status"] = "locked"
        _save(state)
        print("Your vault is locked.")
        return 0

    if cmd == "sync":
        print("Syncing complete.")
        return 0

    if cmd == "encode":
        data = sys.stdin.read()
        print(base64.b64encode(data.encode("utf-8")).decode("ascii"))
        return 0

    if cmd == "get" and len(args) >= 3 and args[1] == "template":
        if args[2] == "item":
            print(json.dumps(TEMPLATE))
            return 0
        print("{}")
        return 0

    if cmd == "list" and len(args) >= 2 and args[1] == "items":
        items = state.get("items", [])
        if "--search" in args:
            term = args[args.index("--search") + 1].lower()
            items = [
                it for it in items
                if term in json.dumps(it).lower()
            ]
        print(json.dumps(items))
        return 0

    if cmd == "create" and len(args) >= 3 and args[1] == "item":
        item = json.loads(base64.b64decode(args[2]).decode("utf-8"))
        item["id"] = str(uuid.uuid4())
        state.setdefault("items", []).append(item)
        _save(state)
        print(json.dumps(item))
        return 0

    if cmd == "edit" and len(args) >= 4 and args[1] == "item":
        item_id = args[2]
        new = json.loads(base64.b64decode(args[3]).decode("utf-8"))
        for i, it in enumerate(state.get("items", [])):
            if it.get("id") == item_id:
                new["id"] = item_id
                state["items"][i] = new
                _save(state)
                print(json.dumps(new))
                return 0
        print("Not found.", file=sys.stderr)
        return 1

    if cmd == "delete" and len(args) >= 3 and args[1] == "item":
        item_id = args[2]
        before = len(state.get("items", []))
        state["items"] = [it for it in state.get("items", []) if it.get("id") != item_id]
        _save(state)
        if len(state["items"]) == before:
            print("Not found.", file=sys.stderr)
            return 1
        return 0

    print(f"fake_bw: unsupported command: {' '.join(args)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
