"""Thin wrapper around the Bitwarden CLI (``bw``) with an optional
``bw serve`` REST-API transport.

Item type constants (Bitwarden):
    1 login, 2 secure note, 3 card, 4 identity, 5 ssh key

The client exposes a small, mockable surface used by the importer:
    unlock / lock / sync / list_items / create_item / edit_item / delete_item
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

TYPE_LOGIN = 1
TYPE_SECURE_NOTE = 2
TYPE_CARD = 3
TYPE_IDENTITY = 4
TYPE_SSH_KEY = 5


def _clean_bw_error(detail: str) -> str:
    """Strip raw Node.js stacktraces and FetchError noise from bw CLI error output."""
    if not detail:
        return detail
    lines = detail.split("\n")
    cleaned: List[str] = []
    lines_to_skip = {
        "triggerUncaughtException",
        "type: 'system'",
        "errno: 'ETIMEDOUT'",
        "errno: 'ECONNREFUSED'",
        "errno: 'ENOTFOUND'",
        "errno: 'ECONNRESET'",
        "code: 'ETIMEDOUT'",
        "code: 'ECONNREFUSED'",
        "code: 'ENOTFOUND'",
        "code: 'ECONNRESET'",
        "code: 'ERR_UNHANDLED_REJECTION'",
        "error: 'ERR_UNHANDLED_REJECTION'",
    }
    for line in lines:
        stripped = line.strip()
        if not stripped:
            cleaned.append(line)
            continue
        if stripped.startswith("at ") and "(" in stripped and ":" in stripped:
            continue
        if stripped.startswith("Node.js v"):
            continue
        if stripped.startswith("/snapshot/") or stripped.startswith("file://"):
            continue
        if stripped.startswith("FetchError:"):
            continue
        if stripped in lines_to_skip:
            continue
        if "triggerUncaughtException" in stripped:
            continue
        cleaned.append(line)
    result = "\n".join(cleaned).strip()
    if not result or len(result) < 5:
        return lines[0] if lines else detail
    return result


class BitwardenError(Exception):
    """Raised when a bw command or API call fails."""


@dataclass
class BWResult:
    ok: bool
    stdout: str
    stderr: str
    code: int


class BitwardenClient:
    """Talk to a Bitwarden vault.

    Parameters
    ----------
    bw_path:
        Path/name of the ``bw`` executable.
    session:
        Existing ``BW_SESSION`` key to reuse (skips unlocking).
    use_serve:
        When True, mutating/listing operations go through a local
        ``bw serve`` REST server (faster for bulk ops).  Auth still uses CLI.
    serve_port:
        Port for ``bw serve`` (default 8087).
    verbose:
        Verbosity level: 0=quiet, 1=progress, 2=diagnostics, 3=debug.
    """

    def __init__(
        self,
        bw_path: str = "bw",
        *,
        session: Optional[str] = None,
        use_serve: bool = False,
        serve_port: int = 8087,
        verbose: int = 1,
        email: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        self.bw_path = bw_path
        self.session = session
        self.use_serve = use_serve
        self.serve_port = serve_port
        self.verbose = verbose
        self.email = email
        self.password = password
        self._serve_proc: Optional[subprocess.Popen] = None

    def _progress(self, msg: str) -> None:
        if self.verbose >= 1:
            print(msg, file=sys.stderr, flush=True)

    def _diagnostic(self, msg: str) -> None:
        if self.verbose >= 2:
            print(msg, file=sys.stderr, flush=True)

    def _debug(self, msg: str) -> None:
        if self.verbose >= 3:
            print(msg, file=sys.stderr, flush=True)

    # ------------------------------------------------------------------ #
    # Low-level CLI helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _is_network_timed_out(output: str) -> bool:
        """Check if output indicates a network timeout."""
        lower = output.lower()
        return any(
            marker in lower
            for marker in [
                "timed out",
                "etimedout",
                "econnrefused",
                "enotfound",
                "econnreset",
                "fetcherror",
                "unable to fetch",
            ]
        )

    def _run(
        self,
        args: List[str],
        *,
        input_text: Optional[str] = None,
        check: bool = True,
        with_session: bool = True,
        timeout: float = 60.0,
    ) -> BWResult:
        cmd = [self.bw_path] + args
        if with_session and self.session:
            cmd += ["--session", self.session]
        env = dict(os.environ)
        if self.session:
            env["BW_SESSION"] = self.session
        try:
            proc = subprocess.run(
                cmd,
                input=input_text if input_text is not None else "",
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            msg = (
                f"`bw {' '.join(args)}` timed out after {timeout:.0f}s.\n"
                f"  The Bitwarden CLI may be stuck or your network connection may be slow.\n"
                f"  - Check your internet connection\n"
                f"  - Verify 'bw' can reach api.bitwarden.com (try 'bw sync' manually)\n"
                f"  - Check that your vault session is valid\n"
                f"  - Confirm 'bw' is the correct executable ({self.bw_path})"
            )
            raise BitwardenError(msg)
        result = BWResult(
            ok=proc.returncode == 0,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
            code=proc.returncode,
        )
        if not result.ok:
            detail = (result.stderr or result.stdout).strip()
            # SIGKILL often means bw was stuck prompting for a password
            if result.code == -9:
                detail = (
                    f"{detail}\n  The process was killed (SIGKILL). "
                    f"This usually means 'bw' tried to prompt for the master password\n"
                    f"  because the session key is invalid or missing."
                )
            elif result.code == -15:
                detail = (
                    f"{detail}\n  The process was terminated (SIGTERM)."
                )
            # Clean up raw Node.js stacktraces from bw CLI errors.
            detail = _clean_bw_error(detail)
            # Detect network issues and give actionable advice
            if self._is_network_timed_out(detail):
                detail = (
                    f"{detail}\n"
                    f"  This appears to be a network connectivity issue. "
                    f"Make sure you have internet access\n"
                    f"  and can reach https://api.bitwarden.com (try 'curl -I "
                    f"https://api.bitwarden.com')."
                )
            if check:
                raise BitwardenError(
                    f"`bw {' '.join(args)}` failed (exit {result.code}): {detail}"
                )
        return result

    # ------------------------------------------------------------------ #
    # Status / auth
    # ------------------------------------------------------------------ #
    def status(self) -> Dict[str, Any]:
        res = self._run(["status"], with_session=True, check=False)
        try:
            return json.loads(res.stdout)
        except (json.JSONDecodeError, ValueError):
            return {"status": "unknown"}

    def is_logged_in(self) -> bool:
        return self.status().get("status") in {"locked", "unlocked"}

    def login(self, email: str, password: str) -> None:
        self._progress("  logging in to Bitwarden …")
        self.email = email
        self.password = password
        res = self._run(
            ["login", email, password, "--raw"],
            with_session=False,
            check=False,
            timeout=120.0,
        )
        if not res.ok:
            # Already authenticated is not fatal.
            if "already logged in" in (res.stderr + res.stdout).lower():
                self._progress("  already logged in")
                return
            raise BitwardenError(f"Login failed: {res.stderr or res.stdout}")
        if res.stdout:
            self.session = res.stdout
        self._progress("  logged in")

    def unlock(self, password: str, *, email: Optional[str] = None) -> str:
        """Unlock the vault and store the session key. Returns the session key."""
        self._progress("  unlocking vault …")
        if email:
            self.email = email
        self.password = password
        res = self._run(
            ["unlock", password, "--raw"],
            with_session=False,
            check=False,
            timeout=120.0,
        )
        if not res.ok or not res.stdout:
            raise BitwardenError(f"Unlock failed: {res.stderr or res.stdout}")
        self.session = res.stdout
        self._progress("  vault unlocked")
        return self.session

    def ensure_session(self, email: Optional[str], password: str) -> str:
        """Make sure we have a usable session, logging in if necessary."""
        self._check_bw_binary()
        if email:
            self.email = email
        if password:
            self.password = password
        st = self.status().get("status")
        if st == "unlocked" and self.session:
            self._progress("  session already active")
            return self.session
        if st == "unauthenticated":
            if not email:
                raise BitwardenError("Not logged in and no email provided.")
            self.login(email, password)
            # login --raw returns a session when 2FA is not required.
            if self.session:
                return self.session
        return self.unlock(password)

    def verify_session(self) -> bool:
        """Check that we have a session key and the vault reports unlocked."""
        if not self.session:
            return False
        st = self.status().get("status")
        return st == "unlocked"

    def _ensure_vault_ready(self) -> None:
        """Verify session health before vault operations. Re-authenticate if
        the session has expired."""
        if self.use_serve:
            return
        if self.verify_session():
            return
        self._progress("  vault session expired, re-authenticating …")
        if self.email and self.password:
            self.ensure_session(self.email, self.password)
        else:
            raise BitwardenError(
                "Vault session is invalid or has expired.\n"
                "  Provide a session key (--session / BW_SESSION), email and password\n"
                "  (--email / --password / BW_EMAIL / BW_PASSWORD), or use --use-stored\n"
                "  with credentials saved via 'store-credentials'."
            )

    def lock(self) -> None:
        self._progress("  locking vault …")
        self._run(["lock"], with_session=False, check=False)
        self.session = None
        self._progress("  vault locked")

    def sync(self) -> None:
        self._progress("  syncing vault with server …")
        self._run(["sync"], timeout=120.0)
        self._progress("  sync complete")

    # ------------------------------------------------------------------ #
    # bw serve (REST) lifecycle
    # ------------------------------------------------------------------ #
    def start_serve(self, timeout: float = 30.0) -> None:
        if self._serve_proc is not None:
            self._progress("  bw serve already running")
            return
        env = dict(os.environ)
        if self.session:
            env["BW_SESSION"] = self.session
        self._progress(f"  starting bw serve on 127.0.0.1:{self.serve_port} …")
        proc = subprocess.Popen(
            [self.bw_path, "serve", "--port", str(self.serve_port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        self._serve_proc = proc
        start = time.time()
        deadline = start + timeout
        last_print = 0.0
        while time.time() < deadline:
            if proc.poll() is not None:
                self._serve_proc = None
                raise BitwardenError(
                    f"bw serve exited unexpectedly (exit {proc.returncode}). "
                    f"Check that 'bw' is installed and functional."
                )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", self.serve_port)) == 0:
                    self._progress(f"  bw serve ready ({time.time() - start:.1f}s)")
                    return
            elapsed = time.time() - start
            now = time.time()
            if now - last_print >= 2.0:
                self._progress(f"  … waiting for bw serve ({elapsed:.0f}s)")
                last_print = now
            time.sleep(0.3)
        self.stop_serve()
        raise BitwardenError(
            f"bw serve did not start within {timeout:.0f}s. "
            f"Check that 'bw' is installed (e.g. snap install bw)."
        )

    def stop_serve(self) -> None:
        if self._serve_proc is not None:
            self._serve_proc.terminate()
            try:
                self._serve_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._serve_proc.kill()
            self._serve_proc = None

    def _api(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        url = f"http://127.0.0.1:{self.serve_port}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:  # pragma: no cover - network path
            raise BitwardenError(f"API {method} {path} failed: {exc}") from exc
        except urllib.error.URLError as exc:  # pragma: no cover - network path
            raise BitwardenError(f"API {method} {path} unreachable: {exc}") from exc
        if not payload.get("success", False):
            raise BitwardenError(f"API {method} {path}: {payload}")
        return payload.get("data")

    # ------------------------------------------------------------------ #
    # Vault item operations
    # ------------------------------------------------------------------ #
    def _check_bw_binary(self) -> None:
        """Raise a clear error if the bw binary is not found or not executable."""
        import shutil
        if not shutil.which(self.bw_path):
            raise BitwardenError(
                f"Bitwarden CLI ('{self.bw_path}') not found on PATH.\n"
                f"  Install it (e.g. 'snap install bw' or download from "
                f"https://github.com/bitwarden/clients/releases)\n"
                f"  or set the path via --bw-path."
            )

    def list_items(self, search: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.use_serve:
            path = "/list/object/items"
            if search:
                path += f"?search={urllib.parse.quote(search)}"
            data = self._api("GET", path)
            return data.get("data", []) if isinstance(data, dict) else (data or [])
        self._ensure_vault_ready()
        args = ["list", "items"]
        if search:
            args += ["--search", search]
        res = self._run(args)
        return json.loads(res.stdout) if res.stdout else []

    def get_item(self, item_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single vault item by ID."""
        if self.use_serve:
            try:
                return self._api("GET", f"/object/item/{item_id}")
            except BitwardenError:
                return None
        self._ensure_vault_ready()
        try:
            res = self._run(["get", "item", item_id])
            return json.loads(res.stdout) if res.stdout else None
        except BitwardenError:
            return None

    def get_template(self, name: str = "item") -> Dict[str, Any]:
        self._ensure_vault_ready()
        res = self._run(["get", "template", name])
        return json.loads(res.stdout)

    def create_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_vault_ready()
        if self.use_serve:
            return self._api("POST", "/object/item", item)
        encoded = self._encode(item)
        res = self._run(["create", "item", encoded])
        return json.loads(res.stdout) if res.stdout else {}

    def edit_item(self, item_id: str, item: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_vault_ready()
        if self.use_serve:
            return self._api("PUT", f"/object/item/{item_id}", item)
        encoded = self._encode(item)
        res = self._run(["edit", "item", item_id, encoded])
        return json.loads(res.stdout) if res.stdout else {}

    def delete_item(self, item_id: str, *, permanent: bool = False) -> None:
        self._ensure_vault_ready()
        if self.use_serve:
            self._api("DELETE", f"/object/item/{item_id}")
            return
        args = ["delete", "item", item_id]
        if permanent:
            args.append("--permanent")
        self._run(args)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _encode(self, item: Dict[str, Any]) -> str:
        """Base64-encode an item via ``bw encode`` (matches bw expectations)."""
        res = self._run(["encode"], input_text=json.dumps(item), with_session=False)
        return res.stdout

    def __enter__(self) -> "BitwardenClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop_serve()


# urllib.parse is only needed when use_serve is on; import lazily-safe here.
import urllib.parse  # noqa: E402
