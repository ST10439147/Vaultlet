"""Native messaging helper for the browser extension.

The browser starts this process itself and talks to it over stdin/stdout (4-byte length + JSON),
so there is no network port for web pages or other programs to reach, and the browser only lets
the extension ID in the host manifest connect. It holds the vault key while unlocked and answers:

    status                       -> {unlocked}
    unlock {password}            -> {}
    lock                         -> {}
    match {url}                  -> {entries: [...]}   entries for that site, no secrets
    search {query}               -> {entries: [...]}   any entry, no secrets
    fill {entry, url}             -> {username, password}  only if the entry matches the page
    copy {entry, field}           -> {seconds}          copied by this process; cleared later

Fill credentials are the only secrets sent to the browser, and only for a matching https page.
"""

import argparse
import json
import secrets
import struct
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

import pyperclip

from vaultlet import totp, vault
from vaultlet.errors import CorruptVault, WrongPassword

HOST_NAME = "com.vaultlet.helper"
# Pinned by the public "key" in extension/manifest.json (an unpacked extension's ID comes from it).
EXTENSION_ID = "lpbnpdbfajmdfjjfmgbdngnaoghfppan"
CLEAR_AFTER = 20
IDLE_LOCK = 300
MAX_MESSAGE = 1024 * 1024


def read_message(stream) -> dict | None:
    header = stream.read(4)
    if len(header) < 4:
        return None  # browser closed the port
    (length,) = struct.unpack("=I", header)  # native byte order, per the native messaging spec
    if length > MAX_MESSAGE:
        raise ValueError("message too large")
    return json.loads(stream.read(length).decode("utf-8"))


def write_message(stream, message: dict) -> None:
    data = json.dumps(message).encode("utf-8")
    stream.write(struct.pack("=I", len(data)) + data)
    stream.flush()


def host_of(url: str) -> str:
    if "://" not in url:
        url = "https://" + url  # entries often store just "github.com"
    host = (urlsplit(url).hostname or "").lower()
    return host.removeprefix("www.")


def site_matches(entry_url: str, page_url: str) -> bool:
    """Entry for example.com matches example.com and its subdomains, never lookalikes."""
    # ponytail: suffix match on the stored host, no public-suffix list; an entry saved as a bare
    # shared suffix (github.io) would match every site under it
    entry, page = host_of(entry_url), host_of(page_url)
    return bool(entry) and (page == entry or page.endswith("." + entry))


def fillable(page_url: str) -> bool:
    parts = urlsplit(page_url)
    return parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1"))


def summary(e: dict) -> dict:
    return {"id": e["id"], "title": e["title"], "username": e["username"], "url": e["url"],
            "has_totp": bool(e.get("totp"))}


class Helper:
    def __init__(self, path: Path, idle: int = IDLE_LOCK) -> None:
        self.path, self.idle = path, idle
        self.key: bytes | None = None
        self.lock = threading.Lock()
        self.idle_timer: threading.Timer | None = None
        self.copied: str | None = None

    # --- state -------------------------------------------------------------
    def entries(self) -> list[dict]:
        # Re-read every time so edits from the CLI, TUI or a sync show up; no Argon2 needed.
        return vault.read_entries(vault.load(self.path), self.key)

    def entry(self, entry_id: str) -> dict:
        found = [e for e in self.entries() if e["id"] == entry_id]
        if not found:
            raise LookupError("no such entry")
        return found[0]

    def do_lock(self) -> None:
        # ponytail: drops the reference only; Python can't reliably wipe the key bytes
        self.key = None

    def touch(self) -> None:
        if self.idle_timer:
            self.idle_timer.cancel()
        self.idle_timer = threading.Timer(self.idle, self.locked_call, (self.do_lock,))
        self.idle_timer.daemon = True
        self.idle_timer.start()

    def locked_call(self, fn, *args):
        with self.lock:
            return fn(*args)

    # --- clipboard ---------------------------------------------------------
    def copy(self, value: str, seconds: int) -> None:
        pyperclip.copy(value)
        self.copied = value
        timer = threading.Timer(seconds, self.locked_call, (self.clear_clipboard, value))
        timer.daemon = True
        timer.start()

    def clear_clipboard(self, value: str | None = None) -> None:
        """Clear only if the clipboard still holds what we copied (and, from a timer, that same value)."""
        value = value or self.copied
        if value is None or value != self.copied:
            return
        try:
            if secrets.compare_digest(pyperclip.paste().encode(), value.encode()):
                pyperclip.copy("")
        except pyperclip.PyperclipException:
            pass
        self.copied = None

    # --- protocol ----------------------------------------------------------
    def handle(self, msg: dict) -> dict:
        with self.lock:
            try:
                reply = self.dispatch(msg)
                reply["ok"] = True
            except (WrongPassword, CorruptVault):
                reply = {"ok": False, "error": "Could not unlock the vault: wrong password or damaged file."}
            except FileNotFoundError:
                reply = {"ok": False, "error": f"No vault at {self.path}."}
            except (LookupError, PermissionError, ValueError, pyperclip.PyperclipException) as exc:
                reply = {"ok": False, "error": str(exc) or type(exc).__name__}
        if "id" in msg:
            reply["id"] = msg["id"]
        return reply

    def dispatch(self, msg: dict) -> dict:
        cmd = msg.get("cmd")
        if cmd == "status":
            return {"unlocked": self.key is not None}
        if cmd == "unlock":
            password = msg.get("password")
            if not isinstance(password, str) or not password:
                raise ValueError("password required")
            self.key = vault.open_vault(self.path, password)[1]
            self.touch()
            return {}
        if cmd == "lock":
            self.do_lock()
            return {}
        if self.key is None:
            raise PermissionError("locked")
        self.touch()
        if cmd == "match":
            url = str(msg.get("url", ""))
            hits = [summary(e) for e in vault.list_entries(self.entries()) if site_matches(e["url"], url)]
            return {"entries": hits, "fillable": fillable(url)}
        if cmd == "search":
            hits = vault.search(self.entries(), str(msg.get("query", "")))
            return {"entries": [summary(e) for e in vault.list_entries(hits)[:50]]}
        if cmd == "fill":
            e, url = self.entry(str(msg.get("entry"))), str(msg.get("url", ""))
            if not fillable(url):
                raise PermissionError("Only https pages are filled. Copy the password instead.")
            if not site_matches(e["url"], url):
                raise PermissionError(f"{e['title']} is not saved for {host_of(url)}.")
            return {"username": e["username"], "password": e["password"], "host": urlsplit(url).hostname}
        if cmd == "copy":
            e, field = self.entry(str(msg.get("entry"))), msg.get("field")
            if field == "totp":
                if not e.get("totp"):
                    raise LookupError("no TOTP secret for this entry")
                code, left = totp.code(e["totp"])
                self.copy(code, min(CLEAR_AFTER, left))
                return {"seconds": min(CLEAR_AFTER, left)}
            if field not in ("username", "password"):
                raise ValueError("field must be username, password or totp")
            self.copy(e[field], CLEAR_AFTER)
            return {"seconds": CLEAR_AFTER}
        raise ValueError(f"unknown command {cmd!r}")


# --- install -----------------------------------------------------------------
# Chromium browsers find hosts via a per-user registry key on Windows, a per-user folder elsewhere.
WIN_KEYS = [rf"Software\{b}\NativeMessagingHosts\{HOST_NAME}"
            for b in (r"Google\Chrome", r"Microsoft\Edge", "Chromium", r"BraveSoftware\Brave-Browser")]
UNIX_DIRS = {
    "darwin": ["Library/Application Support/" + d for d in
               ("Google/Chrome", "Microsoft Edge", "Chromium", "BraveSoftware/Brave-Browser")],
    "linux": [".config/" + d for d in ("google-chrome", "microsoft-edge", "chromium", "BraveSoftware/Brave-Browser")],
}


def install(vault_path: Path, idle: int, home: Path, platform: str = sys.platform,
            python: str = sys.executable) -> list[str]:
    """Write the launcher and host manifest under ~/.vaultlet/native and register them. Returns where."""
    folder = home / ".vaultlet" / "native"
    folder.mkdir(parents=True, exist_ok=True)
    args = f'-m vaultlet.native --vault "{vault_path.resolve()}" --idle {idle}'
    if platform == "win32":  # the manifest "path" can't carry arguments, so a wrapper passes them
        launcher = folder / "vaultlet-native.bat"
        launcher.write_text(f'@echo off\r\n"{python}" {args} %*\r\n', encoding="utf-8", newline="")  # keep CRLF as is
    else:
        launcher = folder / "vaultlet-native.sh"
        launcher.write_text(f'#!/bin/sh\nexec "{python}" {args} "$@"\n', encoding="utf-8")
        launcher.chmod(0o755)
    manifest = folder / f"{HOST_NAME}.json"
    manifest.write_text(json.dumps({
        "name": HOST_NAME, "description": "Vaultlet password helper", "path": str(launcher),
        "type": "stdio", "allowed_origins": [f"chrome-extension://{EXTENSION_ID}/"],
    }, indent=2), encoding="utf-8")
    if platform == "win32":
        import winreg
        for key in WIN_KEYS:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
                winreg.SetValue(handle, "", winreg.REG_SZ, str(manifest))
        return [f"HKCU\\{k}" for k in WIN_KEYS]
    placed = []
    for browser in UNIX_DIRS.get("darwin" if platform == "darwin" else "linux"):
        if (home / browser).is_dir():  # only browsers that are installed
            target = home / browser / "NativeMessagingHosts" / f"{HOST_NAME}.json"
            target.parent.mkdir(exist_ok=True)
            target.write_text(manifest.read_text(encoding="utf-8"), encoding="utf-8")
            placed.append(str(target))
    return placed


def uninstall(home: Path, platform: str = sys.platform) -> None:
    if platform == "win32":
        import winreg
        for key in WIN_KEYS:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
            except FileNotFoundError:
                pass
    else:
        for browser in UNIX_DIRS.get("darwin" if platform == "darwin" else "linux"):
            (home / browser / "NativeMessagingHosts" / f"{HOST_NAME}.json").unlink(missing_ok=True)
    for name in ("vaultlet-native.bat", "vaultlet-native.sh", f"{HOST_NAME}.json"):
        (home / ".vaultlet" / "native" / name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="vaultlet-native")
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--idle", type=int, default=IDLE_LOCK)
    # Chrome appends the caller's origin (and on Windows --parent-window=...); the manifest's
    # allowed_origins already limits who can start us, so they're accepted and ignored.
    args, _ = parser.parse_known_args(argv)
    helper = Helper(args.vault, args.idle)
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr  # a stray print() must never corrupt the message stream
    try:
        while (msg := read_message(stdin)) is not None:
            write_message(stdout, helper.handle(msg) if isinstance(msg, dict) else {"ok": False, "error": "bad message"})
    finally:
        helper.locked_call(helper.clear_clipboard)  # browser closed: don't leave a password behind
        helper.do_lock()


if __name__ == "__main__":
    main()
