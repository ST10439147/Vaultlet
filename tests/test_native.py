import base64
import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

from vaultlet import native, vault

EXTENSION = Path(__file__).parents[1] / "extension"


def make_vault(tmp_path):
    path = tmp_path / "vault.json"
    vault.create(path, "pw")
    file, key, entries = vault.open_vault(path, "pw")
    vault.add(entries, title="GitHub", username="me", password="hunter2", url="https://github.com/login",
              totp="JBSWY3DPEHPK3PXP")
    vault.add(entries, title="Bank", username="b", password="money", url="bank.example")
    vault.persist(path, file, key, entries)
    return path


def test_site_matching():
    assert native.site_matches("https://github.com/login", "https://github.com/")
    assert native.site_matches("github.com", "https://gist.github.com/x")
    assert native.site_matches("https://www.github.com", "https://github.com")
    assert not native.site_matches("github.com", "https://github.com.evil.example/")
    assert not native.site_matches("github.com", "https://notgithub.com/")
    assert not native.site_matches("", "https://github.com/")
    assert native.fillable("https://a.b/") and native.fillable("http://localhost:8000/")
    assert not native.fillable("http://github.com/") and not native.fillable("chrome://settings")


def test_extension_id_matches_manifest_key():
    der = base64.b64decode(json.loads((EXTENSION / "manifest.json").read_text())["key"])
    digest = hashlib.sha256(der).hexdigest()[:32]
    assert "".join("abcdefghijklmnop"[int(c, 16)] for c in digest) == native.EXTENSION_ID


def test_helper_over_stdio(tmp_path):
    """Drive the real helper process the way the browser does: length-prefixed JSON on stdin/stdout."""
    path = make_vault(tmp_path)
    proc = subprocess.Popen([sys.executable, "-m", "vaultlet.native", "--vault", str(path),
                             f"chrome-extension://{native.EXTENSION_ID}/"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    seq = iter(range(1, 1000))

    def call(**msg):
        msg["id"] = next(seq)
        native.write_message(proc.stdin, msg)
        reply = native.read_message(proc.stdout)
        assert reply["id"] == msg["id"]
        return reply

    try:
        assert call(cmd="status") == {"ok": True, "unlocked": False, "id": 1}
        assert call(cmd="match", url="https://github.com/")["error"] == "locked"
        assert "Could not unlock" in call(cmd="unlock", password="nope")["error"]
        assert call(cmd="unlock", password="pw")["ok"]

        r = call(cmd="match", url="https://github.com/login")
        assert r["fillable"] and [e["title"] for e in r["entries"]] == ["GitHub"]
        assert r["entries"][0]["has_totp"] and "password" not in r["entries"][0]  # no secrets in lists
        gh = r["entries"][0]["id"]
        assert [e["title"] for e in call(cmd="search", query="ban")["entries"]] == ["Bank"]

        r = call(cmd="fill", entry=gh, url="https://github.com/login")
        assert (r["username"], r["password"], r["host"]) == ("me", "hunter2", "github.com")
        assert "not saved for" in call(cmd="fill", entry=gh, url="https://evil.example/")["error"]
        assert "Only https" in call(cmd="fill", entry=gh, url="http://github.com/")["error"]
        assert not call(cmd="copy", entry=gh, field="notes")["ok"]

        # Edits made elsewhere show up without unlocking again.
        file, key, entries = vault.open_vault(path, "pw")
        vault.add(entries, title="Mail", url="mail.example")
        vault.persist(path, file, key, entries)
        assert call(cmd="match", url="https://mail.example/")["entries"][0]["title"] == "Mail"

        assert call(cmd="lock")["ok"]
        assert call(cmd="fill", entry=gh, url="https://github.com/")["error"] == "locked"
    finally:
        proc.stdin.close()
        assert proc.wait(10) == 0  # closing the port ends the helper cleanly


def test_idle_lock(tmp_path):
    helper = native.Helper(make_vault(tmp_path), idle=1)
    assert helper.handle({"cmd": "unlock", "password": "pw"})["ok"]
    helper.idle_timer.join(3)
    assert helper.handle({"cmd": "status"})["unlocked"] is False


def test_install_unix(tmp_path):
    (tmp_path / ".config" / "google-chrome").mkdir(parents=True)
    vault_path = tmp_path / "v.json"
    places = native.install(vault_path, 120, tmp_path, platform="linux", python="/usr/bin/python3")
    assert places == [str(tmp_path / ".config/google-chrome/NativeMessagingHosts/com.vaultlet.helper.json")]
    manifest = json.loads(Path(places[0]).read_text())
    assert manifest["allowed_origins"] == [f"chrome-extension://{native.EXTENSION_ID}/"]
    launcher = Path(manifest["path"]).read_text()
    assert str(vault_path.resolve()) in launcher and "--idle 120" in launcher
    native.uninstall(tmp_path, platform="linux")
    assert not Path(places[0]).exists() and not Path(manifest["path"]).exists()


def test_install_windows_registers_manifest(tmp_path, monkeypatch):
    written = {}

    class Key:
        def __init__(self, name):
            self.name = name

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    fake = types.SimpleNamespace(HKEY_CURRENT_USER="HKCU", REG_SZ=1,
                                 CreateKey=lambda root, name: Key(name),
                                 SetValue=lambda key, sub, kind, value: written.__setitem__(key.name, value))
    monkeypatch.setitem(sys.modules, "winreg", fake)  # never touch the real registry in tests
    native.install(tmp_path / "v.json", 300, tmp_path, platform="win32", python=r"C:\py\python.exe")
    manifest = tmp_path / ".vaultlet" / "native" / "com.vaultlet.helper.json"
    assert set(written) == set(native.WIN_KEYS) and set(written.values()) == {str(manifest)}
    bat = (tmp_path / ".vaultlet" / "native" / "vaultlet-native.bat").read_text()
    assert bat.startswith("@echo off") and r'"C:\py\python.exe" -m vaultlet.native' in bat
