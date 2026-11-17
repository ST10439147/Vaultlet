"""Sync client. Sends the encrypted vault file and an HKDF-derived auth key; nothing else leaves.

State lives next to the vault in `<vault>.sync` (JSON, not secret): server URL, account id, the
server version last synced, the KDF salt last synced, and HMAC fingerprints of each entry as of
that sync. The fingerprints are keyed from the vault key, so they reveal only ids and the count.
They make the merge three-way: a side that changed an entry since the last sync wins over a side
that didn't; when both changed it, both versions are kept.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import shutil
import ssl
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from vaultlet import crypto, vault
from vaultlet.errors import VaultletError, WrongPassword

BASE_INFO = b"vaultlet sync base v1"


class SyncError(VaultletError):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def config_path(path: Path) -> Path:
    return path.with_name(path.name + ".sync")


def load_config(path: Path) -> dict:
    try:
        return json.loads(config_path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SyncError("This vault isn't set up for sync. Run 'vaultlet sync register' or 'sync link'.") from None


def save_config(path: Path, cfg: dict) -> None:
    config_path(path).write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def check_url(url: str) -> str:
    """TLS is mandatory, except plain http to this machine (local testing, or a local TLS proxy)."""
    parts = urlsplit(url)
    if parts.scheme == "https":
        return url.rstrip("/")
    try:
        loopback = parts.hostname == "localhost" or ipaddress.ip_address(parts.hostname or "").is_loopback
    except ValueError:
        loopback = False
    if parts.scheme == "http" and loopback:
        return url.rstrip("/")
    raise SyncError("The server URL must start with https:// (plain http is only allowed for localhost).")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _request(cfg: dict, method: str, route: str, body: dict | None = None,
             auth: bytes | None = None, headers: dict | None = None) -> dict:
    headers = {"Content-Type": "application/json", "User-Agent": "vaultlet", **(headers or {})}
    if auth is not None:
        headers["Authorization"] = "Bearer " + _b64(auth)
    request = urllib.request.Request(check_url(cfg["url"]) + route, method=method, headers=headers,
                                     data=None if body is None else json.dumps(body).encode())
    context = ssl.create_default_context(cafile=cfg.get("cafile"))  # cafile: trust a self-signed server cert
    try:
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("detail")
        except ValueError:
            detail = None
        message = detail.get("error") if isinstance(detail, dict) else detail
        raise SyncError(f"Server said {exc.code}: {message or exc.reason}", exc.code) from None
    except (urllib.error.URLError, OSError) as exc:  # includes TLS verification failures
        raise SyncError(f"Could not reach the sync server: {getattr(exc, 'reason', exc)}") from None


def _server_kdf(cfg: dict) -> dict:
    kdf = _request(cfg, "GET", f"/v1/accounts/{cfg['account']}/kdf")["kdf"]
    vault.check_file({"version": 1, "kdf": kdf, "wrapped_key": None, "vault": None})  # bounded before Argon2 runs
    return kdf


def _pull(cfg: dict, auth: bytes) -> tuple[int, dict]:
    remote = _request(cfg, "GET", f"/v1/accounts/{cfg['account']}/vault", auth=auth)
    vault.check_file(remote["blob"])
    return remote["version"], remote["blob"]


def fingerprints(key: bytes, entries: list[dict]) -> dict[str, str]:
    k = crypto.subkey(key, BASE_INFO)
    return {e["id"]: hmac.new(k, json.dumps(e, sort_keys=True).encode(), hashlib.sha256).hexdigest()
            for e in entries}


def merge3(base: dict[str, str], local: list[dict], remote: list[dict], key: bytes) -> tuple[list[dict], int]:
    """Three-way merge by entry id. Returns (entries, number of conflicts kept as copies)."""
    lf, rf = fingerprints(key, local), fingerprints(key, remote)
    lmap, rmap = {e["id"]: e for e in local}, {e["id"]: e for e in remote}
    merged, conflicts = [], 0
    for eid in [*lmap, *(i for i in rmap if i not in lmap)]:
        l, r, b = lmap.get(eid), rmap.get(eid), base.get(eid)
        if l and r:
            if lf[eid] == rf[eid] or rf[eid] == b:
                merged.append(l)  # same, or only this device changed it
            elif lf[eid] == b:
                merged.append(r)  # only the other side changed it
            else:  # both changed it: keep both rather than lose an edit
                merged += [l, {**r, "id": uuid.uuid4().hex, "title": r["title"] + " (conflict)"}]
                conflicts += 1
        elif l:  # not on the server: new here, or deleted there
            if b is None or lf[eid] != b:
                merged.append(l)  # new, or edited here after being deleted there: keep the edit
        elif b is None or rf[eid] != b:
            merged.append(r)  # new there, or edited there after being deleted here
    return merged, conflicts


def _canon(entries: list[dict]) -> list[str]:
    return sorted(json.dumps(e, sort_keys=True) for e in entries)


def register(path: Path, password: str, url: str, token: str, cafile: str | None = None) -> str:
    """Upload this vault as a new account. Returns the account id other devices need for 'link'."""
    if config_path(path).exists():
        raise SyncError("This vault is already set up for sync.")
    cfg = {"url": check_url(url), "cafile": cafile}
    file, key, entries = vault.open_vault(path, password)
    reply = _request(cfg, "POST", "/v1/accounts", headers={"X-Register-Token": token}, body={
        "auth_key": _b64(crypto.sync_auth_key(password, file["kdf"])), "blob": file})
    save_config(path, {**cfg, "account": reply["account"], "version": reply["version"],
                       "salt": file["kdf"]["salt"], "base": fingerprints(key, entries)})
    return reply["account"]


def link(path: Path, password: str, url: str, account: str, cafile: str | None = None) -> int:
    """Download an existing account into a new vault file on this device. Returns the entry count."""
    if path.exists():
        raise SyncError(f"{path} already exists. 'link' downloads into a new vault file; pick another --vault "
                        "and move entries across with export / import-vault.")
    cfg = {"url": check_url(url), "cafile": cafile, "account": account}
    try:
        version, blob = _pull(cfg, crypto.sync_auth_key(password, _server_kdf(cfg)))
    except SyncError as exc:
        if exc.status == 401:
            raise WrongPassword("wrong master password for that account") from None
        raise
    key = vault.unlock(blob, password)
    entries = vault.read_entries(blob, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    vault.save(path, blob)
    save_config(path, {**cfg, "version": version, "salt": blob["kdf"]["salt"], "base": fingerprints(key, entries)})
    return len(entries)


def run(path: Path, password: str, ask_password: Callable[[str], str], attempts: int = 5) -> str:
    """Pull, merge, push. Retries when another device pushed in between (409)."""
    cfg = load_config(path)
    file, key, local = vault.open_vault(path, password)
    server_password = password
    for _ in range(attempts):
        kdf = _server_kdf(cfg)
        try:
            version, blob = _pull(cfg, crypto.sync_auth_key(server_password, kdf))
        except SyncError as exc:
            if exc.status != 401 or server_password != password:
                raise WrongPassword("wrong master password for the synced vault") if exc.status == 401 else exc
            # Another device changed the master password, or this one did and hasn't pushed yet.
            server_password = ask_password("The synced copy uses a different master password. Enter that one")
            continue
        remote_key = vault.unlock(blob, server_password)
        remote = vault.read_entries(blob, remote_key)
        merged, conflicts = merge3(cfg["base"], local, remote, key)

        adopt = blob["kdf"]["salt"] != cfg["salt"]  # password/KDF changed elsewhere since our last sync: take it
        new_file, new_key = (blob, remote_key) if adopt else (file, key)
        new_file = crypto.write_entries(new_file, new_key, merged)
        local_changed = adopt or _canon(merged) != _canon(local)
        header_changed = new_file["wrapped_key"] != blob["wrapped_key"]  # changed here: server needs it
        if local_changed:
            vault.save(path, new_file)  # saved before pushing: a failed push just merges again next time
            if adopt:  # like vault.rekey: the old password must not keep opening the .bak
                shutil.copyfile(path, path.with_name(path.name + ".bak"))
        if header_changed or _canon(merged) != _canon(remote):
            body = {"base_version": version, "blob": new_file}
            if header_changed:
                body["auth_key"] = _b64(crypto.sync_auth_key(password, new_file["kdf"]))
            try:
                version = _request(cfg, "PUT", f"/v1/accounts/{cfg['account']}/vault", body,
                                   auth=crypto.sync_auth_key(server_password, kdf))["version"]
            except SyncError as exc:
                if exc.status != 409:
                    raise
                file, key, local = new_file, new_key, merged  # someone pushed meanwhile: merge again
                continue
            pushed = True
        else:
            pushed = False
        save_config(path, {**cfg, "version": version, "salt": new_file["kdf"]["salt"],
                           "base": fingerprints(new_key, merged)})
        parts = ["Pulled changes." if local_changed else "", "Pushed changes." if pushed else ""]
        if adopt:
            parts.append("This device now uses the synced master password.")
        if conflicts:
            parts.append(f"{conflicts} entr{'y was' if conflicts == 1 else 'ies were'} edited on both sides; "
                         "the other version was kept with '(conflict)' in its title.")
        return " ".join(p for p in parts if p) or "Already up to date."
    raise SyncError("The server copy kept changing during sync; try again.")
