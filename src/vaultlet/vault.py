"""Vault file I/O and error mapping. Crypto lives in crypto.py."""

import json
import os
import shutil
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag

from vaultlet import crypto
from vaultlet.errors import CorruptVault, EntryNotFound, WrongPassword

REQUIRED_FIELDS = ("version", "kdf", "wrapped_key", "vault")
ENTRY_FIELDS = ("title", "username", "password", "url", "notes")


def load(path: str | Path) -> dict:
    """Read and structurally check a vault file. Missing files raise FileNotFoundError."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except ValueError as exc:  # covers empty, truncated and non-JSON input
        raise CorruptVault("vault file is not valid JSON") from exc
    if not isinstance(data, dict) or any(k not in data for k in REQUIRED_FIELDS):
        raise CorruptVault("vault file is missing required fields")
    return data


def save(path: str | Path, file: dict) -> None:
    """Atomically replace the vault file, keeping one .bak of the previous version."""
    path = Path(path)
    data = json.dumps(file).encode("utf-8")
    tmp = path.with_name(path.name + ".tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            shutil.copyfile(path, path.with_name(path.name + ".bak"))
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def unlock(file: dict, password: str) -> bytes:
    try:
        return crypto.unlock(file, password)
    except InvalidTag as exc:
        raise WrongPassword("wrong master password") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise CorruptVault("vault header is malformed") from exc


def read_entries(file: dict, vault_key: bytes) -> list[dict]:
    try:
        return crypto.read_entries(file, vault_key)
    except InvalidTag as exc:
        raise CorruptVault("vault contents failed authentication") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise CorruptVault("vault contents are malformed") from exc


# Entry operations work on the decrypted list in memory. Callers persist with persist().

def add(entries: list[dict], *, title: str, username: str = "", password: str = "",
        url: str = "", notes: str = "") -> dict:
    entry = {"id": uuid.uuid4().hex, "title": title, "username": username,
             "password": password, "url": url, "notes": notes}
    entries.append(entry)
    return entry


def get(entries: list[dict], entry_id: str) -> dict:
    for entry in entries:
        if entry["id"] == entry_id:
            return entry
    raise EntryNotFound(f"no entry with id {entry_id}")


def list_entries(entries: list[dict]) -> list[dict]:
    return sorted(entries, key=lambda e: e["title"].lower())


def edit(entries: list[dict], entry_id: str, **changes: str) -> dict:
    unknown = set(changes) - set(ENTRY_FIELDS)
    if unknown:
        raise ValueError(f"unknown fields: {', '.join(sorted(unknown))}")
    entry = get(entries, entry_id)
    entry.update(changes)
    return entry


def delete(entries: list[dict], entry_id: str) -> None:
    entries.remove(get(entries, entry_id))


def search(entries: list[dict], query: str) -> list[dict]:
    # ponytail: linear scan; add an index if vaults grow past a few thousand entries
    q = query.lower()
    return [e for e in entries if q in e["title"].lower() or q in e["username"].lower()]


def persist(path: str | Path, file: dict, vault_key: bytes, entries: list[dict]) -> dict:
    new_file = crypto.write_entries(file, vault_key, entries)
    save(path, new_file)
    return new_file
