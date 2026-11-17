"""Vault file I/O and error mapping. Crypto lives in crypto.py."""

import csv
import io
import json
import os
import shutil
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag

from vaultlet import crypto
from vaultlet.errors import CorruptVault, EntryNotFound, WrongPassword

REQUIRED_FIELDS = ("version", "kdf", "wrapped_key", "vault")
ENTRY_FIELDS = ("title", "username", "password", "url", "notes", "totp")
# Upper bounds stop a hostile vault or export file from demanding e.g. 64 GiB or hours of Argon2id.
KDF_LIMITS = {"time_cost": (1, 50), "memory_kib": (8, 4 * 1024 * 1024), "parallelism": (1, 64)}


def check_kdf(kdf: object) -> None:
    if not isinstance(kdf, dict):
        raise CorruptVault("vault KDF parameters are malformed")
    for name, (low, high) in KDF_LIMITS.items():
        value = kdf.get(name)
        if type(value) is not int or not low <= value <= high:
            raise CorruptVault(f"vault KDF parameter {name} is out of range")
    if kdf["memory_kib"] < 8 * kdf["parallelism"]:  # Argon2 minimum
        raise CorruptVault("vault KDF memory is too small for its parallelism")


def load(path: str | Path) -> dict:
    """Read and structurally check a vault file. Missing files raise FileNotFoundError."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except ValueError as exc:  # covers empty, truncated and non-JSON input
        raise CorruptVault("vault file is not valid JSON") from exc
    check_file(data)
    return data


def check_file(data: object) -> None:
    """Structural check of a parsed vault file; also used on blobs from the sync server and its clients."""
    if not isinstance(data, dict) or any(k not in data for k in REQUIRED_FIELDS):
        raise CorruptVault("vault file is missing required fields")
    check_kdf(data["kdf"])
    if not isinstance(data["kdf"].get("salt"), str):
        raise CorruptVault("vault KDF salt is missing")


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
        entries = crypto.read_entries(file, vault_key)
    except InvalidTag as exc:
        raise CorruptVault("vault contents failed authentication") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise CorruptVault("vault contents are malformed") from exc
    if isinstance(entries, list):  # vaults and exports from before TOTP support lack the field
        for e in entries:
            if isinstance(e, dict):
                e.setdefault("totp", "")
    return entries


def create(path: str | Path, password: str, entries: list[dict] | None = None) -> None:
    """Write a new vault (fresh salt and vault key). Also used for encrypted exports."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    file, vault_key = crypto.new_vault(password)
    save(path, crypto.write_entries(file, vault_key, entries or []))


CSV_REQUIRED = ("url", "username", "password")  # Chrome/Edge add name,note; Firefox adds httpRealm etc.


def import_csv(entries: list[dict], text: str) -> tuple[int, int]:
    """Add rows from a browser password export. Returns (added, skipped as duplicates).

    Duplicates are rows whose (url, username, password) already exist in the vault or earlier in the file.
    """
    reader = csv.DictReader(io.StringIO(text))
    missing = [c for c in CSV_REQUIRED if c not in (reader.fieldnames or [])]
    if missing:
        raise ValueError(f"not a browser password export: missing column(s) {', '.join(missing)}")
    seen = {(e["url"], e["username"], e["password"]) for e in entries}
    added = skipped = 0
    for row in reader:
        url, username, password = (row.get(c) or "" for c in CSV_REQUIRED)
        if not (url or username or password):
            continue
        if (url, username, password) in seen:
            skipped += 1
            continue
        seen.add((url, username, password))
        title = row.get("name") or urlsplit(url).hostname or url or username
        add(entries, title=title, username=username, password=password, url=url,
            notes=row.get("note") or row.get("notes") or "")
        added += 1
    return added, skipped


def merge(entries: list[dict], incoming: object) -> int:
    """Add entries from another vault whose ids aren't already present. Returns how many were added."""
    if not isinstance(incoming, list) or not all(
        isinstance(e, dict) and all(isinstance(e.get(k), str) for k in ("id", *ENTRY_FIELDS))
        for e in incoming
    ):
        raise CorruptVault("imported vault has malformed entries")
    have = {e["id"] for e in entries}
    added = 0
    for e in incoming:
        if e["id"] not in have:
            have.add(e["id"])
            entries.append({k: e[k] for k in ("id", *ENTRY_FIELDS)})
            added += 1
    return added


def open_vault(path: str | Path, password: str,
               kdf: dict | None = None) -> tuple[dict, bytes, list[dict]]:
    """Load, unlock and decrypt. Returns (file, vault_key, entries).

    Re-keys to KDF if given; otherwise raises any parameter below crypto.KDF_DEFAULTS up to it,
    so raising the defaults later upgrades every vault the next time it is opened.
    """
    file = load(path)
    vault_key = unlock(file, password)
    entries = read_entries(file, vault_key)
    current = {k: file["kdf"][k] for k in crypto.KDF_DEFAULTS}
    target = kdf or {k: max(v, crypto.KDF_DEFAULTS[k]) for k, v in current.items()}
    if target != current:
        file = rekey(path, file, vault_key, entries, password, target)
    return file, vault_key, entries


# Entry operations work on the decrypted list in memory. Callers persist with persist().

def add(entries: list[dict], *, title: str, username: str = "", password: str = "",
        url: str = "", notes: str = "", totp: str = "") -> dict:
    entry = {"id": uuid.uuid4().hex, "title": title, "username": username,
             "password": password, "url": url, "notes": notes, "totp": totp}
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


def rekey(path: str | Path, file: dict, vault_key: bytes, entries: list[dict],
          password: str, kdf: dict | None = None) -> dict:
    """Re-key the vault under a new password and/or KDF params and save it atomically.

    The .bak is then replaced too, so the old password (or weak KDF) no longer opens any copy.
    """
    new_file = crypto.rekey(file, vault_key, entries, password, kdf)
    save(path, new_file)
    # ponytail: overwrite, not a secure wipe; SSDs and filesystem snapshots can keep old blocks
    shutil.copyfile(path, Path(path).with_name(Path(path).name + ".bak"))
    return new_file
