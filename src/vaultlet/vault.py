"""Vault file I/O and error mapping. Crypto lives in crypto.py."""

import json
import os
import shutil
from pathlib import Path

from cryptography.exceptions import InvalidTag

from vaultlet import crypto
from vaultlet.errors import CorruptVault, WrongPassword

REQUIRED_FIELDS = ("version", "kdf", "wrapped_key", "vault")


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
