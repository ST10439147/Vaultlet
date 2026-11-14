"""Vault file I/O and error mapping. Crypto lives in crypto.py."""

import json
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
    # ponytail: plain write; atomic temp-file + os.replace comes in section 2
    Path(path).write_text(json.dumps(file), encoding="utf-8")


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
