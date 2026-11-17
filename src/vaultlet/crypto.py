"""Vault crypto: Argon2id KEK, AES-256-GCM wrapping and sealing. No I/O."""

import base64
import json
import os
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KDF_DEFAULTS = {"time_cost": 3, "memory_kib": 65536, "parallelism": 4}


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def derive_kek(password: str, salt: bytes, kdf: dict) -> bytes:
    secret = unicodedata.normalize("NFKC", password).encode("utf-8")
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=kdf["time_cost"],
        memory_cost=kdf["memory_kib"],
        parallelism=kdf["parallelism"],
        hash_len=32,
        type=Type.ID,
    )


def _aad(file: dict, purpose: bytes) -> bytes:
    header = {"version": file["version"], "kdf": file["kdf"]}
    blob = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    return blob + b"|" + purpose


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> dict:
    nonce = os.urandom(12)  # fresh nonce for every encryption
    return {"nonce": b64e(nonce), "ct": b64e(AESGCM(key).encrypt(nonce, plaintext, aad))}


def _unseal(key: bytes, box: dict, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(b64d(box["nonce"]), b64d(box["ct"]), aad)


def new_vault(password: str) -> tuple[dict, bytes]:
    vault_key = os.urandom(32)
    return rekey({"version": 1}, vault_key, [], password, KDF_DEFAULTS), vault_key


def rekey(file: dict, vault_key: bytes, entries: list[dict], password: str,
          kdf: dict | None = None) -> dict:
    """Wrap the same vault key under a new password and/or KDF params, with a fresh salt.

    The header is in both AADs, so the entries are re-sealed too. kdf=None keeps the
    file's current params.
    """
    if kdf is None:
        kdf = {k: v for k, v in file["kdf"].items() if k not in ("alg", "salt")}
    salt = os.urandom(16)
    new = {"version": file["version"], "kdf": {"alg": "argon2id", "salt": b64e(salt), **kdf}}
    kek = derive_kek(password, salt, new["kdf"])
    new["wrapped_key"] = _seal(kek, vault_key, _aad(new, b"key"))
    return write_entries(new, vault_key, entries)


def unlock(file: dict, password: str) -> bytes:
    """Return the vault key. Raises InvalidTag on a wrong password or tampering."""
    kek = derive_kek(password, b64d(file["kdf"]["salt"]), file["kdf"])
    return _unseal(kek, file["wrapped_key"], _aad(file, b"key"))


def read_entries(file: dict, vault_key: bytes) -> list[dict]:
    return json.loads(_unseal(vault_key, file["vault"], _aad(file, b"vault")))


def write_entries(file: dict, vault_key: bytes, entries: list[dict]) -> dict:
    plaintext = json.dumps(entries).encode()
    return {**file, "vault": _seal(vault_key, plaintext, _aad(file, b"vault"))}


def subkey(key: bytes, info: bytes) -> bytes:
    """Derive an independent 32-byte key for one purpose (HKDF-SHA256; INFO separates purposes)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(key)


def sync_auth_key(password: str, kdf: dict) -> bytes:
    """Sync login key: HKDF of the KEK. The server only learns this, and it can't be turned back into the KEK."""
    return subkey(derive_kek(password, b64d(kdf["salt"]), kdf), b"vaultlet sync auth v1")
