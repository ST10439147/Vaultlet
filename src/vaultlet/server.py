"""Optional sync server. Stores each account's vault file exactly as the client encrypted it.

The server never sees a master password, KEK or vault key. Clients log in with an auth key
(HKDF of the KEK, see crypto.sync_auth_key); only its SHA-256 is stored. Every write names the
version it was based on, and a stale write gets 409 so the client merges instead of overwriting.

Run: vaultlet-server --cert cert.pem --key key.pem   (pip install "vaultlet[server]")
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import sqlite3
import sys
import uuid
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request

from vaultlet import vault
from vaultlet.errors import CorruptVault

MAX_BODY = 16 * 1024 * 1024  # far above any real vault; stops memory-exhaustion uploads

SCHEMA = """CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY, auth_hash BLOB NOT NULL, version INTEGER NOT NULL, blob TEXT NOT NULL)"""


def _hash(auth_key: bytes) -> bytes:
    # The auth key is 256 random-looking bits, so a fast hash is enough: there's nothing to brute-force.
    return hashlib.sha256(auth_key).digest()


def _decode_key(text: object) -> bytes:
    try:
        key = base64.b64decode(text, validate=True) if isinstance(text, str) else b""
    except binascii.Error:
        key = b""
    if len(key) != 32:
        raise HTTPException(400, "auth_key must be 32 bytes, base64")
    return key


def _check_blob(blob: object) -> str:
    try:
        vault.check_file(blob)  # keeps /kdf answerable and rejects junk; contents stay opaque
    except CorruptVault as exc:
        raise HTTPException(422, f"not a vault file: {exc}") from exc
    return json.dumps(blob)


async def _json_body(request: Request) -> dict:
    size = request.headers.get("content-length")
    if size is None:
        raise HTTPException(411, "Content-Length required")
    if not size.isdigit() or int(size) > MAX_BODY:
        raise HTTPException(413, "request too large")
    try:
        data = json.loads(await request.body())
    except ValueError as exc:
        raise HTTPException(400, "body must be JSON") from exc
    if not isinstance(data, dict):
        raise HTTPException(400, "body must be a JSON object")
    return data


def create_app(db_path: str | Path, register_token: str | None) -> FastAPI:
    # No interactive docs: nothing here is meant for browsing.
    app = FastAPI(title="Vaultlet sync", docs_url=None, redoc_url=None, openapi_url=None)
    with sqlite3.connect(db_path) as conn:
        conn.execute(SCHEMA)

    def db() -> sqlite3.Connection:
        # ponytail: one SQLite connection per request, blocking calls in async handlers; fine for a
        # personal server, move to a thread pool or a real DB if many users share it
        return sqlite3.connect(db_path)

    def row(conn: sqlite3.Connection, account: str) -> tuple[bytes, int, str]:
        found = conn.execute("SELECT auth_hash, version, blob FROM accounts WHERE id = ?", (account,)).fetchone()
        if found is None:
            raise HTTPException(404, "no such account")
        return found

    def authorize(conn: sqlite3.Connection, account: str, authorization: str | None) -> tuple[int, str]:
        auth_hash, version, blob = row(conn, account)
        scheme, _, token = (authorization or "").partition(" ")
        try:
            key = base64.b64decode(token, validate=True)
        except binascii.Error:
            key = b""
        if scheme.lower() != "bearer" or not hmac.compare_digest(_hash(key), auth_hash):
            raise HTTPException(401, "bad auth key", headers={"WWW-Authenticate": "Bearer"})
        return version, blob

    @app.post("/v1/accounts", status_code=201)
    async def register(request: Request, x_register_token: str | None = Header(None)) -> dict:
        if not register_token:
            raise HTTPException(403, "registration is disabled on this server")
        if not hmac.compare_digest((x_register_token or "").encode(), register_token.encode()):
            raise HTTPException(403, "wrong registration token")
        data = await _json_body(request)
        auth_key, blob = _decode_key(data.get("auth_key")), _check_blob(data.get("blob"))
        account = uuid.uuid4().hex
        with db() as conn:
            conn.execute("INSERT INTO accounts VALUES (?, ?, 1, ?)", (account, _hash(auth_key), blob))
        return {"account": account, "version": 1}

    @app.get("/v1/accounts/{account}/kdf")
    def kdf(account: str) -> dict:
        """Pre-login: the KDF settings and salt a client needs to derive its auth key. Not secret."""
        with db() as conn:
            return {"kdf": json.loads(row(conn, account)[2])["kdf"]}

    @app.get("/v1/accounts/{account}/vault")
    def pull(account: str, authorization: str | None = Header(None)) -> dict:
        with db() as conn:
            version, blob = authorize(conn, account, authorization)
        return {"version": version, "blob": json.loads(blob)}

    @app.put("/v1/accounts/{account}/vault")
    async def push(account: str, request: Request, authorization: str | None = Header(None)) -> dict:
        data = await _json_body(request)
        base = data.get("base_version")
        if type(base) is not int:
            raise HTTPException(400, "base_version must be an integer")
        blob = _check_blob(data.get("blob"))
        with db() as conn:
            authorize(conn, account, authorization)
            # The new auth key rides along when the master password or KDF changed (new salt, new KEK).
            new_hash = _hash(_decode_key(data["auth_key"])) if "auth_key" in data else None
            # Compare-and-swap: only the client that saw the latest version wins; others get 409 and merge.
            changed = conn.execute(
                "UPDATE accounts SET blob = ?, version = version + 1, auth_hash = COALESCE(?, auth_hash) "
                "WHERE id = ? AND version = ?", (blob, new_hash, account, base)).rowcount
            current = row(conn, account)[1]
        if not changed:
            raise HTTPException(409, {"error": "vault changed on the server; pull and merge first",
                                      "version": current})
        return {"version": current}

    return app


def _loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def main(argv: list[str] | None = None) -> None:
    import uvicorn

    parser = argparse.ArgumentParser(prog="vaultlet-server", description="Vaultlet sync server (ciphertext only).")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--db", default=str(Path.home() / ".vaultlet" / "server.db"))
    parser.add_argument("--cert", help="TLS certificate (PEM)")
    parser.add_argument("--key", help="TLS private key (PEM)")
    parser.add_argument("--insecure-http", action="store_true",
                        help="Serve plain HTTP. Only allowed on a loopback address (e.g. behind a local TLS proxy).")
    args = parser.parse_args(argv)

    if not (args.cert and args.key):
        if not (args.insecure_http and _loopback(args.host)):
            sys.exit("TLS is required: pass --cert and --key (plain HTTP only with --insecure-http on loopback).")
    token = os.environ.get("VAULTLET_REGISTER_TOKEN")
    print("Registration " + ("enabled (VAULTLET_REGISTER_TOKEN is set)." if token
                             else "disabled. Set VAULTLET_REGISTER_TOKEN to allow new accounts."))
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    uvicorn.run(create_app(args.db, token), host=args.host, port=args.port,
                ssl_certfile=args.cert, ssl_keyfile=args.key)


if __name__ == "__main__":
    main()
