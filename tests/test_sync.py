import base64
import datetime
import ipaddress
import json
import sqlite3
import threading
import time

import pytest

pytest.importorskip("fastapi")
uvicorn = pytest.importorskip("uvicorn")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from vaultlet import crypto, sync, vault
from vaultlet.errors import WrongPassword
from vaultlet.server import create_app

TOKEN = "reg-token"


def self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vaultlet-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return str(cert_path), str(key_path)


@pytest.fixture
def server(tmp_path):
    cert, key = self_signed(tmp_path)
    db = tmp_path / "server.db"
    config = uvicorn.Config(create_app(db, TOKEN), host="127.0.0.1", port=0, log_level="warning",
                            ssl_certfile=cert, ssl_keyfile=key)
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    while not srv.started:
        time.sleep(0.02)
    port = srv.servers[0].sockets[0].getsockname()[1]
    yield {"url": f"https://127.0.0.1:{port}", "cafile": cert, "db": db}
    srv.should_exit = True
    thread.join(5)


def titles(path, pw="pw"):
    return sorted(e["title"] for e in vault.open_vault(path, pw)[2])


def change(path, fn, pw="pw"):
    file, key, entries = vault.open_vault(path, pw)
    fn(entries)
    vault.persist(path, file, key, entries)


def never(_):
    raise AssertionError("should not ask for another password")


def test_merge3_rules():
    key = bytes(32)
    e = lambda i, t: {"id": i, "title": t}
    base_entries = [e("keep", "K"), e("ledit", "A"), e("redit", "B"), e("both", "C"), e("ldel", "D"), e("rdel", "E")]
    base = sync.fingerprints(key, base_entries)
    local = [e("keep", "K"), e("ledit", "A2"), e("redit", "B"), e("both", "C-local"), e("rdel", "E"), e("lnew", "N")]
    remote = [e("keep", "K"), e("ledit", "A"), e("redit", "B2"), e("both", "C-remote"), e("ldel", "D"), e("rnew", "M")]
    merged, conflicts = sync.merge3(base, local, remote, key)
    assert sorted(x["title"] for x in merged) == ["A2", "B2", "C-local", "C-remote (conflict)", "K", "M", "N"]
    assert conflicts == 1


def test_two_devices(server, tmp_path):
    a, b = tmp_path / "a" / "vault.json", tmp_path / "b" / "vault.json"
    vault.create(a, "pw")
    change(a, lambda es: vault.add(es, title="GitHub", password="hunter2"))

    with pytest.raises(sync.SyncError, match="403"):
        sync.register(a, "pw", server["url"], "wrong", server["cafile"])
    with pytest.raises(sync.SyncError, match="certificate verify failed"):  # TLS is really verified
        sync.register(a, "pw", server["url"], TOKEN)
    account = sync.register(a, "pw", server["url"], TOKEN, server["cafile"])

    with pytest.raises(WrongPassword):
        sync.link(b, "nope", server["url"], account, server["cafile"])
    assert sync.link(b, "pw", server["url"], account, server["cafile"]) == 1
    assert sync.run(b, "pw", never) == "Already up to date."

    # Independent changes on each side merge.
    change(a, lambda es: vault.add(es, title="Mail"))
    change(b, lambda es: vault.add(es, title="Bank"))
    assert "Pushed" in sync.run(a, "pw", never)
    assert "Pulled" in sync.run(b, "pw", never) and titles(b) == ["Bank", "GitHub", "Mail"]
    sync.run(a, "pw", never)
    assert titles(a) == titles(b)

    # Same entry edited on both sides: both versions survive.
    def retitle(new):
        return lambda es: vault.edit(es, next(e for e in es if e["title"] == "GitHub")["id"], title=new)
    change(a, retitle("GitHub-A"))
    change(b, retitle("GitHub-B"))
    sync.run(a, "pw", never)
    assert "edited on both sides" in sync.run(b, "pw", never)
    sync.run(a, "pw", never)
    assert titles(a) == titles(b) == ["Bank", "GitHub-A (conflict)", "GitHub-B", "Mail"]

    # Deletes propagate.
    change(a, lambda es: vault.delete(es, next(e for e in es if e["title"] == "Bank")["id"]))
    sync.run(a, "pw", never)
    sync.run(b, "pw", never)
    assert "Bank" not in titles(b)

    # Master password change on A: B is asked for it once, then adopts it.
    file, key, entries = vault.open_vault(a, "pw")
    vault.rekey(a, file, key, entries, "new-pw")
    assert sync.run(a, "new-pw", lambda q: "pw") == "Pushed changes."
    asked = []
    msg = sync.run(b, "pw", lambda q: asked.append(q) or "new-pw")
    assert asked and "now uses the synced master password" in msg
    assert titles(b, "new-pw") == titles(a, "new-pw")
    with pytest.raises(WrongPassword):
        vault.open_vault(b, "pw")
    with pytest.raises(WrongPassword):
        vault.open_vault(b.with_name("vault.json.bak"), "pw")  # old password doesn't open the backup either

    # The server only ever held ciphertext and a hash of the auth key.
    raw = server["db"].read_bytes()
    assert b"hunter2" not in raw and b"GitHub" not in raw


def test_server_rejects_stale_and_unauthenticated_writes(server, tmp_path):
    a = tmp_path / "vault.json"
    vault.create(a, "pw")
    account = sync.register(a, "pw", server["url"], TOKEN, server["cafile"])
    cfg = {"url": server["url"], "cafile": server["cafile"], "account": account}
    file = vault.load(a)
    auth = crypto.sync_auth_key("pw", file["kdf"])
    route = f"/v1/accounts/{account}/vault"

    with pytest.raises(sync.SyncError, match="401"):
        sync._request(cfg, "GET", route, auth=bytes(32))
    with pytest.raises(sync.SyncError, match="422"):
        sync._request(cfg, "PUT", route, {"base_version": 1, "blob": {"not": "a vault"}}, auth=auth)
    assert sync._request(cfg, "PUT", route, {"base_version": 1, "blob": file}, auth=auth)["version"] == 2
    with pytest.raises(sync.SyncError, match="409"):  # based on version 1, but the server is at 2
        sync._request(cfg, "PUT", route, {"base_version": 1, "blob": file}, auth=auth)

    stored = sqlite3.connect(server["db"]).execute("SELECT auth_hash FROM accounts").fetchone()[0]
    assert auth not in stored and base64.b64encode(auth) not in stored


def test_urls_must_use_tls():
    assert sync.check_url("https://example.com/") == "https://example.com"
    assert sync.check_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    with pytest.raises(sync.SyncError):
        sync.check_url("http://example.com")


def test_hostile_kdf_from_server_is_refused(monkeypatch, tmp_path):
    a = tmp_path / "vault.json"
    vault.create(a, "pw")
    sync.save_config(a, {"url": "https://x", "account": "x", "version": 1, "salt": "", "base": {}})
    monkeypatch.setattr(sync, "_request", lambda *a, **k: {"kdf": {"salt": "AA==", "time_cost": 10**6,
                                                                     "memory_kib": 65536, "parallelism": 4}})
    with pytest.raises(Exception, match="out of range"):
        sync.run(a, "pw", never)


def test_push_race_retries_and_merges(server, tmp_path, monkeypatch):
    a, b = tmp_path / "a" / "vault.json", tmp_path / "b" / "vault.json"
    vault.create(a, "pw")
    account = sync.register(a, "pw", server["url"], TOKEN, server["cafile"])
    sync.link(b, "pw", server["url"], account, server["cafile"])
    change(a, lambda es: vault.add(es, title="FromA"))
    change(b, lambda es: vault.add(es, title="FromB"))

    real, raced = sync._request, []

    def racing(cfg, method, *args, **kwargs):
        if method == "PUT" and not raced:  # B sneaks a push in between A's pull and A's push
            raced.append(True)
            sync.run(b, "pw", never)
        return real(cfg, method, *args, **kwargs)

    monkeypatch.setattr(sync, "_request", racing)
    sync.run(a, "pw", never)  # first PUT gets 409, then A re-pulls, merges and pushes
    monkeypatch.setattr(sync, "_request", real)
    sync.run(b, "pw", never)
    assert raced and titles(a) == titles(b) == ["FromA", "FromB"]


def test_cli_sync_commands(server, tmp_path):
    from typer.testing import CliRunner
    from vaultlet.cli import app

    runner = CliRunner()
    run = lambda path, *a, input: runner.invoke(app, ["--vault", str(path), *a], input=input)
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert run(a, "init", input="pw\npw\n").exit_code == 0
    r = run(a, "sync", "register", server["url"], "--cafile", server["cafile"], input=f"pw\n{TOKEN}\n")
    assert r.exit_code == 0, r.output
    account = r.output.split("Account id: ")[1].split()[0]
    r = run(b, "sync", "link", server["url"], account, "--cafile", server["cafile"], input="pw\n")
    assert r.exit_code == 0 and "Downloaded 0 entries" in r.output, r.output
    assert "Already up to date." in run(b, "sync", input="pw\n").output
    r = run(b, "sync", input="wrong\n")
    assert r.exit_code == 1 and "Could not unlock" in r.output
    r = run(tmp_path / "c.json", "sync", "link", "http://example.com", "x", input="pw\n")
    assert r.exit_code == 1 and "https://" in r.output
