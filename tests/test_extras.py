import base64
import hashlib
import hmac
import io
import struct
import time

import pytest
from typer.testing import CliRunner

from vaultlet import breach, totp
from vaultlet.cli import app

SECRET = "JBSWY3DPEHPK3PXP"  # 80 bits: short, but still issued by real sites


def rfc6238(secret, step=30, digits=6):
    """Independent reference implementation for the current time step."""
    mac = hmac.new(base64.b32decode(secret), struct.pack(">Q", int(time.time()) // step), hashlib.sha1).digest()
    offset = mac[-1] & 15
    return str((struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**digits).zfill(digits)


def test_totp_normalize_and_code():
    assert totp.normalize(" jbsw y3dp-ehpk 3pxp ") == SECRET
    assert totp.code(SECRET)[0] == rfc6238(SECRET)
    uri = "otpauth://totp/Ex:me?secret=JBSWY3DPEHPK3PXP&digits=8&period=60"
    assert totp.code(totp.normalize(uri))[0] == rfc6238(SECRET, step=60, digits=8)
    for bad in ("not base32!", "otpauth://hotp/Ex:me?secret=JBSWY3DPEHPK3PXP&counter=1"):
        with pytest.raises(ValueError):
            totp.normalize(bad)


def test_breach_sends_only_prefix(monkeypatch):
    digest = hashlib.sha1(b"password").hexdigest().upper()
    seen = []

    def fake_urlopen(request, timeout):
        seen.append(request)
        return io.BytesIO(f"0000000000000000000000000000000000A:0\r\n{digest[5:]}:42\r\n".encode())

    monkeypatch.setattr(breach.urllib.request, "urlopen", fake_urlopen)
    assert breach.pwned_count("password") == 42
    assert seen[0].full_url == breach.API + digest[:5]
    assert digest[5:] not in seen[0].full_url and seen[0].get_header("Add-padding") == "true"
    assert breach.pwned_count("something else") == 0


def test_cli_totp_and_breach(tmp_path, monkeypatch):
    runner, path = CliRunner(), tmp_path / "v.json"
    run = lambda *a, input="pw\n": runner.invoke(app, ["--vault", str(path), *a], input=input)
    run("init", input="pw\npw\n")
    r = run("add", "Mail", "--totp", input=f"pw\nhunter2\nhunter2\n{SECRET.lower()}\n")
    assert r.exit_code == 0, r.output
    short = run("list").output.strip().splitlines()[-1].split()[0]
    assert "totp:" in run("get", short).output
    assert run("totp", short).output.strip().splitlines()[-1].split()[0] == rfc6238(SECRET)

    monkeypatch.setattr(breach, "pwned_count", lambda pw: 7 if pw == "hunter2" else 0)
    r = run("breach")
    assert r.exit_code == 1 and "Mail" in r.output and "1 of 1" in r.output

    r = run("edit", short, "--totp", input="pw\n\n")  # empty answer clears it
    assert r.exit_code == 0 and "totp:" not in run("get", short).output
