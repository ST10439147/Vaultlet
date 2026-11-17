"""TOTP codes (RFC 6238) via pyotp. Entries store either a base32 secret or a full otpauth:// URI."""

import base64
import hashlib
import time
from urllib.parse import parse_qs, urlsplit

import pyotp


class _TOTP(pyotp.TOTP):
    """pyotp >= 2.10 refuses secrets under 112 bits, but many sites still issue 80-bit ones.

    The site picks the secret, not us, so accept whatever base32 it gave us.
    """

    def byte_secret(self) -> bytes:
        secret = self.secret + "=" * (-len(self.secret) % 8)
        decoded = base64.b32decode(secret, casefold=True)
        if not decoded:
            raise ValueError("empty TOTP secret")
        return decoded


DIGESTS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def _totp(secret: str) -> pyotp.TOTP:
    if not secret.lower().startswith("otpauth://"):
        return _TOTP(secret)
    # Parsed by hand: pyotp.parse_uri applies the same 112-bit floor.
    url = urlsplit(secret)
    if url.netloc.lower() != "totp":
        raise ValueError("only time-based (totp) otpauth URIs are supported")
    q = {k.lower(): v[0] for k, v in parse_qs(url.query).items()}
    return _TOTP(q["secret"].replace(" ", "").upper(), digits=int(q.get("digits", 6)),
                 digest=DIGESTS[q.get("algorithm", "SHA1").upper()], interval=int(q.get("period", 30)))


def normalize(secret: str) -> str:
    """Clean up a pasted secret or URI and check it works. Raises ValueError if it doesn't."""
    secret = secret.strip()
    if not secret.lower().startswith("otpauth://"):
        secret = secret.replace(" ", "").replace("-", "").upper()  # "abcd efgh" as shown by many sites
    try:
        _totp(secret).now()
    except Exception as exc:  # pyotp raises binascii.Error, ValueError or TypeError for junk
        raise ValueError("not a valid TOTP secret (base32) or otpauth:// URI") from exc
    return secret


def code(secret: str) -> tuple[str, int]:
    """Return (current code, seconds until it changes)."""
    otp = _totp(secret)
    return otp.now(), otp.interval - int(time.time()) % otp.interval
