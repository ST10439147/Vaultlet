"""Have I Been Pwned password check using k-anonymity.

Only the first 5 hex characters of the password's SHA-1 leave the machine. The API answers with
every hash suffix in that range (padded with fake rows), and the match happens locally.
"""

import hashlib
import urllib.request

API = "https://api.pwnedpasswords.com/range/"


def pwned_count(password: str, timeout: float = 10) -> int:
    """How many times PASSWORD appears in known breaches (0 = not found). Network errors raise OSError."""
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(API + prefix, headers={
        "User-Agent": "vaultlet",
        "Add-Padding": "true",  # hides the real response size from anyone watching the traffic
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("ascii")
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate == suffix:
            return int(count)  # padding rows have count 0, which is also right
    return 0


def check(passwords: list[str]) -> dict[str, int]:
    """Count breaches for each distinct password; one request per distinct password."""
    return {pw: pwned_count(pw) for pw in set(passwords) if pw}
