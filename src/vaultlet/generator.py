import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


def generate(length: int = 20, symbols: bool = True) -> str:
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append(SYMBOLS)
    if length < len(pools):
        raise ValueError("length too short for the selected character sets")
    alphabet = "".join(pools)
    while True:  # rejection sampling: keep only passwords using every pool
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in pool for c in pw) for pool in pools):
            return pw
