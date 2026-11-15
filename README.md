# Vaultlet
Password management system: a local-first, zero-knowledge password manager in Python.

## Threat model

| Threat | Defended? | How |
|---|---|---|
| Stolen vault file (offline guessing) | Yes | Argon2id makes each guess slow and memory-hungry |
| Vault file edited or corrupted | Yes | AEAD authentication tag fails on any change |
| Compromised sync server (later) | Yes | Server stores ciphertext only |
| Shoulder-surfing, walk-up access | Partly | Masked fields, auto-lock, clipboard clearing |
| Weak master password | No | Strength check only; cannot be fixed in code |
| Malware or keylogger on your machine | No | Out of scope |
| Memory scraping while unlocked | Limited | Python cannot reliably wipe memory |

This is a learning and portfolio project. Keep real credentials in an audited manager until Vaultlet has had independent review.

## Crypto decisions

- **KDF:** Argon2id (`argon2-cffi`), 32-byte KEK, time_cost 3, memory 64 MiB, parallelism 4. Tune upward until unlock takes about 0.5–1 s.
- **Vault key:** random 32 bytes, wrapped with the KEK via AES-256-GCM. Changing the master password re-wraps only the vault key.
- **Nonces:** fresh 96-bit `os.urandom` for every encryption.
- **AAD:** the header (version and KDF parameters) is authenticated into both ciphertexts, with `key` or `vault` as a purpose suffix.
- **Passwords:** Unicode NFKC-normalised before derivation.
- **Randomness:** `os.urandom` / `secrets` only, never `random`.

## Development

```
python -m venv .venv
.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```
