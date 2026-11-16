# Vaultlet
Password management system: a local-first, zero-knowledge password manager in Python.

## Threat model

| Threat | Defended? | How |
|---|---|---|
| Stolen vault file (offline guessing) | Yes | Argon2id makes each guess slow and memory-hungry |
| Vault file edited or corrupted | Yes | AEAD authentication tag fails on any change |
| Compromised sync server (later) | Yes | Server stores ciphertext only |
| Shoulder-surfing, walk-up access | Partly | Passwords masked unless `--show`; `shell` clears the screen and locks when idle; copied passwords cleared after 20 s |
| Clipboard history / cloud clipboard (Windows Win+V) | No | Those keep their own copy; leave them off |
| Secrets in crash tracebacks | Yes | Typer `pretty_exceptions_show_locals` forced off |
| Weak master password | No | Strength check only; cannot be fixed in code |
| Malware or keylogger on your machine | No | Out of scope |
| Memory scraping while unlocked | Limited | Python cannot reliably wipe memory |

This is a learning and portfolio project. Keep real credentials in an audited manager until Vaultlet has had independent review.

## Crypto decisions

- **KDF:** Argon2id (`argon2-cffi`), 32-byte KEK, time_cost 3, memory 64 MiB, parallelism 4. Tune upward until unlock takes about 0.5–1 s.
- **Vault key:** random 32 bytes, wrapped with the KEK via AES-256-GCM. Changing the master password or KDF parameters keeps the vault key, re-wraps it under a fresh salt, and re-seals the entries (the header is in both AADs). Only one Argon2id run is needed.
- **Nonces:** fresh 96-bit `os.urandom` for every encryption.
- **AAD:** the header (version and KDF parameters) is authenticated into both ciphertexts, with `key` or `vault` as a purpose suffix.
- **Passwords:** Unicode NFKC-normalised before derivation.
- **Randomness:** `os.urandom` / `secrets` only, never `random`.

## Daily use

```
vaultlet init                       # create a vault (~/.vaultlet/vault.json, or --vault / VAULTLET_VAULT)
vaultlet add GitHub --username me -g --length 24 --no-symbols
vaultlet list                       # ids, titles, usernames; never passwords
vaultlet get <id>                   # password masked
vaultlet get <id> --copy            # copy password; clipboard clears after 20 s (Ctrl+C clears now)
vaultlet generate --length 30       # print a password; no vault needed
vaultlet passwd                     # change the master password (always asks for the current one)
vaultlet shell --idle 300           # unlock once; locks and clears the screen after 300 s idle
```

The clipboard is only cleared if it still holds the copied password. On Linux, `--copy` needs `xclip`, `xsel` or `wl-clipboard`.

## Development

```
python -m venv .venv
.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```
