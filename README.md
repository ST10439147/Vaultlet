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
| Leaked master password | Yes, going forward | `passwd` re-keys the vault and its `.bak`; old copies elsewhere (backups, sync, SSD remnants) still open with it |
| Stolen encrypted export | Yes | Same Argon2id + AES-GCM as the vault; only as strong as the export password |
| Browser CSV left on disk | No | It is plaintext; `import-csv` warns, but deleting it is up to you |
| Hostile vault/export file with huge KDF settings | Yes | KDF parameters are bounded at load |
| Weak master password | No | Strength check only; cannot be fixed in code |
| Malware or keylogger on your machine | No | Out of scope |
| Memory scraping while unlocked | Limited | Python cannot reliably wipe memory |

This is a learning and portfolio project. Keep real credentials in an audited manager until Vaultlet has had independent review.

## Crypto decisions

- **KDF:** Argon2id (`argon2-cffi`), 32-byte KEK, time_cost 3, memory 64 MiB, parallelism 4. Tune upward until unlock takes about 0.5–1 s. A vault below the defaults is re-keyed to them on its next unlock; KDF parameters above 50 passes, 4 GiB or 64 lanes are rejected as corrupt so a hostile file can't stall the machine.
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
vaultlet upgrade-kdf --time-cost 4  # stronger Argon2id (never below the defaults)
vaultlet export backup.json         # separate vault file with its own export password
vaultlet import-vault backup.json   # merge an export back in (skips ids already present)
vaultlet import-csv passwords.csv   # Chrome / Edge / Firefox export; delete the CSV afterwards
vaultlet shell --idle 300           # unlock once; locks and clears the screen after 300 s idle
vaultlet tui --idle 300             # full-screen UI; creates the vault if missing; locks when idle
```

In the TUI: `/` search, `a` add, `e` edit, `d` delete, `c` copy password (clears after 20 s), `u` copy username, `s` show/hide password, `Ctrl+L` lock, `Ctrl+Q` quit. Ctrl+G in the entry form generates a password. Use the CLI for `passwd`, `export`, the imports and `upgrade-kdf`.

The clipboard is only cleared if it still holds the copied password. On Linux, `--copy` needs `xclip`, `xsel` or `wl-clipboard`.

## Development

```
python -m venv .venv
.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```
