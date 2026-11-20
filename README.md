# Vaultlet
Password management system: a local-first, zero-knowledge password manager in Python.

## Threat model

| Threat | Defended? | How |
|---|---|---|
| Stolen vault file (offline guessing) | Yes | Argon2id makes each guess slow and memory-hungry |
| Vault file edited or corrupted | Yes | AEAD authentication tag fails on any change |
| Compromised or curious sync server | Yes | Stores the encrypted vault file and SHA-256 of an HKDF-derived auth key; never sees the password, KEK or vault key |
| Sync server reading the auth key in transit or memory | Partly | It's HKDF(KEK), so it can't be reversed to the KEK; it does let that server guess master passwords offline (Argon2id cost per guess), same as holding the vault file |
| Network attacker between client and server | Yes | TLS required (https only, except loopback); self-signed servers are pinned with `--cafile` |
| Online password guessing against the sync server | Yes | Each guess costs a client-side Argon2id run, and after 5 failures per account the server backs off exponentially to one try per 15 min. Someone who knows your account id can use this to delay your syncs by up to 15 min. `vaultlet-server` keeps the backoff in memory (resets on restart); the Cloudflare Worker stores it in D1 |
| Two devices editing at once | Yes | Server accepts a push only against the latest version (409 otherwise); the client merges three-way and keeps both copies of an entry edited on both sides |
| Sync metadata on disk | Partly | `<vault>.sync` holds the URL, account id, entry ids and keyed (HMAC) fingerprints: reveals the entry count, not contents |
| Shoulder-surfing, walk-up access | Partly | Passwords masked unless `--show`; `shell` clears the screen and locks when idle; copied passwords cleared after 20 s |
| Clipboard history / cloud clipboard (Windows Win+V) | No | Those keep their own copy; leave them off |
| Secrets in crash tracebacks | Yes | Typer `pretty_exceptions_show_locals` forced off |
| Leaked master password | Yes, going forward | `passwd` re-keys the vault and its `.bak`; old copies elsewhere (backups, sync, SSD remnants) still open with it |
| Stolen encrypted export | Yes | Same Argon2id + AES-GCM as the vault; only as strong as the export password |
| Browser CSV left on disk | No | It is plaintext; `import-csv` warns, but deleting it is up to you |
| Hostile vault/export file with huge KDF settings | Yes | KDF parameters are bounded at load |
| Weak master password | No | Strength check only; cannot be fixed in code |
| Breach check leaking passwords | Yes | HIBP k-anonymity: only a 5-char SHA-1 prefix is sent, with padded responses |
| Web page reaching the vault through the extension | Yes | No content scripts, no `externally_connectable`, no host permissions; the page only gets code injected when you click Fill |
| Other extensions or programs talking to the helper | Partly | Native messaging: no network port, and the browser only starts the helper for Vaultlet's extension id. Local malware could still run the helper itself, but it could also read the vault file |
| Phishing look-alike sites | Yes | Fill is only offered and only answered for entries whose saved host matches the page (same host or a subdomain), on https; the page host is checked again at fill time |
| Credentials leaking into iframes | Yes | Fill runs in the top frame only |
| Unlocked helper left running | Partly | Locks after `--idle` seconds unused (default 300) and when the browser closes |
| Malware or keylogger on your machine | No | Not done yet |
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
vaultlet add GitHub --totp          # also prompts for a TOTP secret or otpauth:// URI (edit --totp; empty clears)
vaultlet totp <id> --copy           # current 2FA code; clipboard clears when the code expires
vaultlet breach                     # check every password with Have I Been Pwned (or: breach <id>)
```

In the TUI: `/` search, `a` add, `e` edit, `d` delete, `c` copy password (clears after 20 s), `u` copy username, `t` copy TOTP code, `b` breach check, `y` sync, `s` show/hide password, `Ctrl+L` lock, `Ctrl+Q` quit. Ctrl+G in the entry form generates a password. The detail panel shows the live TOTP code.

**Breach check privacy:** it uses the HIBP [range API](https://haveibeenpwned.com/API/v3#PwnedPasswords). Only the first 5 hex characters of each password's SHA-1 are sent; the full hash and the password never leave your machine, and responses are padded so their size doesn't reveal anything. HIBP still sees your IP address and when you checked. `breach` exits with status 1 if any password is found.

**TOTP:** keeping the second factor in the same vault as the password means one unlocked vault gives both. That's convenient, but weaker than a separate authenticator app; choose per account. Use the CLI for `passwd`, `export`, the imports and `upgrade-kdf`.

The clipboard is only cleared if it still holds the copied password. On Linux, `--copy` needs `xclip`, `xsel` or `wl-clipboard`.

## Sync (optional)

The server stores each account's vault file exactly as the client encrypted it. To log in, a client fetches the KDF salt, runs Argon2id, and derives a separate auth key from the KEK with HKDF (`vaultlet sync auth v1`). The server keeps only SHA-256 of that key.

Run a server (needs `pip install "vaultlet[server]"`). A certificate is required:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825   -keyout key.pem -out cert.pem -subj "/CN=vaultlet" -addext "subjectAltName=DNS:myhost,IP:192.168.1.10"
VAULTLET_REGISTER_TOKEN=<long random string> vaultlet-server --host 0.0.0.0 --cert cert.pem --key key.pem
```

Registration only works while `VAULTLET_REGISTER_TOKEN` is set; restart the server without it once your devices are registered. `--insecure-http` is allowed only on a loopback address (e.g. behind a local TLS proxy).

```
vaultlet sync register https://myhost:8443 --cafile cert.pem         # upload this vault; prints the account id
vaultlet sync link https://myhost:8443 <account> --cafile cert.pem  # on another device
vaultlet sync                                                        # pull, merge, push
```

- **Conflicts:** pushes carry the version they were based on. If another device pushed first, the server answers 409 and the client pulls, merges and retries. The merge compares each entry with the last sync. One-sided edits, additions and deletions win. An entry edited on both sides is kept twice, the other copy marked `(conflict)`. An edit beats a delete.
- **Changing the master password:** run `passwd` on one device, then `sync`; it asks once for the old password to authenticate and uploads the new key. Other devices are asked for the new password on their next `sync` and switch to it.
- `link` downloads the account if this device has no vault. If it has one, its entries are merged in (asking for its password if it differs) and the device switches to the synced master password. Delete `<vault>.sync` to stop syncing.
- In the TUI, `y` syncs. It asks for the master password each time, because the TUI keeps the vault key, never the password, and edits wait until the sync finishes. Set up with `register` / `link` in the CLI first.
- Registration-token guesses are rate-limited the same way as logins.

### Hosting on Cloudflare (alternative server)

`worker/` is a Cloudflare Worker + D1 port of `vaultlet-server`: same routes, JSON and status codes, so the client works with it unchanged. Cloudflare provides the TLS certificate, so `--cafile` isn't needed.

```
cd worker
npm install
npx wrangler d1 create vaultlet-sync          # put the printed database_id in wrangler.jsonc
npm run schema:remote                         # create the tables
npx wrangler secret put VAULTLET_REGISTER_TOKEN
npm run deploy                                # prints https://vaultlet-sync.<you>.workers.dev
```

Then `vaultlet sync register https://vaultlet-sync.<you>.workers.dev`, and `link` on other devices as above. Once every device is registered, `npx wrangler secret delete VAULTLET_REGISTER_TOKEN` turns registration off. For local testing: `npm run schema:local`, put the token in `worker/.dev.vars`, and `npm run dev`.

## Browser extension

A Chromium extension (Chrome, Edge, Brave, Chromium) in `extension/`, talking to a local helper over [native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging). The browser starts the helper (`python -m vaultlet.native`) itself and talks to it over stdin/stdout, so there is no network port.

```
vaultlet native install --idle 300    # per-user: writes ~/.vaultlet/native and registers it (HKCU on Windows)
```

Then open `chrome://extensions`, enable Developer mode, **Load unpacked**, pick the `extension/` folder, and restart the browser. The extension id is pinned to `lpbnpdbfajmdfjjfmgbdngnaoghfppan` by the public key in its manifest, and the helper only accepts that id. `vaultlet native uninstall` removes the registration.

Click the icon (or Ctrl+Shift+L): unlock with the master password, then **Fill** a login for the current site, or copy the password, username or TOTP code. Copies happen in the helper and clear after 20 s. Search finds any entry for copying; fill is only offered for entries saved for the current site, on https pages. The helper reads the vault fresh for each request, so edits from the CLI, TUI or a sync show up straight away.

Not supported yet: Firefox (different background model and manifest keys), saving new logins from a page, filling inside iframes. A Chrome Web Store build would get a different id; update `EXTENSION_ID` in `native.py` to match.

## Development

```
python -m venv .venv
.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```
