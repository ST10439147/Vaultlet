"""Command-line interface. Talks to vault.py; never touches crypto directly.

Secrets (master and entry passwords) are only ever read from a hidden prompt,
never from arguments or environment variables.
"""

import csv
import os
import secrets
import shlex
import threading
import time
from pathlib import Path
from typing import Annotated, NoReturn, Optional

import pyperclip
import typer

from vaultlet import breach, totp, vault
from vaultlet.errors import CorruptVault, WrongPassword
from vaultlet.generator import generate

DEFAULT_VAULT = Path.home() / ".vaultlet" / "vault.json"
UNLOCK_FAILED = "Could not unlock the vault: wrong password or damaged file."
MASK = "********"
CLEAR_AFTER = 20  # seconds a copied password stays on the clipboard
IDLE_LOCK = 300  # seconds without input before `shell` locks

_session_key: bytes | None = None  # set only while `vaultlet shell` is unlocked

# show_locals stays off explicitly: a crash traceback must never dump the vault key or entries.
app = typer.Typer(help="Vaultlet: a local, encrypted password manager.", no_args_is_help=True,
                  pretty_exceptions_show_locals=False)

Length = Annotated[int, typer.Option("--length", min=4, help="Length for --generate.")]
Generate = Annotated[bool, typer.Option("--generate", "-g", help="Generate a strong password.")]
Symbols = Annotated[bool, typer.Option("--symbols/--no-symbols", help="Include symbols when generating.")]
Totp = Annotated[bool, typer.Option("--totp", help="Prompt for a TOTP secret or otpauth:// URI (empty clears it).")]


def fail(message: str) -> NoReturn:
    typer.echo(message, err=True)
    raise typer.Exit(1)


def ask_master(confirm: bool = False) -> str:
    return typer.prompt("Master password", hide_input=True, confirmation_prompt=confirm)


def ask_entry_password(gen: bool, length: int, symbols: bool) -> str:
    if gen:
        return generate(length, symbols)
    return typer.prompt("Entry password", hide_input=True, confirmation_prompt=True)


def ask_totp() -> str:
    secret = typer.prompt("TOTP secret or otpauth:// URI", hide_input=True, default="", show_default=False)
    if not secret.strip():
        return ""
    try:
        return totp.normalize(secret)
    except ValueError as exc:
        fail(str(exc))


def unlock(path: Path, always_prompt: bool = False,
           kdf: dict | None = None) -> tuple[dict, bytes, list[dict]]:
    if not path.exists():
        fail(f"No vault at {path}. Run 'vaultlet init' first.")
    try:
        if _session_key is not None and not always_prompt:  # unlocked shell: no prompt, re-read the file
            file = vault.load(path)
            return file, _session_key, vault.read_entries(file, _session_key)
        return vault.open_vault(path, ask_master(), kdf)
    except (WrongPassword, CorruptVault):
        fail(UNLOCK_FAILED)  # one message for both, so failures reveal nothing


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def copy_then_clear(value: str, seconds: int = CLEAR_AFTER, what: str = "Password") -> None:
    """Copy VALUE, wait, then clear the clipboard only if it still holds VALUE."""
    # ponytail: blocks the terminal for the wait; move to a detached clearer process if that gets annoying
    try:
        pyperclip.copy(value)
    except pyperclip.PyperclipException:
        fail("No clipboard available (on Linux, install xclip, xsel or wl-clipboard).")
    typer.echo(f"{what} copied. Clipboard clears in {seconds}s (Ctrl+C to clear now).")
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass
    finally:
        # Don't wipe something the user copied in the meantime.
        unchanged = secrets.compare_digest(pyperclip.paste().encode(), value.encode())
        if unchanged:
            pyperclip.copy("")
    typer.echo("Clipboard cleared." if unchanged else "Clipboard changed since copy; left alone.")


def resolve(entries: list[dict], ref: str) -> dict:
    """Find an entry by its id or a unique prefix of it (list shows the first 8 chars)."""
    matches = [e for e in entries if ref and e["id"].startswith(ref)]
    if len(matches) == 1:
        return matches[0]
    fail("No entry matches that id." if not matches else "That id matches several entries; type more of it.")


def split_line(line: str) -> list[str]:
    """Split a shell line on whitespace with quote support, but keep backslashes (Windows paths)."""
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.escape = ""
    return list(lexer)


def print_rows(entries: list[dict], empty: str) -> None:
    if not entries:
        typer.echo(empty)
    for e in entries:
        typer.echo(f"{e['id'][:8]}  {e['title']}  {e['username']}")


@app.callback()
def main(
    ctx: typer.Context,
    vault_path: Annotated[
        Path, typer.Option("--vault", envvar="VAULTLET_VAULT", help="Path to the vault file.")
    ] = DEFAULT_VAULT,
) -> None:
    ctx.obj = vault_path


@app.command("generate")
def generate_cmd(length: Length = 20, symbols: Symbols = True) -> None:
    """Print a strong random password. No vault needed; nothing is saved."""
    typer.echo(generate(length, symbols))


@app.command()
def init(ctx: typer.Context) -> None:
    """Create a new, empty vault."""
    path: Path = ctx.obj
    if path.exists():
        fail(f"A vault already exists at {path}.")
    vault.create(path, ask_master(confirm=True))
    typer.echo(f"Created vault at {path}")


@app.command()
def add(
    ctx: typer.Context,
    title: str,
    username: Annotated[str, typer.Option()] = "",
    url: Annotated[str, typer.Option()] = "",
    notes: Annotated[str, typer.Option()] = "",
    gen: Generate = False,
    length: Length = 20,
    symbols: Symbols = True,
    with_totp: Totp = False,
) -> None:
    """Add an entry. The password is prompted for, or generated with --generate."""
    path: Path = ctx.obj
    file, key, entries = unlock(path)
    entry = vault.add(entries, title=title, username=username,
                      password=ask_entry_password(gen, length, symbols), url=url, notes=notes,
                      totp=ask_totp() if with_totp else "")
    vault.persist(path, file, key, entries)
    typer.echo(f"Added {entry['title']} ({entry['id'][:8]})")


@app.command()
def get(
    ctx: typer.Context,
    entry_id: str,
    show: Annotated[bool, typer.Option("--show", help="Print the password instead of masking it.")] = False,
    copy: Annotated[bool, typer.Option("--copy", "-c", help=f"Copy the password; clears after {CLEAR_AFTER}s.")] = False,
) -> None:
    """Show one entry. The password is masked unless --show is given."""
    _, _, entries = unlock(ctx.obj)
    e = resolve(entries, entry_id)
    typer.echo(f"id:       {e['id']}")
    typer.echo(f"title:    {e['title']}")
    typer.echo(f"username: {e['username']}")
    typer.echo(f"password: {e['password'] if show else MASK}")
    typer.echo(f"url:      {e['url']}")
    typer.echo(f"notes:    {e['notes']}")
    if e["totp"]:
        now, left = totp.code(e["totp"])
        typer.echo(f"totp:     {now} ({left}s left)")
    if copy:
        copy_then_clear(e["password"])


@app.command("list")
def list_cmd(ctx: typer.Context) -> None:
    """List all entries, sorted by title."""
    _, _, entries = unlock(ctx.obj)
    print_rows(vault.list_entries(entries), "Vault is empty.")


@app.command()
def search(ctx: typer.Context, query: str) -> None:
    """Find entries whose title or username contains QUERY."""
    _, _, entries = unlock(ctx.obj)
    print_rows(vault.list_entries(vault.search(entries, query)), "No matches.")


@app.command()
def edit(
    ctx: typer.Context,
    entry_id: str,
    title: Annotated[Optional[str], typer.Option()] = None,
    username: Annotated[Optional[str], typer.Option()] = None,
    url: Annotated[Optional[str], typer.Option()] = None,
    notes: Annotated[Optional[str], typer.Option()] = None,
    password: Annotated[bool, typer.Option("--password", help="Prompt for a new password.")] = False,
    gen: Generate = False,
    length: Length = 20,
    symbols: Symbols = True,
    with_totp: Totp = False,
) -> None:
    """Change fields of an entry."""
    fields = {"title": title, "username": username, "url": url, "notes": notes}
    changes = {k: v for k, v in fields.items() if v is not None}
    if not (changes or password or gen or with_totp):
        fail("Nothing to change. Pass --title, --username, --url, --notes, --password, --generate or --totp.")
    path: Path = ctx.obj
    file, key, entries = unlock(path)
    entry = resolve(entries, entry_id)
    if password or gen:
        changes["password"] = ask_entry_password(gen, length, symbols)
    if with_totp:
        changes["totp"] = ask_totp()
    vault.edit(entries, entry["id"], **changes)
    vault.persist(path, file, key, entries)
    typer.echo(f"Updated {entry['title']}")


@app.command()
def delete(
    ctx: typer.Context,
    entry_id: str,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt.")] = False,
) -> None:
    """Delete an entry."""
    path: Path = ctx.obj
    file, key, entries = unlock(path)
    entry = resolve(entries, entry_id)
    if not yes:
        typer.confirm(f"Delete {entry['title']}?", abort=True)
    vault.delete(entries, entry["id"])
    vault.persist(path, file, key, entries)
    typer.echo(f"Deleted {entry['title']}")


@app.command()
def passwd(ctx: typer.Context) -> None:
    """Change the master password. Entries and the vault key stay the same."""
    path: Path = ctx.obj
    # Always ask for the current password, even in an unlocked shell, so walk-up access can't change it.
    file, key, entries = unlock(path, always_prompt=True)
    new = typer.prompt("New master password", hide_input=True, confirmation_prompt=True)
    vault.rekey(path, file, key, entries, new)
    typer.echo("Master password changed.")


@app.command()
def export(ctx: typer.Context, out: Path) -> None:
    """Write all entries to OUT as a separate vault locked with its own export password."""
    if out.exists():
        fail(f"{out} already exists; pick a new file name.")
    # Always ask for the master password, so walk-up access to a shell can't copy the vault out.
    _, _, entries = unlock(ctx.obj, always_prompt=True)
    password = typer.prompt("Export password", hide_input=True, confirmation_prompt=True)
    vault.create(out, password, entries)
    typer.echo(f"Exported {len(entries)} entries to {out}. It opens with the export password, "
               f"e.g. 'vaultlet --vault {out} list'.")


@app.command("import-vault")
def import_vault(ctx: typer.Context, source: Path) -> None:
    """Add entries from an exported vault file. Entries whose id already exists are skipped."""
    if not source.exists():
        fail(f"No file at {source}.")
    path: Path = ctx.obj
    file, key, entries = unlock(path)
    try:
        src = vault.load(source)
        incoming = vault.read_entries(src, vault.unlock(src, typer.prompt("Export password", hide_input=True)))
        added = vault.merge(entries, incoming)
    except (WrongPassword, CorruptVault):
        fail("Could not open the export: wrong password or damaged file.")
    vault.persist(path, file, key, entries)
    typer.echo(f"Imported {added} entries; skipped {len(incoming) - added} already present.")


@app.command("import-csv")
def import_csv(ctx: typer.Context, source: Path) -> None:
    """Add entries from a Chrome, Edge or Firefox password export (CSV)."""
    if not source.exists():
        fail(f"No file at {source}.")
    path: Path = ctx.obj
    file, key, entries = unlock(path)
    try:
        # utf-8-sig drops the BOM some browsers write; newline="" lets csv handle quoted line breaks
        with source.open(encoding="utf-8-sig", newline="") as handle:
            added, skipped = vault.import_csv(entries, handle.read())
    except (ValueError, csv.Error) as exc:  # UnicodeDecodeError is a ValueError
        fail(f"Could not import {source}: {exc}")
    vault.persist(path, file, key, entries)
    typer.echo(f"Imported {added} entries; skipped {skipped} duplicates.")
    typer.echo(f"WARNING: {source} holds every password in plain text. Delete it now, "
               "and empty the Recycle Bin/Trash.", err=True)


def kdf_option(name: str, flag: str, help: str):
    """An Argon2id option that can't go below the defaults (open_vault would raise it back anyway)."""
    return Annotated[int, typer.Option(flag, min=vault.crypto.KDF_DEFAULTS[name],
                                       max=vault.KDF_LIMITS[name][1], help=help)]


@app.command("upgrade-kdf")
def upgrade_kdf(
    ctx: typer.Context,
    time_cost: kdf_option("time_cost", "--time-cost", "Argon2id passes.") = vault.crypto.KDF_DEFAULTS["time_cost"],
    memory_kib: kdf_option("memory_kib", "--memory-kib", "Argon2id memory in KiB.") = vault.crypto.KDF_DEFAULTS["memory_kib"],
    parallelism: kdf_option("parallelism", "--parallelism", "Argon2id lanes.") = vault.crypto.KDF_DEFAULTS["parallelism"],
) -> None:
    """Re-key the vault with stronger Argon2id settings. Aim for an unlock of about 0.5-1 s."""
    kdf = {"time_cost": time_cost, "memory_kib": memory_kib, "parallelism": parallelism}
    unlock(ctx.obj, always_prompt=True, kdf=kdf)  # also needed in a shell: re-keying needs the password
    typer.echo(f"KDF set to time_cost={time_cost}, memory_kib={memory_kib}, parallelism={parallelism}.")


@app.command("totp")
def totp_cmd(
    ctx: typer.Context,
    entry_id: str,
    copy: Annotated[bool, typer.Option("--copy", "-c", help=f"Copy the code; clears after {CLEAR_AFTER}s.")] = False,
) -> None:
    """Print the current TOTP code for an entry."""
    e = resolve(unlock(ctx.obj)[2], entry_id)
    if not e["totp"]:
        fail(f"{e['title']} has no TOTP secret. Add one with 'vaultlet edit <id> --totp'.")
    now, left = totp.code(e["totp"])
    typer.echo(f"{now}  ({left}s left)")
    if copy:
        copy_then_clear(now, min(CLEAR_AFTER, left), what="Code")


@app.command("breach")
def breach_cmd(ctx: typer.Context, entry_id: Annotated[Optional[str], typer.Argument()] = None) -> None:
    """Check passwords against Have I Been Pwned. Only a 5-character SHA-1 prefix is sent."""
    entries = unlock(ctx.obj)[2]
    targets = [resolve(entries, entry_id)] if entry_id else vault.list_entries(entries)
    try:
        counts = breach.check([e["password"] for e in targets])
    except OSError as exc:  # URLError, timeouts and HTTP errors are all OSError
        fail(f"Could not reach Have I Been Pwned: {exc}")
    hits = [e for e in targets if counts.get(e["password"])]
    for e in hits:
        typer.echo(f"{e['id'][:8]}  {e['title']}  seen {counts[e['password']]:,} times in breaches")
    typer.echo(f"{len(hits)} of {len(targets)} passwords found in breaches." if hits
               else f"None of {len(targets)} passwords found in known breaches.")
    if hits:
        raise typer.Exit(1)


@app.command()
def tui(
    ctx: typer.Context,
    idle: Annotated[int, typer.Option("--idle", min=10, help="Lock after this many seconds without input.")] = IDLE_LOCK,
) -> None:
    """Full-screen terminal UI: browse, search, add, edit, delete and copy entries."""
    from vaultlet.tui import run  # lazy: keeps Textual's import cost off every other command

    run(ctx.obj, idle)


@app.command()
def shell(
    ctx: typer.Context,
    idle: Annotated[int, typer.Option("--idle", min=10, help="Lock after this many seconds without input.")] = IDLE_LOCK,
) -> None:
    """Unlock once, then run commands interactively. Locks itself after --idle seconds without input."""
    global _session_key
    path: Path = ctx.obj
    command = typer.main.get_command(app)

    def lock() -> None:
        global _session_key
        # ponytail: drops the reference only; Python can't reliably wipe the key bytes (see README threat model)
        _session_key = None
        clear_screen()
        typer.echo(f"Locked after {idle}s idle. Enter a command to unlock.")

    _session_key = unlock(path)[1]
    typer.echo("Unlocked. Type a command (e.g. list, get <id> --copy) or 'exit'.")
    try:
        while True:
            timer = threading.Timer(idle, lock)  # only runs while waiting at the prompt
            timer.daemon = True
            timer.start()
            try:
                line = input("vaultlet> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            finally:
                timer.cancel()
            if line in ("exit", "quit"):
                break
            if not line:
                continue
            if _session_key is None:
                try:
                    _session_key = unlock(path)[1]
                except typer.Exit:
                    continue  # unlock() already printed why
            try:
                args = split_line(line)
            except ValueError as exc:
                typer.echo(f"Error: {exc}", err=True)
                continue
            if args[0] in ("shell", "init"):
                typer.echo(f"'{args[0]}' isn't available inside the shell.", err=True)
                continue
            try:
                command.main(["--vault", str(path), *args], prog_name="vaultlet", standalone_mode=False)
            except typer.Abort:
                typer.echo("Aborted.")
            except typer.TyperException as exc:
                typer.echo(f"Error: {exc}", err=True)
    except typer.Abort:  # Ctrl+C at the unlock prompt
        pass
    finally:
        _session_key = None
    typer.echo("Locked. Bye.")
