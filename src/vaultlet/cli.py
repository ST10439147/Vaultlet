"""Command-line interface. Talks to vault.py; never touches crypto directly.

Secrets (master and entry passwords) are only ever read from a hidden prompt,
never from arguments or environment variables.
"""

from pathlib import Path
from typing import Annotated, NoReturn, Optional

import typer

from vaultlet import vault
from vaultlet.errors import CorruptVault, WrongPassword
from vaultlet.generator import generate

DEFAULT_VAULT = Path.home() / ".vaultlet" / "vault.json"
UNLOCK_FAILED = "Could not unlock the vault: wrong password or damaged file."
MASK = "********"

app = typer.Typer(help="Vaultlet: a local, encrypted password manager.", no_args_is_help=True)

Length = Annotated[int, typer.Option("--length", min=4, help="Length for --generate.")]
Generate = Annotated[bool, typer.Option("--generate", "-g", help="Generate a strong password.")]


def fail(message: str) -> NoReturn:
    typer.echo(message, err=True)
    raise typer.Exit(1)


def ask_master(confirm: bool = False) -> str:
    return typer.prompt("Master password", hide_input=True, confirmation_prompt=confirm)


def ask_entry_password(gen: bool, length: int) -> str:
    if gen:
        return generate(length)
    return typer.prompt("Entry password", hide_input=True, confirmation_prompt=True)


def unlock(path: Path) -> tuple[dict, bytes, list[dict]]:
    if not path.exists():
        fail(f"No vault at {path}. Run 'vaultlet init' first.")
    try:
        return vault.open_vault(path, ask_master())
    except (WrongPassword, CorruptVault):
        fail(UNLOCK_FAILED)  # one message for both, so failures reveal nothing


def resolve(entries: list[dict], ref: str) -> dict:
    """Find an entry by its id or a unique prefix of it (list shows the first 8 chars)."""
    matches = [e for e in entries if ref and e["id"].startswith(ref)]
    if len(matches) == 1:
        return matches[0]
    fail("No entry matches that id." if not matches else "That id matches several entries; type more of it.")


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
) -> None:
    """Add an entry. The password is prompted for, or generated with --generate."""
    path: Path = ctx.obj
    file, key, entries = unlock(path)
    entry = vault.add(entries, title=title, username=username,
                      password=ask_entry_password(gen, length), url=url, notes=notes)
    vault.persist(path, file, key, entries)
    typer.echo(f"Added {entry['title']} ({entry['id'][:8]})")


@app.command()
def get(
    ctx: typer.Context,
    entry_id: str,
    show: Annotated[bool, typer.Option("--show", help="Print the password instead of masking it.")] = False,
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
) -> None:
    """Change fields of an entry."""
    fields = {"title": title, "username": username, "url": url, "notes": notes}
    changes = {k: v for k, v in fields.items() if v is not None}
    if not (changes or password or gen):
        fail("Nothing to change. Pass --title, --username, --url, --notes, --password or --generate.")
    path: Path = ctx.obj
    file, key, entries = unlock(path)
    entry = resolve(entries, entry_id)
    if password or gen:
        changes["password"] = ask_entry_password(gen, length)
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
