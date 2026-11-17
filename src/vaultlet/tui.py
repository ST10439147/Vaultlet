"""Textual terminal UI. Like cli.py, it talks to vault.py and never touches crypto directly."""

import secrets
import time
from concurrent.futures import Future
from pathlib import Path

import pyperclip
from rich.markup import escape
from rich.text import Text
from textual import events, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Input, Label, Static

from vaultlet import breach, sync, totp, vault
from vaultlet.errors import CorruptVault, WrongPassword
from vaultlet.generator import generate

UNLOCK_FAILED = "Could not unlock the vault: wrong password or damaged file."
MASK = "********"
CLEAR_AFTER = 20
IDLE_LOCK = 300

CSS = """
UnlockScreen { align: center middle; }
#unlock { width: 60; height: auto; border: round $accent; padding: 1 2; }
#unlock Input { margin-top: 1; }
#error { color: $error; margin-top: 1; }
#detail { height: auto; border: round $accent; padding: 0 1; }
EntryForm, ConfirmDelete, PasswordPrompt { align: center middle; }
#form, #confirm, #prompt { width: 70; height: auto; border: round $accent; padding: 1 2; background: $surface; }
#form Horizontal, #confirm Horizontal { height: auto; margin-top: 1; }
#form Button, #confirm Button { margin-right: 1; }
"""


class UnlockScreen(Screen):
    """Asks for the master password; creates the vault if there isn't one yet."""

    def compose(self) -> ComposeResult:
        creating = not self.app.path.exists()
        with Vertical(id="unlock"):
            yield Label(f"{'Create' if creating else 'Unlock'} vault at {self.app.path}")
            yield Input(placeholder="Master password", password=True, id="pw")
            if creating:
                yield Input(placeholder="Repeat master password", password=True, id="pw2")
            yield Label("", id="error")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        pw = self.query_one("#pw", Input).value
        if not pw:
            return
        if self.app.path.exists():
            self.query_one("#error", Label).update("Unlocking...")
            self.unlock(pw)
        elif event.input.id == "pw":
            self.query_one("#pw2", Input).focus()
        elif pw != event.value:
            self.query_one("#error", Label).update("Passwords don't match.")
        else:
            vault.create(self.app.path, pw)
            self.unlock(pw)

    @work(thread=True, exclusive=True)  # Argon2id takes ~0.5 s; keep the UI responsive
    def unlock(self, pw: str) -> None:
        try:
            opened = vault.open_vault(self.app.path, pw)
        except (WrongPassword, CorruptVault):
            self.app.call_from_thread(self.failed)
        else:
            self.app.call_from_thread(self.app.unlocked, *opened)

    def failed(self) -> None:
        self.query_one("#error", Label).update(UNLOCK_FAILED)
        self.query_one("#pw", Input).value = ""


class EntryForm(ModalScreen[dict | None]):
    FIELDS = ("title", "username", "password", "url", "notes", "totp")
    PLACEHOLDERS = {"totp": "TOTP secret or otpauth:// URI (optional)"}
    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel"), Binding("ctrl+g", "generate", "Generate")]

    def __init__(self, entry: dict | None = None) -> None:
        super().__init__()
        self.entry = entry or {}

    def compose(self) -> ComposeResult:
        with Vertical(id="form"):
            yield Label("Edit entry" if self.entry else "New entry")
            for name in self.FIELDS:
                yield Input(self.entry.get(name, ""), placeholder=self.PLACEHOLDERS.get(name, name.capitalize()),
                            password=name in ("password", "totp"), id=name)
            with Horizontal():
                yield Button("Save", variant="primary", id="save")
                yield Button("Generate (ctrl+g)", id="gen")
                yield Button("Show", id="show")
                yield Button("Cancel", id="cancel")
            yield Label("", id="error")

    def action_generate(self) -> None:
        self.query_one("#password", Input).value = generate()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        match event.button.id:
            case "gen":
                self.action_generate()
            case "show":
                pw = self.query_one("#password", Input)
                pw.password = not pw.password
                event.button.label = "Hide" if not pw.password else "Show"
            case "cancel":
                self.dismiss(None)
            case "save":
                self.save()

    def on_input_submitted(self) -> None:
        self.save()

    def save(self) -> None:
        values = {name: self.query_one(f"#{name}", Input).value for name in self.FIELDS}
        if not values["title"].strip():
            self.query_one("#error", Label).update("Title is required.")
            return
        if values["totp"].strip():
            try:
                values["totp"] = totp.normalize(values["totp"])
            except ValueError as exc:
                self.query_one("#error", Label).update(str(exc))
                return
        else:
            values["totp"] = ""
        self.dismiss(values)


class PasswordPrompt(ModalScreen[str | None]):
    """Hidden password prompt. With a Future, a worker thread can wait on it; closing it any way
    (including an idle lock popping it) answers None, so the waiting thread never hangs."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel")]

    def __init__(self, question: str, answer: Future | None = None) -> None:
        super().__init__()
        self.question, self.answer, self.value = question, answer, None

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt"):
            yield Label(self.question)
            yield Input(password=True)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.value = event.value or None
        self.dismiss(self.value)

    def on_unmount(self) -> None:
        if self.answer is not None and not self.answer.done():
            self.answer.set_result(self.value)


class ConfirmDelete(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel"), Binding("y", "dismiss(True)", "Yes")]

    def __init__(self, title: str) -> None:
        super().__init__()
        self.entry_title = title

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm"):
            yield Label(f"Delete {self.entry_title}?")
            with Horizontal():
                yield Button("Delete (y)", variant="error", id="yes")
                yield Button("Cancel", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class MainScreen(Screen):
    BINDINGS = [
        Binding("a", "add", "Add"),
        Binding("e", "edit", "Edit"),
        Binding("d", "delete", "Delete"),
        Binding("c", "copy('password')", "Copy password"),
        Binding("u", "copy('username')", "Copy user"),
        Binding("t", "copy_totp", "Copy TOTP"),
        Binding("b", "breach_check", "Breach check"),
        Binding("y", "sync", "Sync"),
        Binding("s", "toggle_show", "Show/hide"),
        Binding("slash", "focus_search", "Search"),
        Binding("ctrl+l", "app.lock", "Lock"),
        Binding("ctrl+q", "app.quit", "Quit"),
    ]

    show = False

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Search title or username  (/)", id="search")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Static(id="detail")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one(DataTable).add_columns("Title", "Username", "URL")
        self.refresh_table()
        self.query_one(DataTable).focus()
        self.set_interval(1, self.tick)

    def tick(self) -> None:
        if (e := self.selected()) and e["totp"]:  # keep the code and countdown live
            self.show_detail()

    def refresh_table(self, select: str | None = None) -> None:
        query = self.query_one("#search", Input).value
        entries = self.app.entries
        rows = vault.list_entries(vault.search(entries, query) if query else entries)
        table = self.query_one(DataTable)
        table.clear()
        for e in rows:
            table.add_row(*(Text(e[k]) for k in ("title", "username", "url")), key=e["id"])  # Text: no markup parsing
        if select and select in [e["id"] for e in rows]:
            table.move_cursor(row=table.get_row_index(select))
        self.show_detail()

    def selected(self) -> dict | None:
        table = self.query_one(DataTable)
        if not table.row_count:
            return None
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        return vault.get(self.app.entries, key)

    def show_detail(self) -> None:
        e = self.selected()
        detail = self.query_one("#detail", Static)
        if e is None:
            detail.update("Vault is empty. Press 'a' to add an entry." if not self.app.entries else "No matches.")
            return
        pw = e["password"] if self.show else MASK
        detail.update("\n".join(f"[b]{k:<9}[/b] {escape(v)}" for k, v in [
            ("title", e["title"]), ("username", e["username"]), ("password", pw),
            ("url", e["url"]), ("notes", e["notes"]), ("totp", self.totp_text(e)), ("id", e["id"][:8])]))

    @staticmethod
    def totp_text(e: dict) -> str:
        if not e["totp"]:
            return ""
        now, left = totp.code(e["totp"])
        return f"{now[:3]} {now[3:]}  ({left}s)"

    def on_input_changed(self, event: Input.Changed) -> None:
        self.refresh_table()

    def on_input_submitted(self) -> None:
        self.query_one(DataTable).focus()

    def on_data_table_row_highlighted(self) -> None:
        self.show = False  # never carry a revealed password over to the next row
        self.show_detail()

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_toggle_show(self) -> None:
        self.show = not self.show
        self.show_detail()

    def action_copy(self, field: str) -> None:
        if e := self.selected():
            self.app.copy(e[field], secret=field == "password")

    def action_copy_totp(self) -> None:
        if (e := self.selected()) and e["totp"]:
            now, left = totp.code(e["totp"])
            self.app.copy(now, secret=True, what="Code", seconds=min(CLEAR_AFTER, left))

    def action_breach_check(self) -> None:
        self.notify("Checking passwords with Have I Been Pwned (only 5-character hash prefixes are sent)...")
        self.check_breaches([(e["title"], e["password"]) for e in self.app.entries])

    @work(thread=True, exclusive=True, group="breach")
    def check_breaches(self, pairs: list[tuple[str, str]]) -> None:
        try:
            counts = breach.check([pw for _, pw in pairs])
        except OSError as exc:
            self.app.call_from_thread(self.notify, f"Could not reach Have I Been Pwned: {exc}", severity="error")
            return
        hits = sorted({title for title, pw in pairs if counts.get(pw)})
        if self.app.key is None:  # locked while checking: don't put titles on the lock screen
            return
        message = (f"{len(hits)} of {len(pairs)} passwords found in breaches: {', '.join(hits)}" if hits
                   else f"None of {len(pairs)} passwords found in known breaches.")
        self.app.call_from_thread(self.notify, message, severity="warning" if hits else "information",
                                  timeout=15 if hits else 5)

    def busy(self) -> bool:
        if self.app.syncing:  # an edit now would be overwritten by the sync result
            self.notify("Wait for the sync to finish.", severity="warning")
        return self.app.syncing

    def action_sync(self) -> None:
        if not sync.config_path(self.app.path).exists():
            self.notify("This vault isn't set up for sync. Run 'vaultlet sync register' or "
                        "'vaultlet sync link' first.", severity="warning", timeout=8)
        elif not self.busy():
            # Asked each time: the TUI keeps the vault key, never the master password.
            self.app.push_screen(PasswordPrompt("Master password (to sign in to the sync server)"),
                                 lambda pw: pw and self.app.start_sync(pw))

    def action_add(self) -> None:
        if self.busy():
            return

        def done(values: dict | None) -> None:
            if values:
                entry = vault.add(self.app.entries, **values)
                self.app.save()
                self.refresh_table(select=entry["id"])
        self.app.push_screen(EntryForm(), done)

    def action_edit(self) -> None:
        if self.busy() or (e := self.selected()) is None:
            return

        def done(values: dict | None) -> None:
            if values:
                vault.edit(self.app.entries, e["id"], **values)
                self.app.save()
                self.refresh_table(select=e["id"])
        self.app.push_screen(EntryForm(e), done)

    def action_delete(self) -> None:
        if self.busy() or (e := self.selected()) is None:
            return

        def done(yes: bool | None) -> None:
            if yes:
                vault.delete(self.app.entries, e["id"])
                self.app.save()
                self.refresh_table()
        self.app.push_screen(ConfirmDelete(e["title"]), done)


class VaultletApp(App):
    TITLE = "Vaultlet"
    CSS = CSS
    BINDINGS = [Binding("ctrl+q", "quit", "Quit")]

    def __init__(self, path: Path, idle: int = IDLE_LOCK) -> None:
        super().__init__()
        self.path, self.idle = path, idle
        self.file: dict | None = None
        self.key: bytes | None = None
        self.entries: list[dict] = []
        self.last_input = time.monotonic()
        self.copied: str | None = None
        self.syncing = False
        self.session = 0  # bumped on lock, so a sync that finishes after a lock is ignored

    def on_mount(self) -> None:
        self.push_screen(UnlockScreen())
        self.set_interval(1, self.lock_if_idle)

    async def on_event(self, event: events.Event) -> None:
        if isinstance(event, (events.Key, events.MouseDown, events.MouseScrollDown, events.MouseScrollUp)):
            self.last_input = time.monotonic()
        await super().on_event(event)

    def lock_if_idle(self) -> None:
        if self.key is not None and time.monotonic() - self.last_input > self.idle:
            self.action_lock()

    def unlocked(self, file: dict, key: bytes, entries: list[dict]) -> None:
        self.file, self.key, self.entries = file, key, entries
        self.last_input = time.monotonic()
        self.switch_screen(MainScreen())

    def save(self) -> None:
        self.file = vault.persist(self.path, self.file, self.key, self.entries)

    def action_lock(self) -> None:
        # ponytail: drops references only; Python can't reliably wipe the key bytes (see README threat model)
        self.file = self.key = None
        self.entries = []
        self.session += 1
        while len(self.screen_stack) > 2:  # close any open form so its fields don't linger
            self.pop_screen()
        self.switch_screen(UnlockScreen())

    def start_sync(self, password: str) -> None:
        self.syncing = True
        self.notify("Syncing...")
        self.run_sync(password, self.session)

    @work(thread=True, group="sync")
    def run_sync(self, password: str, session: int) -> None:
        def ask(question: str) -> str:  # called by sync.run when the server copy has another password
            answer: Future = Future()
            self.call_from_thread(self.push_screen, PasswordPrompt(question, answer))
            if not (value := answer.result()):
                raise sync.SyncError("Sync cancelled.")
            return value

        try:
            result = sync.run(self.path, password, ask)
        except (WrongPassword, CorruptVault):
            result = UNLOCK_FAILED
        except sync.SyncError as exc:
            result = str(exc)
        self.call_from_thread(self.sync_finished, session, result)

    def sync_finished(self, session: int, result: str | tuple) -> None:
        self.syncing = False
        if session != self.session or self.key is None:
            return  # locked meanwhile; the merged vault is on disk for the next unlock
        if isinstance(result, str):
            self.notify(result, severity="error", timeout=10)
            return
        message, self.file, self.key, self.entries = result
        for screen in self.screen_stack:
            if isinstance(screen, MainScreen):
                screen.refresh_table()
        self.notify(message, timeout=10)

    def copy(self, value: str, secret: bool, what: str = "Password", seconds: int = CLEAR_AFTER) -> None:
        try:
            pyperclip.copy(value)
        except pyperclip.PyperclipException:
            self.notify("No clipboard available (on Linux, install xclip, xsel or wl-clipboard).", severity="error")
            return
        if not secret:
            self.notify("Copied.")
            return
        self.copied = value
        self.notify(f"{what} copied. Clipboard clears in {seconds}s.")
        self.set_timer(seconds, self.clear_clipboard)

    def clear_clipboard(self) -> None:
        """Clear the clipboard only if it still holds the password we copied."""
        if self.copied is None:
            return
        try:
            if secrets.compare_digest(pyperclip.paste().encode(), self.copied.encode()):
                pyperclip.copy("")
        except pyperclip.PyperclipException:
            pass
        self.copied = None

    def on_unmount(self) -> None:
        self.clear_clipboard()  # don't leave a password behind on quit


def run(path: Path, idle: int = IDLE_LOCK) -> None:
    VaultletApp(path, idle).run()
