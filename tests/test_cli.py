import pytest
from typer.testing import CliRunner

from vaultlet import cli
from vaultlet.cli import app

runner = CliRunner()


def run(path, *args, input=None):
    return runner.invoke(app, ["--vault", str(path), *args], input=input)


def init(tmp_path, password="pw"):
    path = tmp_path / "vault.json"
    result = run(path, "init", input=f"{password}\n{password}\n")
    assert result.exit_code == 0, result.output
    return path


def field(output, name):
    line = next(l for l in output.splitlines() if l.startswith(f"{name}:"))
    return line.split(":", 1)[1].strip()


def test_full_flow(tmp_path):
    path = init(tmp_path)

    r = run(path, "add", "GitHub", "--username", "dillo", input="pw\ns3cret\ns3cret\n")
    assert r.exit_code == 0, r.output

    r = run(path, "list", input="pw\n")
    assert "GitHub" in r.output and "dillo" in r.output
    short_id = r.output.strip().splitlines()[-1].split()[0]

    r = run(path, "get", short_id, input="pw\n")
    assert "s3cret" not in r.output and field(r.output, "password") == "********"
    r = run(path, "get", short_id, "--show", input="pw\n")
    assert field(r.output, "password") == "s3cret"

    assert "GitHub" in run(path, "search", "git", input="pw\n").output
    assert "No matches." in run(path, "search", "zzz", input="pw\n").output

    r = run(path, "edit", short_id, "--url", "https://github.com", input="pw\n")
    assert r.exit_code == 0, r.output
    assert field(run(path, "get", short_id, input="pw\n").output, "url") == "https://github.com"

    r = run(path, "delete", short_id, "--yes", input="pw\n")
    assert r.exit_code == 0, r.output
    assert "Vault is empty." in run(path, "list", input="pw\n").output


def test_add_with_generated_password(tmp_path):
    path = init(tmp_path)
    run(path, "add", "Mail", "--generate", "--length", "24", input="pw\n")
    short_id = run(path, "list", input="pw\n").output.strip().splitlines()[-1].split()[0]
    assert len(field(run(path, "get", short_id, "--show", input="pw\n").output, "password")) == 24


def test_wrong_password_and_corrupt_file_give_same_message(tmp_path):
    path = init(tmp_path)
    wrong = run(path, "list", input="nope\n")
    path.write_text("garbage", encoding="utf-8")
    corrupt = run(path, "list", input="pw\n")
    for r in (wrong, corrupt):
        assert r.exit_code == 1
        assert "wrong password or damaged file" in r.output


def test_init_refuses_to_overwrite(tmp_path):
    path = init(tmp_path)
    before = path.read_bytes()
    r = run(path, "init", input="other\nother\n")
    assert r.exit_code == 1 and path.read_bytes() == before


def test_missing_vault_fails_before_asking_for_password(tmp_path):
    r = run(tmp_path / "nope.json", "list")
    assert r.exit_code == 1
    assert "No vault at" in r.output and "Master password" not in r.output


def test_unknown_id_and_empty_edit_fail(tmp_path):
    path = init(tmp_path)
    assert run(path, "get", "deadbeef", input="pw\n").exit_code == 1
    assert run(path, "edit", "deadbeef").exit_code == 1


def test_generate_command_needs_no_vault(tmp_path):
    r = run(tmp_path / "missing.json", "generate", "--length", "30", "--no-symbols")
    assert r.exit_code == 0, r.output
    pw = r.output.strip()
    assert len(pw) == 30 and pw.isalnum()
    assert not (tmp_path / "missing.json").exists()


def test_add_generated_without_symbols(tmp_path):
    path = init(tmp_path)
    run(path, "add", "Bank", "-g", "--no-symbols", input="pw\n")
    short_id = run(path, "list", input="pw\n").output.strip().splitlines()[-1].split()[0]
    pw = field(run(path, "get", short_id, "--show", input="pw\n").output, "password")
    assert len(pw) == 20 and pw.isalnum()


def test_password_only_printed_with_show(tmp_path):
    secret, master = "Zq9-unique-secret", "Mst-unique-master"
    path = init(tmp_path, master)
    m = f"{master}\n"
    outputs = [run(path, "add", "Site", input=f"{m}{secret}\n{secret}\n").output]
    short_id = run(path, "list", input=m).output.strip().splitlines()[-1].split()[0]
    outputs += [
        run(path, "list", input=m).output,
        run(path, "search", "site", input=m).output,
        run(path, "get", short_id, input=m).output,
        run(path, "edit", short_id, "--notes", "n", input=m).output,
        run(path, "delete", short_id, "--yes", input=m).output,
    ]
    for out in outputs:
        assert secret not in out and master not in out


def test_tracebacks_never_show_locals():
    assert app.pretty_exceptions_show_locals is False


@pytest.fixture
def clipboard(monkeypatch):
    """Fake clipboard; sleep runs `during_wait` instead of waiting."""
    board = {"text": "", "during_wait": lambda: None}
    monkeypatch.setattr(cli.pyperclip, "copy", lambda t: board.update(text=t))
    monkeypatch.setattr(cli.pyperclip, "paste", lambda: board["text"])
    monkeypatch.setattr(cli.time, "sleep", lambda s: board["during_wait"]())
    return board


def add_entry(tmp_path, secret="s3cret"):
    path = init(tmp_path)
    run(path, "add", "Site", input=f"pw\n{secret}\n{secret}\n")
    return path, run(path, "list", input="pw\n").output.strip().splitlines()[-1].split()[0]


def test_copy_puts_password_on_clipboard_then_clears(tmp_path, clipboard):
    path, short_id = add_entry(tmp_path)
    seen = []
    clipboard["during_wait"] = lambda: seen.append(clipboard["text"])
    r = run(path, "get", short_id, "--copy", input="pw\n")
    assert r.exit_code == 0, r.output
    assert seen == ["s3cret"] and clipboard["text"] == ""
    assert "s3cret" not in r.output and "Clipboard cleared." in r.output


def test_copy_leaves_clipboard_alone_if_user_copied_something_else(tmp_path, clipboard):
    path, short_id = add_entry(tmp_path)
    clipboard["during_wait"] = lambda: clipboard.update(text="other")
    r = run(path, "get", short_id, "-c", input="pw\n")
    assert clipboard["text"] == "other" and "left alone" in r.output


def test_ctrl_c_clears_clipboard_immediately(tmp_path, clipboard):
    path, short_id = add_entry(tmp_path)

    def interrupt():
        raise KeyboardInterrupt

    clipboard["during_wait"] = interrupt
    r = run(path, "get", short_id, "--copy", input="pw\n")
    assert r.exit_code == 0, r.output
    assert clipboard["text"] == ""
