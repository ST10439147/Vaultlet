from typer.testing import CliRunner

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
