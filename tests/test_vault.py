import json
import os
import stat

import pytest

from vaultlet import crypto, vault
from vaultlet.errors import CorruptVault, EntryNotFound, WrongPassword


def make_file(tmp_path, password="pw"):
    f, vk = crypto.new_vault(password)
    path = tmp_path / "vault.json"
    vault.save(path, f)
    return path, f, vk


def test_save_then_load_roundtrip(tmp_path):
    path, f, _ = make_file(tmp_path)
    assert vault.load(path) == f


@pytest.mark.parametrize("content", ["", '{"version": 1, "kdf"', "not json", "[1, 2]"])
def test_load_rejects_empty_truncated_or_non_json(tmp_path, content):
    path = tmp_path / "vault.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(CorruptVault):
        vault.load(path)


def test_load_rejects_missing_fields(tmp_path):
    path, f, _ = make_file(tmp_path)
    del f["wrapped_key"]
    path.write_text(json.dumps(f), encoding="utf-8")
    with pytest.raises(CorruptVault):
        vault.load(path)


def test_wrong_password_raises_wrong_password(tmp_path):
    _, f, _ = make_file(tmp_path, password="right")
    with pytest.raises(WrongPassword):
        vault.unlock(f, "wrong")


def test_malformed_kdf_raises_corrupt_vault(tmp_path):
    _, f, _ = make_file(tmp_path)
    f["kdf"]["salt"] = "!!not base64!!"
    with pytest.raises(CorruptVault):
        vault.unlock(f, "pw")


def test_tampered_vault_contents_raise_corrupt_vault(tmp_path):
    _, f, vk = make_file(tmp_path)
    raw = bytearray(crypto.b64d(f["vault"]["ct"]))
    raw[0] ^= 1
    f["vault"]["ct"] = crypto.b64e(bytes(raw))
    with pytest.raises(CorruptVault):
        vault.read_entries(f, vk)


def test_unlock_and_read_entries_happy_path(tmp_path):
    _, f, _ = make_file(tmp_path, password="pw")
    f = crypto.write_entries(f, crypto.unlock(f, "pw"), [{"title": "GitHub"}])
    vk = vault.unlock(f, "pw")
    assert vault.read_entries(f, vk) == [{"title": "GitHub"}]


def test_failed_save_keeps_old_file(tmp_path, monkeypatch):
    path, f, _ = make_file(tmp_path)
    before = path.read_bytes()

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(vault.os, "replace", boom)
    with pytest.raises(OSError):
        vault.save(path, {**f, "marker": 1})
    assert path.read_bytes() == before
    assert not (tmp_path / "vault.json.tmp").exists()


def test_first_save_creates_no_backup(tmp_path):
    path = tmp_path / "vault.json"
    vault.save(path, {"marker": 1})
    assert not (tmp_path / "vault.json.bak").exists()


def test_save_keeps_one_backup_of_previous_version(tmp_path):
    path, f, _ = make_file(tmp_path)
    vault.save(path, {**f, "marker": 2})
    vault.save(path, {**f, "marker": 3})
    backup = json.loads((tmp_path / "vault.json.bak").read_text(encoding="utf-8"))
    assert backup["marker"] == 2
    assert json.loads(path.read_text(encoding="utf-8"))["marker"] == 3


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")
def test_vault_file_mode_is_0600(tmp_path):
    path, _, _ = make_file(tmp_path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_add_gives_unique_ids_and_stores_fields():
    entries = []
    a = vault.add(entries, title="GitHub", username="dillo", password="p1")
    b = vault.add(entries, title="Mail")
    assert a["id"] != b["id"]
    assert vault.get(entries, a["id"])["password"] == "p1"
    assert b["username"] == "" and b["notes"] == ""


def test_get_missing_entry_raises():
    with pytest.raises(EntryNotFound):
        vault.get([], "nope")


def test_edit_changes_fields_and_rejects_unknown():
    entries = []
    e = vault.add(entries, title="GitHub")
    vault.edit(entries, e["id"], username="dillo", url="https://github.com")
    assert vault.get(entries, e["id"])["username"] == "dillo"
    with pytest.raises(ValueError):
        vault.edit(entries, e["id"], id="hijack")


def test_delete_removes_entry_and_missing_raises():
    entries = []
    e = vault.add(entries, title="GitHub")
    vault.delete(entries, e["id"])
    assert entries == []
    with pytest.raises(EntryNotFound):
        vault.delete(entries, e["id"])


def test_search_matches_title_and_username_not_password():
    entries = []
    vault.add(entries, title="GitHub", username="dillo")
    vault.add(entries, title="Bank", username="alice", password="github-ish")
    assert [e["title"] for e in vault.search(entries, "GITHUB")] == ["GitHub"]
    assert [e["title"] for e in vault.search(entries, "ALICE")] == ["Bank"]
    assert vault.search(entries, "github-ish") == []


def test_list_is_sorted_case_insensitively():
    entries = []
    vault.add(entries, title="beta")
    vault.add(entries, title="Alpha")
    assert [e["title"] for e in vault.list_entries(entries)] == ["Alpha", "beta"]


def test_persist_roundtrip_through_file(tmp_path):
    path, f, vk = make_file(tmp_path, password="pw")
    entries = []
    vault.add(entries, title="GitHub", password="s3cret")
    vault.persist(path, f, vk, entries)

    loaded = vault.load(path)
    key = vault.unlock(loaded, "pw")
    assert vault.read_entries(loaded, key) == entries


def test_rekey_saves_new_password(tmp_path):
    path, f, vk = make_file(tmp_path, password="old")
    vault.rekey(path, f, vk, [], "new")
    assert vault.open_vault(path, "new")[1] == vk
    with pytest.raises(WrongPassword):
        vault.open_vault(path, "old")
    with pytest.raises(WrongPassword):  # the backup must not keep the old password alive
        vault.unlock(vault.load(str(path) + ".bak"), "old")
    assert vault.unlock(vault.load(str(path) + ".bak"), "new") == vk
