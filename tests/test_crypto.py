import pytest
from cryptography.exceptions import InvalidTag

from vaultlet import crypto


def test_roundtrip():
    f, vk = crypto.new_vault("correct horse")
    f = crypto.write_entries(f, vk, [{"title": "GitHub", "password": "x"}])
    vk2 = crypto.unlock(f, "correct horse")
    assert crypto.read_entries(f, vk2)[0]["title"] == "GitHub"


def test_wrong_password():
    f, _ = crypto.new_vault("right")
    with pytest.raises(InvalidTag):
        crypto.unlock(f, "wrong")


def test_tampered_ciphertext():
    f, vk = crypto.new_vault("pw")
    raw = bytearray(crypto.b64d(f["vault"]["ct"]))
    raw[0] ^= 1
    f["vault"]["ct"] = crypto.b64e(bytes(raw))
    with pytest.raises(InvalidTag):
        crypto.read_entries(f, vk)


def test_tampered_header():
    f, vk = crypto.new_vault("pw")
    f["version"] = 2
    with pytest.raises(InvalidTag):
        crypto.read_entries(f, vk)


def test_nonce_is_fresh():
    f, vk = crypto.new_vault("pw")
    f2 = crypto.write_entries(f, vk, [])
    assert f["vault"]["nonce"] != f2["vault"]["nonce"]


def test_rekey_changes_password_keeps_key_and_entries():
    f, vk = crypto.new_vault("old")
    f = crypto.write_entries(f, vk, [{"title": "GitHub"}])
    f2 = crypto.rekey(f, vk, crypto.read_entries(f, vk), "new")
    assert crypto.unlock(f2, "new") == vk
    assert crypto.read_entries(f2, vk) == [{"title": "GitHub"}]
    assert f2["kdf"]["salt"] != f["kdf"]["salt"]
    assert f2["vault"]["nonce"] != f["vault"]["nonce"]
    with pytest.raises(InvalidTag):
        crypto.unlock(f2, "old")


def test_rekey_applies_new_kdf_params():
    f, vk = crypto.new_vault("pw")
    params = {"time_cost": 1, "memory_kib": 8192, "parallelism": 1}
    f2 = crypto.rekey(f, vk, [], "pw", params)
    assert {k: f2["kdf"][k] for k in params} == params
    assert crypto.unlock(f2, "pw") == vk
