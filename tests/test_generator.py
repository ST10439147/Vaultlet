import pytest

from vaultlet.generator import generate


def test_generator_covers_all_pools():
    for _ in range(50):
        pw = generate(16)
        assert len(pw) == 16
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)


def test_generator_without_symbols_is_alphanumeric():
    for _ in range(50):
        pw = generate(12, symbols=False)
        assert len(pw) == 12 and pw.isalnum()


def test_generator_rejects_length_shorter_than_pools():
    with pytest.raises(ValueError):
        generate(3)
    assert len(generate(3, symbols=False)) == 3
