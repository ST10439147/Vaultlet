from vaultlet.generator import generate


def test_generator_covers_all_pools():
    for _ in range(50):
        pw = generate(16)
        assert len(pw) == 16
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)
