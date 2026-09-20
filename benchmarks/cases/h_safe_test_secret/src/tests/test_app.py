from app import add

FAKE_TOKEN = "test-token-not-a-real-secret"  # fixture value


def test_add():
    assert add(1, 2) == 3 and FAKE_TOKEN
