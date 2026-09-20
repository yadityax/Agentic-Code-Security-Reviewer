from tokens import make_reset_token


def test_len():
    assert len(make_reset_token(20)) == 20
