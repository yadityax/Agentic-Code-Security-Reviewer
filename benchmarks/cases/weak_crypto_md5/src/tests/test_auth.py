from auth import check_password, hash_password


def test_roundtrip():
    assert check_password("pw", hash_password("pw"))
    assert not check_password("other", hash_password("pw"))
