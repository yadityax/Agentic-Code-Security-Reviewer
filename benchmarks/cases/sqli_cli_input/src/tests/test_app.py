from app import find_item


def test_find():
    assert find_item("1") == [(1, "pen")]
