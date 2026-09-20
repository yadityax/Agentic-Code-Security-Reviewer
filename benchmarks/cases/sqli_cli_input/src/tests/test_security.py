from app import find_item


def test_no_injection():
    assert find_item("1 OR 1=1") == [] or len(find_item("1 OR 1=1")) <= 1
