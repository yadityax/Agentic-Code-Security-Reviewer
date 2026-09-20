from app import etag


def test_etag():
    assert len(etag(b'x')) == 16
