import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


class FakeResp:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n):
        return b"page"


def test_preview_public(client, monkeypatch):
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda url, **kw: FakeResp())
    assert client.get("/preview?link=https://example.com/").get_json() == {"bytes": 4}
