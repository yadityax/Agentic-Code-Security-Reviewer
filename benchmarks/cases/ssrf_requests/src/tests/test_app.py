import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


class FakeResp:
    text = "remote body"


def test_fetch_public_url(client, monkeypatch):
    import requests

    monkeypatch.setattr(requests, "get", lambda url, **kw: FakeResp())
    assert client.get("/fetch?url=https://example.com/").get_json() == {"length": 11}
