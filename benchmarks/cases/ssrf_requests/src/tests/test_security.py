import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_cloud_metadata_url_is_not_fetched(client, monkeypatch):
    import requests

    calls = []
    monkeypatch.setattr(requests, "get", lambda url, **kw: calls.append(url) or type("R", (), {"text": "x"})())
    client.get("/fetch?url=http://169.254.169.254/latest/meta-data/")
    assert calls == []
