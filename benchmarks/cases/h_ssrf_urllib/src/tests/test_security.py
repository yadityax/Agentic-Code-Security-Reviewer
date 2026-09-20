import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_internal_link_not_fetched(client, monkeypatch):
    import urllib.request

    calls = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, **kw: calls.append(url) or (_ for _ in ()).throw(RuntimeError("blocked")))
    client.get("/preview?link=http://127.0.0.1:8080/admin")
    assert calls == []
