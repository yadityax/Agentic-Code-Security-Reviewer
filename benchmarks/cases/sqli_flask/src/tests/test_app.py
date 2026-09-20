import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_lookup(client):
    assert client.get("/users?name=alice").get_json() == [[1, "alice", "a@x.io"]]


def test_unknown(client):
    assert client.get("/users?name=zed").get_json() == []
