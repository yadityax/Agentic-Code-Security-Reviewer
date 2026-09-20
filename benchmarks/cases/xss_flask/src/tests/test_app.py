import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_hello(client):
    assert b"Hello bob" in client.get("/hello?name=bob").data
