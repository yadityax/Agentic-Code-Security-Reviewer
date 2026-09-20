import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_ping(client):
    assert "pinging localhost" in client.get("/ping?host=localhost").get_data(as_text=True)
