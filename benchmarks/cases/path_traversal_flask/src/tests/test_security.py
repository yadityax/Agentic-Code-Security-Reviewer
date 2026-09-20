import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_traversal_blocked(client):
    resp = client.get("/download?name=../secret.txt")
    assert "top-secret" not in resp.get_data(as_text=True)
