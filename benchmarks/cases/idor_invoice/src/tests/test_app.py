import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_own_invoice(client):
    assert client.get("/invoice/1", headers={"X-User": "alice"}).get_json()["total"] == 120


def test_requires_login(client):
    assert client.get("/invoice/1").status_code == 401
