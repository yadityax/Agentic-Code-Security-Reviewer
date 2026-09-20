import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_cannot_read_other_users_invoice(client):
    assert client.get("/invoice/2", headers={"X-User": "alice"}).status_code in (403, 404)
