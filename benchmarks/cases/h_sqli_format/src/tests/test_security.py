import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_no_injection(client):
    assert client.get("/price?sku=x' OR '1'='1").get_json() == {'price': None}
