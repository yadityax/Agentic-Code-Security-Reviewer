import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_price(client):
    assert client.get('/price?sku=A1').get_json() == {'price': 9.5}
