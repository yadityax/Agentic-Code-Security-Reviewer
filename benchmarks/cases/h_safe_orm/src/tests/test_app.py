import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_u(client):
    assert client.get('/u?name=alice').get_json() == ['alice']
