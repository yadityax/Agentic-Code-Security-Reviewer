import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_ok(client):
    assert client.get('/users?name=alice').get_json() == [[1, 'alice']]
