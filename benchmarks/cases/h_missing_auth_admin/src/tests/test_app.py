import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_profile(client):
    assert client.get('/profile', headers={'X-User': 'alice'}).get_json() == {'role': 'user'}
