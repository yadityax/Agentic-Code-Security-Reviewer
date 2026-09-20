import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_import(client):
    assert client.post('/import', data='a: 1\nb: 2').get_json() == {'keys': ['a', 'b']}
