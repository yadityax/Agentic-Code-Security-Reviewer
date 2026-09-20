import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_reject(client):
    assert client.get('/run?cmd=rm').status_code == 400
