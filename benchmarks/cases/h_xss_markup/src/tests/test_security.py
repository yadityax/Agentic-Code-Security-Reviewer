import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_escaped(client):
    assert b'<img' not in client.get('/greet?who=<img src=x onerror=1>').data
