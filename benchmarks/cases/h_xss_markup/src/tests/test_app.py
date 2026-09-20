import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_greet(client):
    assert b'Welcome, ann' in client.get('/greet?who=ann').data
