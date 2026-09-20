import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_report(client):
    assert client.get('/report?id=1').status_code in (200, 404)
