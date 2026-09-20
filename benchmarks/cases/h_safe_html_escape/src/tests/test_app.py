import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_hi(client):
    assert client.get('/hi?n=x').get_data(as_text=True) == '<p>Hi x</p>'
