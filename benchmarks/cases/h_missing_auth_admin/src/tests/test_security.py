import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_admin_requires_admin(client):
    assert client.get('/admin/users').status_code in (401, 403)
