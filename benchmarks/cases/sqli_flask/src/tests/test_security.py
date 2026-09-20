import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_injection_does_not_dump_table(client):
    assert client.get("/users?name=x' OR '1'='1").get_json() == []
