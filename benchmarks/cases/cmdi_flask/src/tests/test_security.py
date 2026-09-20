import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_no_command_chaining(client):
    body = client.get("/ping?host=x;echo INJECTED").get_data(as_text=True)
    assert "INJECTED\n" not in body.replace("pinging x;echo INJECTED", "")
