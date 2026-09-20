import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_download(client):
    assert client.get("/download?name=hello.txt").get_data(as_text=True) == "hello file\n"
