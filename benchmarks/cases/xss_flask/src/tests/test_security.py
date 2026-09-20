import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


def test_script_is_escaped(client):
    assert b"<script>" not in client.get("/hello?name=<script>alert(1)</script>").data
