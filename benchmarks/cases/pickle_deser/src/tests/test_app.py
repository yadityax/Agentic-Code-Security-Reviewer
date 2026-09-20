import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


import base64
import pickle


def test_load(client):
    data = base64.b64encode(pickle.dumps({"a": 1})).decode()
    assert client.post("/load", data={"data": data}).get_json() == {"type": "dict"}
