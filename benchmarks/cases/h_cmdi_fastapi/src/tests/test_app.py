from fastapi.testclient import TestClient

from main import app


def test_echo():
    assert TestClient(app).get("/echo", params={"msg": "hi"}).json() == {"ok": True}
