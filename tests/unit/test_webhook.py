import hashlib
import hmac
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from backend.config import Settings, get_settings
from backend.main import app
from backend.services.queue import ScanRequest, get_queue

SECRET = "test-secret"


class FakeQueue:
    def __init__(self) -> None:
        self.jobs: dict[str, ScanRequest] = {}

    async def enqueue(self, req: ScanRequest) -> bool:
        if req.delivery_id in self.jobs:
            return False
        self.jobs[req.delivery_id] = req
        return True


def sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def pr_payload(action: str = "opened", draft: bool = False) -> dict[str, Any]:
    return {
        "action": action,
        "repository": {"full_name": "yadityax/acsr-test-target"},
        "pull_request": {
            "number": 7,
            "draft": draft,
            "head": {"sha": "h" * 40, "repo": {"full_name": "someone/fork"}},
            "base": {"sha": "b" * 40},
        },
    }


@pytest.fixture
def queue() -> FakeQueue:
    q = FakeQueue()
    app.dependency_overrides[get_queue] = lambda: q
    app.dependency_overrides[get_settings] = lambda: Settings(
        github_webhook_secret=SecretStr(SECRET)
    )
    yield q  # type: ignore[misc]
    app.dependency_overrides.clear()


def post(
    payload: dict[str, Any] | bytes,
    *,
    event: str = "pull_request",
    delivery: str = "d-1",
    signature: str | None = None,
) -> Any:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery,
        "X-Hub-Signature-256": signature if signature is not None else sign(body),
        "Content-Type": "application/json",
    }
    return TestClient(app).post("/webhook/github", content=body, headers=headers)


def test_valid_pr_is_queued_with_fork_head(queue: FakeQueue) -> None:
    resp = post(pr_payload())
    assert resp.status_code == 200
    assert resp.json() == {"status": "queued"}
    job = queue.jobs["d-1"]
    assert (job.repo, job.pr_number, job.head_repo) == (
        "yadityax/acsr-test-target",
        7,
        "someone/fork",
    )


def test_bad_signature_rejected(queue: FakeQueue) -> None:
    assert post(pr_payload(), signature=sign(b"x")).status_code == 401
    assert post(pr_payload(), signature="sha1=abc").status_code == 401
    assert queue.jobs == {}


def test_missing_signature_rejected(queue: FakeQueue) -> None:
    body = json.dumps(pr_payload()).encode()
    resp = TestClient(app).post(
        "/webhook/github", content=body, headers={"X-GitHub-Event": "pull_request"}
    )
    assert resp.status_code == 401


def test_empty_server_secret_fails_closed(queue: FakeQueue) -> None:
    app.dependency_overrides[get_settings] = lambda: Settings(github_webhook_secret=SecretStr(""))
    body = json.dumps(pr_payload()).encode()
    assert post(body, signature=sign(body, "")).status_code == 401


def test_ping(queue: FakeQueue) -> None:
    assert post({"zen": "hi"}, event="ping").json() == {"status": "pong"}


@pytest.mark.parametrize("action", ["closed", "labeled", "edited"])
def test_irrelevant_actions_ignored(queue: FakeQueue, action: str) -> None:
    assert post(pr_payload(action)).json()["status"] == "ignored"
    assert queue.jobs == {}


def test_draft_ignored(queue: FakeQueue) -> None:
    assert post(pr_payload(draft=True)).json()["status"] == "ignored"


def test_other_events_ignored(queue: FakeQueue) -> None:
    assert post({"x": 1}, event="push").json()["status"] == "ignored"


def test_redelivery_is_duplicate(queue: FakeQueue) -> None:
    assert post(pr_payload()).json()["status"] == "queued"
    assert post(pr_payload()).json()["status"] == "duplicate"


def test_malformed_payload_is_422(queue: FakeQueue) -> None:
    assert post({"action": "opened"}).status_code == 422
    assert post(b"not json").status_code == 422
