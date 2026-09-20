import hashlib
import hmac
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from backend.config import Settings, get_settings
from backend.services.queue import ScanQueue, ScanRequest, get_queue

router = APIRouter()

SCAN_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


def verify_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Check GitHub's X-Hub-Signature-256. Fails closed when no secret is configured."""
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def parse_pull_request(delivery_id: str, payload: dict[str, Any]) -> ScanRequest:
    pr = payload["pull_request"]
    return ScanRequest(
        delivery_id=delivery_id,
        repo=payload["repository"]["full_name"],
        pr_number=pr["number"],
        head_sha=pr["head"]["sha"],
        base_sha=pr["base"]["sha"],
        head_repo=(pr["head"].get("repo") or payload["repository"])["full_name"],
        head_ref=pr["head"].get("ref", ""),
        base_ref=pr["base"].get("ref", ""),
    )


@router.post("/webhook/github", status_code=status.HTTP_200_OK)
async def github_webhook(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    queue: Annotated[ScanQueue, Depends(get_queue)],
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_event: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
) -> dict[str, str]:
    body = await request.body()  # raw bytes: the signature covers them exactly
    secret = settings.github_webhook_secret.get_secret_value()
    if not verify_signature(secret, body, x_hub_signature_256):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid signature")

    if x_github_event == "ping":
        return {"status": "pong"}
    if x_github_event != "pull_request":
        return {"status": "ignored", "reason": f"event {x_github_event!r} not handled"}

    try:
        payload = await request.json()
        action = payload["action"]
        if action not in SCAN_ACTIONS or payload["pull_request"].get("draft"):
            return {"status": "ignored", "reason": f"action {action!r} (or draft PR)"}
        scan = parse_pull_request(x_github_delivery or "", payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "malformed payload") from exc
    if not scan.delivery_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing X-GitHub-Delivery")

    queued = await queue.enqueue(scan)
    return {"status": "queued" if queued else "duplicate"}
