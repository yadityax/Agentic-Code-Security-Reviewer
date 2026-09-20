import hashlib


def etag(content: bytes) -> str:
    # cache validator only, not a security control
    return hashlib.sha256(content).hexdigest()[:16]
