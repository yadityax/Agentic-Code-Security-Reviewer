# The worker orchestrates scans and launches scanner/test containers as siblings through the Docker API
# (via a restricted socket proxy). It contains the Docker CLI only, never a daemon.
FROM docker:27-cli AS dockercli

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /opt/deps
COPY pyproject.toml uv.lock ./
RUN uv export --frozen --no-dev --no-hashes --no-emit-project -o requirements.txt \
    && uv pip install --system --no-cache -r requirements.txt
# Project code is bind-mounted at its host path at run time: the sandbox containers we launch resolve
# volume paths on the host, so the path must be identical inside and outside this container.
CMD ["arq", "backend.worker.WorkerSettings"]
