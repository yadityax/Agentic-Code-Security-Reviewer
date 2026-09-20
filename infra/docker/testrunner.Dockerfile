# Offline test runner for untrusted repositories: dependencies are baked in at build time so that
# test runs need no network. Only common libraries; project-specific installs are not supported.
FROM python:3.12-slim
RUN pip install --no-cache-dir pytest flask fastapi httpx requests pyyaml sqlalchemy jinja2 markupsafe werkzeug ruff \
    && useradd -m -u 65532 runner
WORKDIR /work
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/work
