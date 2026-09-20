SHELL := /bin/bash
export HOST_UID := $(shell id -u)
export HOST_GID := $(shell id -g)
COMPOSE := docker compose

.PHONY: results init up down logs test test-fast lint fmt bench bench-dev bench-heldout bench-remediation corpus demo frontend-dev pull-scanners codeql observability

# One-time setup: scanner images, offline vulnerability DB, test-runner image, CodeQL bundle.
init: pull-scanners codeql
	docker build -q -t acsr-testrunner:latest -f infra/docker/testrunner.Dockerfile infra/docker
	docker volume create acsr_scanner-cache >/dev/null
	docker run --rm -v acsr_scanner-cache:/c alpine:3.21 chown -R $(HOST_UID):$(HOST_GID) /c
	docker run --rm --user $(HOST_UID):$(HOST_GID) -e HOME=/tmp -v acsr_scanner-cache:/cache aquasec/trivy:latest image --download-db-only --cache-dir /cache/trivy

pull-scanners:
	docker pull returntocorp/semgrep:latest
	docker pull zricethezav/gitleaks:latest
	docker pull aquasec/trivy:latest
	docker pull anchore/syft:latest

codeql:
	./infra/scripts/get_codeql.sh

up:
	@mkdir -p .workspaces
	@test -f .env || { echo "no .env: copy .env.example to .env and fill in the keys"; exit 1; }
	$(COMPOSE) up -d --build --wait

observability:
	@mkdir -p .workspaces
	OTEL_ENDPOINT=http://jaeger:4318 $(COMPOSE) --profile observability up -d --build --wait

down:
	$(COMPOSE) --profile observability down

logs:
	$(COMPOSE) logs -f worker api

test:
	uv run pytest

test-fast:
	uv run pytest tests/unit

lint:
	uv run ruff check . && uv run mypy backend mcp_server && cd frontend && npm run -s typecheck

fmt:
	uv run ruff format . && uv run ruff check --fix .

corpus:
	python3 benchmarks/build_corpus.py

bench-dev:
	uv run python -m backend.bench.run --split dev --systems A,B,C

bench-heldout:
	uv run python -m backend.bench.run --split heldout --systems A,B,C

bench: bench-dev bench-heldout

bench-remediation:
	uv run python -m backend.bench.remediation_bench --split heldout

demo:
	uv run python infra/scripts/demo.py

frontend-dev:
	cd frontend && npm run dev

# Regenerate docs/results.md from raw result files. Usage: make results DEV=<file> HELDOUT="<files>" REM="<files>"
results:
	uv run python -m backend.bench.report --dev $(DEV) --heldout $(HELDOUT) --remediation $(REM)
