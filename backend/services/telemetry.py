"""Tracing (OpenTelemetry) and metrics (Prometheus). Both are no-ops until configured."""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, Gauge, Histogram

from backend.services.redact import redact_secrets

tracer = trace.get_tracer("acsr")

SCANS = Counter("acsr_scans_total", "Scans completed", ["status"])
SCAN_LATENCY = Histogram(
    "acsr_scan_latency_seconds",
    "End-to-end scan latency",
    buckets=(5, 15, 30, 60, 120, 300, 600, 1800),
)
TOOL_DURATION = Histogram(
    "acsr_tool_duration_seconds", "Scanner duration", ["tool"], buckets=(1, 5, 15, 30, 60, 120, 300)
)
TOOL_ERRORS = Counter("acsr_tool_errors_total", "Scanner failures", ["tool"])
FINDINGS = Counter("acsr_findings_total", "Findings after correlation", ["severity", "verdict"])
LLM_TOKENS = Counter("acsr_llm_tokens_total", "LLM tokens", ["kind"])
LLM_COST = Counter("acsr_llm_cost_usd_total", "Estimated LLM cost in USD")
REMEDIATIONS = Counter("acsr_remediations_total", "Remediation attempts", ["outcome"])
IN_FLIGHT = Gauge("acsr_scans_in_flight", "Scans currently running")


def setup_telemetry(service_name: str = "acsr") -> bool:
    """Export spans over OTLP/HTTP when OTEL_EXPORTER_OTLP_ENDPOINT is set. Returns True if enabled."""
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return False
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    return True


@contextmanager
def span(name: str, **attrs: Any) -> Iterator[trace.Span]:
    """Span whose string attributes are secret-redacted before they can reach a trace backend."""
    with tracer.start_as_current_span(name) as sp:
        for k, v in attrs.items():
            sp.set_attribute(k, redact_secrets(v) if isinstance(v, str) else v)
        yield sp
