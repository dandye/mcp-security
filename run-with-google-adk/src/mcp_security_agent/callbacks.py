# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Lifecycle callbacks for tool schema sanitization and OpenTelemetry trace propagation."""

from collections.abc import MutableMapping
import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_MAX_TOOL_OUTPUT_SCHEMA_BYTES = 4096
VENDOR_SCHEMA_BLOAT_KEYS = frozenset({"x-google-enum-descriptions"})


def _resolve_max_output_schema_bytes() -> int:
    raw = os.environ.get("ADK_MAX_TOOL_OUTPUT_SCHEMA_BYTES")
    if raw is None or not raw.strip():
        return DEFAULT_MAX_TOOL_OUTPUT_SCHEMA_BYTES
    try:
        return int(raw.strip())
    except ValueError:
        return DEFAULT_MAX_TOOL_OUTPUT_SCHEMA_BYTES


def _strip_vendor_bloat_keys(schema: Any) -> int:
    """Recursively removes vendor metadata bloat keys from JSON Schema dictionaries."""
    removed = 0
    if isinstance(schema, dict):
        for key in list(schema.keys()):
            if key in VENDOR_SCHEMA_BLOAT_KEYS:
                del schema[key]
                removed += 1
            else:
                removed += _strip_vendor_bloat_keys(schema[key])
    elif isinstance(schema, list):
        for item in schema:
            removed += _strip_vendor_bloat_keys(item)
    return removed


def _sanitize_tool_schemas(llm_request: Any, max_output_schema_bytes: int) -> None:
    """Bounds oversized outputSchema declarations and strips vendor schema bloat."""
    config = getattr(llm_request, "config", None)
    tools = getattr(config, "tools", None)
    if not isinstance(tools, (list, tuple)):
        return

    dropped_output_schemas = 0
    stripped_vendor_keys = 0

    for tool_entry in tools:
        declarations = getattr(tool_entry, "function_declarations", None)
        if not isinstance(declarations, (list, tuple)):
            continue
        for decl in declarations:
            params_schema = getattr(decl, "parameters_json_schema", None)
            if isinstance(params_schema, dict):
                stripped_vendor_keys += _strip_vendor_bloat_keys(params_schema)

            resp_schema = getattr(decl, "response_json_schema", None)
            if resp_schema is None:
                continue

            if max_output_schema_bytes <= 0:
                decl.response_json_schema = None
                dropped_output_schemas += 1
                continue

            if isinstance(resp_schema, dict):
                stripped_vendor_keys += _strip_vendor_bloat_keys(resp_schema)
                try:
                    encoded_len = len(
                        json.dumps(resp_schema, separators=(",", ":")).encode("utf-8")
                    )
                except (TypeError, ValueError):
                    encoded_len = max_output_schema_bytes + 1
                if encoded_len > max_output_schema_bytes:
                    decl.response_json_schema = None
                    dropped_output_schemas += 1

    if dropped_output_schemas or stripped_vendor_keys:
        logger.debug(
            "Sanitized LLM tool declarations: dropped %d oversized output schemas (>%d B), "
            "stripped %d vendor metadata keys.",
            dropped_output_schemas,
            max_output_schema_bytes,
            stripped_vendor_keys,
        )


def _propagate_otel_trace_context(callback_context: Any, llm_request: Any) -> None:
    """Propagates W3C traceparent and tracestate headers when an OpenTelemetry span is active."""
    try:
        from opentelemetry import propagate, trace

        span = trace.get_current_span()
        if span is None or not span.get_span_context().is_valid:
            return
        carrier: Dict[str, str] = {}
        propagate.inject(carrier)
        if not carrier:
            return

        state = getattr(callback_context, "state", None)
        if isinstance(state, MutableMapping) or hasattr(state, "__setitem__"):
            try:
                state["otel_trace_headers"] = dict(carrier)
            except Exception:
                pass

        config = getattr(llm_request, "config", None)
        http_options = getattr(config, "http_options", None)
        if isinstance(http_options, dict):
            headers = http_options.setdefault("headers", {})
            if isinstance(headers, dict):
                headers.update(carrier)
        elif http_options is not None:
            existing_headers = getattr(http_options, "headers", None)
            if isinstance(existing_headers, dict):
                merged = dict(existing_headers)
                merged.update(carrier)
                http_options.headers = merged
            elif existing_headers is None and hasattr(http_options, "headers"):
                try:
                    http_options.headers = dict(carrier)
                except Exception:
                    pass
    except ImportError:
        return
    except Exception as exc:
        logger.debug("Skipping OpenTelemetry context propagation in before_model_callback: %s", exc)


def bmc_trim_llm_request(
    callback_context: Any,
    llm_request: Any,
    max_output_schema_bytes: Optional[int] = None,
) -> Optional[Any]:
    """Callback executed prior to LLM invocation to sanitize tool schemas and propagate W3C trace context.

    In Google ADK v2, returning None allows the standard model execution flow to proceed.
    Returning an LlmResponse will short-circuit and provide an immediate response.

    Args:
        callback_context: ADK callback context object.
        llm_request: Inbound LLM request object.
        max_output_schema_bytes: Optional override for maximum response_json_schema byte size.

    Returns:
        None to proceed with LLM generation, or an LlmResponse to short-circuit.
    """
    logger.debug("Executing before_model_callback for schema sanitization and trace propagation.")
    threshold = (
        _resolve_max_output_schema_bytes()
        if max_output_schema_bytes is None
        else max_output_schema_bytes
    )
    _sanitize_tool_schemas(llm_request, threshold)
    _propagate_otel_trace_context(callback_context, llm_request)
    return None
