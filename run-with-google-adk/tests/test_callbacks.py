"""Unit tests for mcp_security_agent.callbacks."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from google.genai import types

# Add src directory to path
src_dir = str(Path(__file__).resolve().parents[1] / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from mcp_security_agent.callbacks import bmc_trim_llm_request


def test_bmc_trim_llm_request_passthrough():
    mock_context = MagicMock()
    mock_request = MagicMock()
    mock_request.contents = ["alert summary"]

    result = bmc_trim_llm_request(mock_context, mock_request)
    assert result is None


def test_bmc_sanitizes_oversized_output_schema_and_vendor_bloat():
    compact_decl = types.FunctionDeclaration(
        name="get_security_alerts",
        description="Get alerts",
        parameters_json_schema={
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "enum": ["OPEN", "CLOSED"],
                    "x-google-enum-descriptions": ["Open state", "Closed state"],
                }
            },
        },
        response_json_schema={
            "type": "object",
            "properties": {"status": {"type": "string"}},
        },
    )
    oversized_decl = types.FunctionDeclaration(
        name="list_security_alerts_bloat",
        description="Heavy schema tool",
        parameters_json_schema={"type": "object", "properties": {}},
        response_json_schema={
            "type": "object",
            "properties": {f"field_{i}": {"type": "string", "description": "x" * 80} for i in range(80)},
        },
    )

    llm_request = type(
        "FakeLlmRequest",
        (),
        {
            "config": types.GenerateContentConfig(
                tools=[types.Tool(function_declarations=[compact_decl, oversized_decl])]
            )
        },
    )()
    ctx = type("FakeCtx", (), {"state": {}})()

    res = bmc_trim_llm_request(ctx, llm_request, max_output_schema_bytes=4096)
    assert res is None
    # Vendor enum descriptions stripped, compact response schema preserved
    assert (
        "x-google-enum-descriptions"
        not in compact_decl.parameters_json_schema["properties"]["state"]
    )
    assert compact_decl.response_json_schema is not None
    # Oversized outputSchema dropped cleanly
    assert oversized_decl.response_json_schema is None


def test_bmc_zero_threshold_drops_all_output_schemas():
    decl = types.FunctionDeclaration(
        name="search_udm",
        description="UDM search",
        parameters_json_schema={"type": "object", "properties": {}},
        response_json_schema={"type": "object", "properties": {"count": {"type": "integer"}}},
    )
    llm_request = type(
        "FakeLlmRequest",
        (),
        {"config": types.GenerateContentConfig(tools=[types.Tool(function_declarations=[decl])])},
    )()
    ctx = type("FakeCtx", (), {"state": {}})()

    with patch.dict(os.environ, {"ADK_MAX_TOOL_OUTPUT_SCHEMA_BYTES": "0"}, clear=False):
        bmc_trim_llm_request(ctx, llm_request)
    assert decl.response_json_schema is None


def test_bmc_propagates_w3c_opentelemetry_traceparent():
    http_opts = types.HttpOptions(headers={"x-existing": "1"})
    llm_request = type(
        "FakeLlmRequest",
        (),
        {"config": types.GenerateContentConfig(http_options=http_opts)},
    )()
    ctx = type("FakeCtx", (), {"state": {}})()

    traceparent_val = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    with (
        patch("opentelemetry.trace.get_current_span") as mock_get_span,
        patch("opentelemetry.propagate.inject") as mock_inject,
    ):
        mock_span = MagicMock()
        mock_span.get_span_context.return_value.is_valid = True
        mock_get_span.return_value = mock_span
        mock_inject.side_effect = lambda carrier: carrier.update({"traceparent": traceparent_val})

        res = bmc_trim_llm_request(ctx, llm_request)
        assert res is None
        assert ctx.state["otel_trace_headers"]["traceparent"] == traceparent_val
        assert llm_request.config.http_options.headers["traceparent"] == traceparent_val
        assert llm_request.config.http_options.headers["x-existing"] == "1"


def test_bmc_rewrites_bare_load_mcp_resource_instruction_when_single_prefixed_tool():
    prefixed_decl = types.FunctionDeclaration(
        name="secops_load_mcp_resource",
        description="Loads MCP resources from secops",
        parameters_json_schema={"type": "object", "properties": {}},
    )
    llm_request = type(
        "FakeLlmRequest",
        (),
        {
            "config": types.GenerateContentConfig(
                system_instruction=(
                    "Call the `load_mcp_resource` function. "
                    "Always call load_mcp_resource before answering."
                ),
                tools=[types.Tool(function_declarations=[prefixed_decl])],
            )
        },
    )()
    ctx = type("FakeCtx", (), {"state": {}})()
    bmc_trim_llm_request(ctx, llm_request)
    assert "secops_load_mcp_resource" in llm_request.config.system_instruction
    assert "`load_mcp_resource`" not in llm_request.config.system_instruction
