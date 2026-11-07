# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Phase 3 contract and execution suite: ToolAnnotations, structuredContent, and is_error."""

from __future__ import annotations

from contextlib import asynccontextmanager
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from mcp.client import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import TextContent, Tool
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _pkg_dir in (
    REPO_ROOT / "server" / "secops",
    REPO_ROOT / "server" / "gti",
    REPO_ROOT / "server" / "secops-soar",
    REPO_ROOT / "server" / "secops-soar" / "secops_soar_mcp",
    REPO_ROOT / "server" / "scc",
):
    _pkg_str = str(_pkg_dir)
    if _pkg_str not in sys.path:
        sys.path.insert(0, _pkg_str)

from gti_mcp.server import server as gti_server  # noqa: E402
import scc_mcp  # noqa: E402
from secops_mcp.server import server as secops_server  # noqa: E402
from secops_soar_mcp import bindings as soar_bindings  # noqa: E402
from secops_soar_mcp import case_management as soar_case_mgmt  # noqa: E402
from secops_soar_mcp import server as soar_server_mod  # noqa: E402

scc_server = scc_mcp.mcp
MARKETPLACE_DIR = (
    REPO_ROOT / "server" / "secops-soar" / "secops_soar_mcp" / "marketplace"
)

SERVERS: list[tuple[str, MCPServer]] = [
    ("secops-mcp", secops_server),
    ("gti-mcp", gti_server),
    ("secops-soar-mcp", soar_server_mod.mcp),
    ("scc-mcp", scc_server),
]


@pytest.fixture(scope="module", autouse=True)
def _register_sample_soar_marketplace_integrations() -> None:
    """Register representative SOAR marketplace integrations on secops-soar-mcp."""
    soar_server_mod.register_tools("CSV,ActiveDirectory,Siemplify,VirusTotal,VirusTotalV3")


@pytest.fixture(scope="module")
def full_marketplace_server() -> MCPServer:
    """Build an MCPServer with all 294 SOAR marketplace modules registered."""
    srv = MCPServer("secops-soar-marketplace-audit")
    module_files = sorted(
        path for path in MARKETPLACE_DIR.glob("*.py") if path.name != "__init__.py"
    )
    assert len(module_files) == 294
    for path in module_files:
        safe_stem = path.stem.replace(".", "_")
        mod_name = f"secops_soar_mcp.marketplace._audit_{safe_stem}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.register_tools(srv)
    return srv


@pytest.fixture(scope="module")
def core_soar_tool_names() -> set[str]:
    """Return the exact set of 17 core SOAR case_management tool names."""
    srv = MCPServer("secops-soar-core-only")
    soar_case_mgmt.register_tools(srv)
    return {tool.name for tool in srv._tool_manager.list_tools()}


def _assert_tool_annotations_and_schema_budget(
    server_label: str,
    tools: list[Tool],
) -> None:
    """Verify every tool has title, full ToolAnnotations booleans, and <2 KB output_schema."""
    missing_title: list[str] = []
    missing_annotations: list[str] = []
    invalid_hint_types: list[str] = []
    contradictory_hints: list[str] = []
    missing_output_schema: list[str] = []
    oversized_output_schema: list[str] = []

    for tool in tools:
        if not isinstance(tool.title, str) or not tool.title.strip():
            missing_title.append(tool.name)
        ann = tool.annotations
        if ann is None:
            missing_annotations.append(tool.name)
        else:
            if ann.title != tool.title:
                missing_title.append(f"{tool.name} (annotations.title={ann.title!r})")
            for attr in (
                "read_only_hint",
                "destructive_hint",
                "idempotent_hint",
                "open_world_hint",
            ):
                val = getattr(ann, attr, None)
                if not isinstance(val, bool):
                    invalid_hint_types.append(f"{tool.name}.{attr}={val!r}")
            if ann.read_only_hint is True and ann.destructive_hint is True:
                contradictory_hints.append(tool.name)

        if tool.output_schema is None:
            missing_output_schema.append(tool.name)
        else:
            serialized = json.dumps(tool.output_schema)
            if len(serialized.encode("utf-8")) >= 2048:
                oversized_output_schema.append(
                    f"{tool.name} ({len(serialized.encode('utf-8'))} B)"
                )

    assert not missing_title, f"{server_label} tools missing title: {missing_title[:15]}"
    assert not missing_annotations, (
        f"{server_label} tools missing ToolAnnotations: {missing_annotations[:15]}"
    )
    assert not invalid_hint_types, (
        f"{server_label} tools with non-bool hints: {invalid_hint_types[:15]}"
    )
    assert not contradictory_hints, (
        f"{server_label} tools both read_only and destructive: {contradictory_hints[:15]}"
    )
    assert not missing_output_schema, (
        f"{server_label} tools missing output_schema: {missing_output_schema[:15]}"
    )
    assert not oversized_output_schema, (
        f"{server_label} tools exceeding 2048-byte output_schema budget: "
        f"{oversized_output_schema[:15]}"
    )


def _extract_error_json(result: Any) -> dict[str, Any]:
    """Assert CallToolResult signals is_error=True with structured JSON error text."""
    assert result.is_error is True
    assert len(result.content) >= 1
    first = result.content[0]
    assert isinstance(first, TextContent)
    parsed = json.loads(first.text)
    assert isinstance(parsed, dict)
    assert isinstance(parsed.get("error"), str) and parsed["error"].strip()
    if result.structured_content is not None:
        assert isinstance(result.structured_content, dict)
        assert result.structured_content.get("error") == parsed["error"]
    return parsed


# ---------------------------------------------------------------------------
# 1. 100% ToolAnnotations, title, open_world_hint, and <2 KB output_schema
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("server_name", "server_instance"),
    SERVERS,
    ids=[entry[0] for entry in SERVERS],
)
async def test_100_percent_tool_annotations_title_and_schema_budget(
    server_name: str,
    server_instance: MCPServer,
) -> None:
    """Verify every registered tool across all 4 servers has title, annotations, and <2 KB schema."""
    async with Client(server_instance) as client:
        tools = (await client.list_tools()).tools

    expected_minimums = {
        "secops-mcp": 69,
        "gti-mcp": 36,
        "secops-soar-mcp": 40,
        "scc-mcp": 6,
    }
    assert len(tools) >= expected_minimums[server_name]
    _assert_tool_annotations_and_schema_budget(server_name, tools)


@pytest.mark.asyncio
async def test_all_294_soar_marketplace_modules_annotations_and_schema_budget(
    full_marketplace_server: MCPServer,
) -> None:
    """Verify all 2,123 tools across all 294 SOAR marketplace modules satisfy Phase 3 invariants."""
    async with Client(full_marketplace_server) as client:
        tools = (await client.list_tools()).tools

    assert len(tools) == 2123
    _assert_tool_annotations_and_schema_budget("secops-soar-marketplace-all", tools)


@pytest.mark.asyncio
async def test_security_annotation_invariants_across_all_servers(
    core_soar_tool_names: set[str],
) -> None:
    """Spot-check read-only, destructive, non-idempotent, and open_world_hint security invariants."""
    tools_by_server: dict[str, dict[str, Tool]] = {}
    for server_name, server_instance in SERVERS:
        async with Client(server_instance) as client:
            listed = (await client.list_tools()).tools
        tools_by_server[server_name] = {tool.name: tool for tool in listed}

    assert len(core_soar_tool_names) == 17

    # Read-only invariants (read_only_hint=True, destructive_hint=False, idempotent_hint=True)
    read_only_checks = [
        ("secops-mcp", "search_security_events"),
        ("secops-mcp", "search_udm"),
        ("secops-mcp", "get_ioc_matches"),
        ("secops-mcp", "get_security_alerts"),
        ("secops-mcp", "validate_rule"),
        ("gti-mcp", "get_file_report"),
        ("gti-mcp", "get_domain_report"),
        ("gti-mcp", "search_threats"),
        ("secops-soar-mcp", "list_cases"),
        ("secops-soar-mcp", "get_case_full_details"),
        ("secops-soar-mcp", "active_directory_ping"),
        ("secops-soar-mcp", "active_directory_is_user_in_group"),
        ("secops-soar-mcp", "virus_total_v3_enrich_hash"),
        ("scc-mcp", "top_vulnerability_findings"),
        ("scc-mcp", "search_findings"),
    ]
    for srv_name, tool_name in read_only_checks:
        ann = tools_by_server[srv_name][tool_name].annotations
        assert ann is not None
        assert ann.read_only_hint is True, f"{srv_name}.{tool_name} must be read_only_hint=True"
        assert ann.destructive_hint is False, f"{srv_name}.{tool_name} must not be destructive"
        assert ann.idempotent_hint is True, f"{srv_name}.{tool_name} must be idempotent"

    # Destructive / containment / external-submission invariants
    destructive_checks = [
        ("secops-mcp", "delete_feed"),
        ("secops-mcp", "disable_feed"),
        ("secops-mcp", "delete_data_table_rows"),
        ("secops-mcp", "delete_watchlist"),
        ("secops-mcp", "deactivate_parser"),
        ("secops-mcp", "update_curated_rule_set_deployment"),
        ("secops-mcp", "update_rule_exclusion_deployment"),
        ("gti-mcp", "analyse_file"),
        ("secops-soar-mcp", "close_case"),
        ("secops-soar-mcp", "change_case_priority"),
        ("secops-soar-mcp", "remove_case_tag"),
        ("secops-soar-mcp", "active_directory_disable_account"),
        ("secops-soar-mcp", "virus_total_upload_and_scan_files"),
        ("scc-mcp", "set_finding_mute"),
    ]
    for srv_name, tool_name in destructive_checks:
        ann = tools_by_server[srv_name][tool_name].annotations
        assert ann is not None
        assert ann.read_only_hint is False, f"{srv_name}.{tool_name} must have read_only_hint=False"
        assert ann.destructive_hint is True, f"{srv_name}.{tool_name} must have destructive_hint=True"

    # Non-destructive append/create tools must have read_only_hint=False, destructive_hint=False, idempotent_hint=False
    non_idempotent_creates = [
        ("secops-mcp", "create_rule"),
        ("secops-mcp", "create_parser"),
        ("secops-mcp", "create_reference_list"),
        ("secops-soar-mcp", "create_case"),
        ("secops-soar-mcp", "post_case_comment"),
    ]
    for srv_name, tool_name in non_idempotent_creates:
        ann = tools_by_server[srv_name][tool_name].annotations
        assert ann is not None
        assert ann.read_only_hint is False
        assert ann.destructive_hint is False
        assert ann.idempotent_hint is False

    # open_world_hint invariants:
    # - All 36 gti-mcp tools query global/external threat intelligence -> True
    for tool_name, tool in tools_by_server["gti-mcp"].items():
        assert tool.annotations is not None
        assert tool.annotations.open_world_hint is True, f"gti-mcp.{tool_name}"

    # - All 69 secops-mcp and 6 scc-mcp tools are tenant-scoped -> False
    for srv_name in ("secops-mcp", "scc-mcp"):
        for tool_name, tool in tools_by_server[srv_name].items():
            assert tool.annotations is not None
            assert tool.annotations.open_world_hint is False, f"{srv_name}.{tool_name}"

    # - All 17 core secops-soar-mcp tools are tenant-scoped -> False
    for tool_name in core_soar_tool_names:
        tool = tools_by_server["secops-soar-mcp"][tool_name]
        assert tool.annotations is not None
        assert tool.annotations.open_world_hint is False, f"secops-soar-mcp.{tool_name}"

    # - External TI marketplace tools (VirusTotalV3) -> open_world_hint=True;
    #   internal enterprise directory tools (ActiveDirectory) -> open_world_hint=False
    assert (
        tools_by_server["secops-soar-mcp"]["virus_total_v3_enrich_hash"]
        .annotations.open_world_hint
        is True
    )
    assert (
        tools_by_server["secops-soar-mcp"]["active_directory_ping"]
        .annotations.open_world_hint
        is False
    )


# ---------------------------------------------------------------------------
# 2. Structured Output (structuredContent) Over Live MCP Client Calls
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secops_tools_emit_structured_content_over_mcp() -> None:
    """Verify previously string-only secops-mcp tools emit dict structured_content over MCP."""
    fake_chronicle = MagicMock()
    fake_chronicle.list_iocs.return_value = {
        "matches": [
            {
                "artifactIndicator": {"domain": "malicious.example"},
                "sources": ["Mandiant"],
            }
        ]
    }
    fake_chronicle.get_alerts.return_value = {
        "alerts": {
            "alerts": [
                {
                    "id": "de_a1b2c3d4",
                    "detection": [{"ruleName": "SuspiciousBeacon"}],
                    "createdTime": "2026-11-07T00:00:00Z",
                    "feedbackSummary": {
                        "status": "OPEN",
                        "verdict": "TRUE_POSITIVE",
                        "severityDisplay": "High",
                    },
                }
            ]
        }
    }
    validation_obj = MagicMock()
    validation_obj.success = True
    validation_obj.suggested_fields = ["principal.hostname"]
    fake_chronicle.validate_rule.return_value = validation_obj
    fake_chronicle.fetch_udm_search_csv.return_value = {
        "csv": {"row": ["metadata.event_type", "USER_LOGIN"]}
    }

    with (
        patch("secops_mcp.tools.ioc_matches.get_chronicle_client", return_value=fake_chronicle),
        patch("secops_mcp.tools.security_alerts.get_chronicle_client", return_value=fake_chronicle),
        patch("secops_mcp.tools.security_rules.get_chronicle_client", return_value=fake_chronicle),
        patch("secops_mcp.tools.udm_search.get_chronicle_client", return_value=fake_chronicle),
    ):
        async with Client(secops_server) as client:
            ioc_res = await client.call_tool(
                "get_ioc_matches",
                {"project_id": "proj-1", "customer_id": "a1b2c3d4-e5f6-4321-abcd-ef1234567890"},
            )
            alert_res = await client.call_tool(
                "get_security_alerts",
                {"project_id": "proj-1", "customer_id": "a1b2c3d4-e5f6-4321-abcd-ef1234567890"},
            )
            val_res = await client.call_tool(
                "validate_rule",
                {"rule_text": "rule r { condition: true }", "project_id": "proj-1"},
            )
            csv_res = await client.call_tool(
                "export_udm_search_csv",
                {
                    "query": 'metadata.event_type = "USER_LOGIN"',
                    "fields": ["metadata.event_type"],
                    "project_id": "proj-1",
                },
            )

    assert ioc_res.is_error is False
    assert isinstance(ioc_res.structured_content, dict)
    assert ioc_res.structured_content["count"] == 1
    assert "malicious.example" in ioc_res.structured_content["summary"]

    assert alert_res.is_error is False
    assert isinstance(alert_res.structured_content, dict)
    assert alert_res.structured_content["count"] == 1
    assert "SuspiciousBeacon" in alert_res.structured_content["summary"]

    assert val_res.is_error is False
    assert isinstance(val_res.structured_content, dict)
    assert val_res.structured_content["valid"] is True
    assert "Rule validation PASSED" in val_res.structured_content["summary"]

    assert csv_res.is_error is False
    assert isinstance(csv_res.structured_content, dict)
    assert csv_res.structured_content["row_count"] == 2
    assert "USER_LOGIN" in csv_res.structured_content["csv"]


@pytest.mark.asyncio
async def test_gti_soar_and_scc_tools_emit_structured_content_over_mcp() -> None:
    """Verify gti-mcp, secops-soar-mcp, and scc-mcp emit dict structured_content over MCP."""
    # 1. gti-mcp: get_file_report and get_collections_commonalities
    fake_vt_resp = MagicMock()
    fake_vt_resp.json_async = AsyncMock(
        return_value={
            "data": {
                "id": "col-123",
                "attributes": {
                    "aggregations": {
                        "domains": {
                            "registrar": [{"value": "ExampleRegistrar", "count": 3}]
                        }
                    }
                },
            }
        }
    )
    fake_vt_client = MagicMock()
    fake_vt_client.get_async = AsyncMock(return_value=fake_vt_resp)

    @asynccontextmanager
    async def _fake_vt_cm(_ctx: Any):
        yield fake_vt_client

    with (
        patch("gti_mcp.tools.files.vt_client", _fake_vt_cm),
        patch(
            "gti_mcp.tools.files.utils.fetch_object",
            new=AsyncMock(return_value={"id": "sha256-demo", "type": "file"}),
        ),
        patch("gti_mcp.tools.collections.vt_client", _fake_vt_cm),
    ):
        async with Client(gti_server) as client:
            file_res = await client.call_tool("get_file_report", {"hash": "44d88612fea8a8f36de82e1278abb02f"})
            comm_res = await client.call_tool("get_collections_commonalities", {"collection_id": "col-123"})

    assert file_res.is_error is False
    assert isinstance(file_res.structured_content, dict)
    assert file_res.structured_content["id"] == "sha256-demo"

    assert comm_res.is_error is False
    assert isinstance(comm_res.structured_content, dict)
    assert comm_res.structured_content["collection_id"] == "col-123"
    assert isinstance(comm_res.structured_content["summary"], str)

    # 2. secops-soar-mcp: list_cases (list normalized into {"items": ..., "count": ...})
    fake_soar_http = MagicMock()
    fake_soar_http.get = AsyncMock(return_value=[{"Id": 101, "Title": "Suspicious Beacon"}])
    with patch.object(soar_bindings, "http_client", fake_soar_http):
        async with Client(soar_server_mod.mcp) as client:
            cases_res = await client.call_tool("list_cases", {})

    assert cases_res.is_error is False
    assert isinstance(cases_res.structured_content, dict)
    assert cases_res.structured_content["count"] == 1
    assert cases_res.structured_content["items"][0]["Id"] == 101

    # 3. scc-mcp: top_vulnerability_findings
    fake_scc_client = MagicMock()
    empty_page = MagicMock()
    empty_page.list_findings_results = []
    fake_pager = MagicMock()
    fake_pager.pages = [empty_page]
    fake_scc_client.list_findings.return_value = fake_pager

    with patch.object(scc_mcp, "scc_client", fake_scc_client):
        async with Client(scc_server) as client:
            scc_res = await client.call_tool(
                "top_vulnerability_findings",
                {"project_id": "demo-project", "max_findings": 5},
            )

    assert scc_res.is_error is False
    assert isinstance(scc_res.structured_content, dict)
    assert scc_res.structured_content["count"] == 0
    assert scc_res.structured_content["top_findings"] == []


# ---------------------------------------------------------------------------
# 3. True is_error=True Failure Signaling Across All 4 Servers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secops_error_paths_set_is_error_true_over_mcp() -> None:
    """Verify upstream exceptions and input validation failures set is_error=True on secops-mcp."""
    failing_chronicle = MagicMock()
    failing_chronicle.search_udm.side_effect = RuntimeError("Chronicle backend unavailable")

    with patch(
        "secops_mcp.tools.security_events.get_chronicle_client",
        return_value=failing_chronicle,
    ):
        async with Client(secops_server) as client:
            upstream_err = await client.call_tool(
                "search_security_events",
                {"text": " suspicious login ", "project_id": "proj-1"},
            )
            validation_err = await client.call_tool(
                "export_udm_search_csv",
                {
                    "query": 'metadata.event_type = "USER_LOGIN"',
                    "fields": ["metadata.event_type"],
                    "start_time": "not-an-iso-date",
                    "project_id": "proj-1",
                },
            )

    parsed_upstream = _extract_error_json(upstream_err)
    assert "Chronicle backend unavailable" in parsed_upstream["error"]

    parsed_validation = _extract_error_json(validation_err)
    assert "Error parsing date format" in parsed_validation["error"]


@pytest.mark.asyncio
async def test_gti_error_paths_set_is_error_true_over_mcp() -> None:
    """Verify upstream API error dicts and invalid parameters set is_error=True on gti-mcp."""
    fake_vt_client = MagicMock()

    @asynccontextmanager
    async def _fake_vt_cm(_ctx: Any):
        yield fake_vt_client

    with (
        patch("gti_mcp.tools.files.vt_client", _fake_vt_cm),
        patch(
            "gti_mcp.tools.files.utils.fetch_object",
            new=AsyncMock(return_value={"error": "VirusTotal quota exceeded"}),
        ),
    ):
        async with Client(gti_server) as client:
            api_err = await client.call_tool(
                "get_file_report",
                {"hash": "44d88612fea8a8f36de82e1278abb02f"},
            )
            bad_type_err = await client.call_tool(
                "search_threats",
                {"query": "ransomware", "collection_type": "invalid-type"},
            )

    parsed_api = _extract_error_json(api_err)
    assert "VirusTotal quota exceeded" in parsed_api["error"]

    parsed_bad_type = _extract_error_json(bad_type_err)
    assert "unknown collection_type" in parsed_bad_type["error"]


@pytest.mark.asyncio
async def test_soar_error_paths_set_is_error_true_over_mcp() -> None:
    """Verify uninitialized client and upstream exceptions set is_error=True on secops-soar-mcp."""
    with patch.object(soar_bindings, "http_client", None):
        async with Client(soar_server_mod.mcp) as client:
            uninit_err = await client.call_tool("list_cases", {})

    parsed_uninit = _extract_error_json(uninit_err)
    assert "not initialized" in parsed_uninit["error"]

    failing_http = MagicMock()
    failing_http.post = AsyncMock(side_effect=RuntimeError("SOAR 503 Service Unavailable"))
    with patch.object(soar_bindings, "http_client", failing_http):
        async with Client(soar_server_mod.mcp) as client:
            post_err = await client.call_tool(
                "close_case",
                {
                    "case_id": "42",
                    "root_cause": "Benign",
                    "comment": "Closing benign test alert",
                    "reason": "Maintenance",
                },
            )

    parsed_post = _extract_error_json(post_err)
    assert "SOAR 503 Service Unavailable" in parsed_post["error"]


@pytest.mark.asyncio
async def test_scc_error_paths_set_is_error_true_over_mcp() -> None:
    """Verify input validation and Google API exceptions set is_error=True on scc-mcp."""
    failing_scc = MagicMock()
    failing_scc.list_findings.side_effect = RuntimeError("SCC gRPC deadline exceeded")

    with patch.object(scc_mcp, "scc_client", failing_scc):
        async with Client(scc_server) as client:
            missing_scope_err = await client.call_tool(
                "top_vulnerability_findings",
                {},
            )
            rpc_err = await client.call_tool(
                "set_finding_mute",
                {
                    "project_id": "demo-project",
                    "finding_id": "finding-123",
                    "mute": "MUTED",
                },
            )

    parsed_missing = _extract_error_json(missing_scope_err)
    assert "project_id or organization_id" in parsed_missing["error"]

    parsed_rpc = _extract_error_json(rpc_err)
    assert "An unexpected error occurred" in parsed_rpc["error"]
    assert "SCC gRPC deadline exceeded" in parsed_rpc.get("details", "")
