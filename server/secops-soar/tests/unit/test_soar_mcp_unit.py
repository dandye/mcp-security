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
"""Offline unit tests for SecOps SOAR MCP server over mcp 2.3 Client."""

from __future__ import annotations

import importlib
import json
from types import ModuleType
from unittest.mock import AsyncMock, patch

import mcp
from mcp.client import Client
from mcp.server.mcpserver import MCPServer
import pytest

from secops_soar_mcp import bindings
from secops_soar_mcp import server as soar_server_mod
from secops_soar_mcp.case_management import register_tools as register_case_tools


@pytest.mark.asyncio
async def test_soar_mcp_server_metadata_and_tool_listing() -> None:
    """Verify Client(mcp_server) negotiates 2026-07-28 and lists case tools."""
    async with Client(soar_server_mod.mcp) as client:
        assert client.protocol_version == "2026-07-28"
        assert client.server_info is not None
        assert client.server_info.name == "secops-soar-mcp"
        assert client.server_info.title == "Google Security Operations SOAR MCP Server"
        assert client.server_info.version == "0.3.0"
        assert str(client.server_info.website_url) == "https://github.com/google/mcp-security"
        assert client.instructions is not None
        assert "list_cases" in client.instructions

        tools_result = await client.list_tools()
        assert isinstance(tools_result, mcp.ListToolsResult)
        tool_names = {tool.name for tool in tools_result.tools}
        assert {
            "list_cases",
            "create_case",
            "get_case_full_details",
            "post_case_comment",
            "close_case",
        }.issubset(tool_names)
        for tool in tools_result.tools:
            assert isinstance(tool.input_schema, dict)
            assert tool.title and tool.title.strip()
            assert tool.annotations is not None
            assert isinstance(tool.annotations.read_only_hint, bool)
            assert isinstance(tool.annotations.destructive_hint, bool)
            assert isinstance(tool.annotations.open_world_hint, bool)
            assert tool.output_schema is not None
            assert len(json.dumps(tool.output_schema)) < 2048


@pytest.mark.asyncio
async def test_soar_case_tools_via_in_memory_client() -> None:
    """Verify list_cases and create_case accept explicit null optional params and emit structured_content."""
    isolated_mcp = MCPServer(name="secops-soar-test")
    register_case_tools(isolated_mcp)

    fake_http = AsyncMock()
    fake_http.get.return_value = {"cases": [{"id": "42", "title": "Suspicious Beacon"}]}
    fake_http.post.return_value = {"id": "43", "Name": "Manual Hunt Case"}

    with patch.object(bindings, "http_client", fake_http):
        async with Client(isolated_mcp) as client:
            list_res = await client.call_tool("list_cases", {"next_page_token": None})
            assert list_res.is_error is False
            assert list_res.structured_content == {"cases": [{"id": "42", "title": "Suspicious Beacon"}]}
            payload = json.loads(list_res.content[0].text)
            assert payload == {"cases": [{"id": "42", "title": "Suspicious Beacon"}]}

            create_res = await client.call_tool(
                "create_case",
                {
                    "name": "Manual Hunt Case",
                    "priority": None,
                    "description": None,
                    "environment": None,
                },
            )
            assert create_res.is_error is False
            assert isinstance(create_res.structured_content, dict)
            assert create_res.structured_content["id"] == "43"
            created = json.loads(create_res.content[0].text)
            assert created["id"] == "43"
            fake_http.post.assert_awaited_once()
            _, kwargs = fake_http.post.await_args
            assert kwargs["req"] == {"Name": "Manual Hunt Case"}


@pytest.mark.asyncio
async def test_soar_case_tools_error_signaling() -> None:
    """Verify missing client, HTTP None responses, and exceptions set is_error=True."""
    isolated_mcp = MCPServer(name="secops-soar-error-test")
    register_case_tools(isolated_mcp)

    with patch.object(bindings, "http_client", None):
        async with Client(isolated_mcp) as client:
            no_client_res = await client.call_tool("list_cases", {})
            assert no_client_res.is_error is True
            assert "error" in json.loads(no_client_res.content[0].text)

    failing_http = AsyncMock()
    failing_http.get.return_value = None
    failing_http.post.side_effect = RuntimeError("SOAR backend 503")

    with patch.object(bindings, "http_client", failing_http):
        async with Client(isolated_mcp) as client:
            none_res = await client.call_tool("list_cases", {})
            assert none_res.is_error is True
            assert "error" in json.loads(none_res.content[0].text)

            exc_res = await client.call_tool(
                "close_case",
                {
                    "case_id": "42",
                    "root_cause": "Test",
                    "comment": "Closing",
                    "reason": "NotMalicious",
                },
            )
            assert exc_res.is_error is True
            err_payload = json.loads(exc_res.content[0].text)
            assert "SOAR backend 503" in err_payload["error"]


@pytest.mark.asyncio
async def test_register_tools_package_import_and_cwd_fallback() -> None:
    """Verify dynamic marketplace loading tries package import then fallback."""
    isolated_mcp = MCPServer(name="secops-soar-marketplace-test")
    register_case_tools(isolated_mcp)

    with patch.object(soar_server_mod, "mcp", isolated_mcp):
        soar_server_mod.register_tools("CSV,Tenable.io")

    async with Client(isolated_mcp) as client:
        tools_result = await client.list_tools()
        names = {t.name for t in tools_result.tools}
        assert any(name.startswith("csv_") for name in names)
        assert any(name.startswith("tenable_io_") for name in names)

    # Also verify fallback to bare `marketplace.<stem>` when package path raises ModuleNotFoundError.
    fallback_mcp = MCPServer(name="secops-soar-fallback-test")
    fallback_called = []

    fake_mod = ModuleType("marketplace.csv")

    def _fake_register(server: MCPServer) -> None:
        fallback_called.append(server)

    fake_mod.register_tools = _fake_register  # type: ignore[attr-defined]
    real_import = importlib.import_module

    def _import_side_effect(name: str, *args, **kwargs):
        if name == "secops_soar_mcp.marketplace.csv":
            raise ModuleNotFoundError(f"No module named '{name}'")
        if name == "marketplace.csv":
            return fake_mod
        return real_import(name, *args, **kwargs)

    with (
        patch.object(soar_server_mod, "mcp", fallback_mcp),
        patch("secops_soar_mcp.server.importlib.import_module", side_effect=_import_side_effect),
    ):
        soar_server_mod.register_tools("CSV")

    assert fallback_called == [fallback_mcp]
