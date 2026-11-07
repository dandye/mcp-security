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
"""Cross-server MCP 2026-07-28 protocol contract suite across all 4 servers."""

from __future__ import annotations

from pathlib import Path
import re
import sys
from typing import Any

import jsonschema
from mcp.client import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import LATEST_PROTOCOL_VERSION
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _pkg_dir in (
    REPO_ROOT / "server" / "secops",
    REPO_ROOT / "server" / "gti",
    REPO_ROOT / "server" / "secops-soar",
    REPO_ROOT / "server" / "scc",
):
    _pkg_str = str(_pkg_dir)
    if _pkg_str not in sys.path:
        sys.path.insert(0, _pkg_str)

from gti_mcp.server import server as gti_server  # noqa: E402
from scc_mcp import mcp as scc_server  # noqa: E402
from secops_mcp.server import server as secops_server  # noqa: E402
from secops_soar_mcp import server as soar_server_mod  # noqa: E402

SEP_986_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

EXPECTED_SERVERS: list[tuple[str, MCPServer, str, str]] = [
    (
        "secops-mcp",
        secops_server,
        "0.9.0",
        "Google Security Operations SIEM MCP Server",
    ),
    (
        "gti-mcp",
        gti_server,
        "0.2.0",
        "Google Threat Intelligence MCP Server",
    ),
    (
        "secops-soar-mcp",
        soar_server_mod.mcp,
        "0.3.0",
        "Google Security Operations SOAR MCP Server",
    ),
    (
        "scc-mcp",
        scc_server,
        "0.3.0",
        "Google Cloud Security Command Center MCP Server",
    ),
]


@pytest.fixture(scope="module", autouse=True)
def _register_sample_soar_marketplace_integrations() -> None:
    """Register representative SOAR marketplace integrations for contract checks."""
    soar_server_mod.register_tools("CSV,ActiveDirectory,Siemplify")


def _schema_accepts_null(prop_schema: dict[str, Any]) -> bool:
    """Return True if a JSON Schema property definition permits null values."""
    prop_type = prop_schema.get("type")
    if prop_type == "null":
        return True
    if isinstance(prop_type, list) and "null" in prop_type:
        return True
    for keyword in ("anyOf", "oneOf"):
        for branch in prop_schema.get(keyword, []):
            if isinstance(branch, dict) and _schema_accepts_null(branch):
                return True
    return False


def test_latest_protocol_version_is_2026_07_28() -> None:
    """Ensure the installed mcp SDK targets MCP specification 2026-07-28."""
    assert LATEST_PROTOCOL_VERSION == "2026-07-28"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("expected_name", "server_instance", "expected_version", "expected_title"),
    EXPECTED_SERVERS,
    ids=[entry[0] for entry in EXPECTED_SERVERS],
)
async def test_server_initialize_metadata_contract(
    expected_name: str,
    server_instance: MCPServer,
    expected_version: str,
    expected_title: str,
) -> None:
    """Verify every MCPServer exposes 2026-07-28 discovery metadata and instructions."""
    assert isinstance(server_instance, MCPServer)

    async with Client(server_instance) as client:
        assert client.protocol_version == "2026-07-28"
        info = client.server_info
        assert info is not None
        assert info.name == expected_name
        assert info.title == expected_title
        assert info.version == expected_version
        assert str(info.website_url) == "https://github.com/google/mcp-security"
        assert isinstance(info.description, str) and info.description.strip()
        assert isinstance(client.instructions, str) and client.instructions.strip()

        if expected_name == "secops-mcp":
            assert "YARA-L 2.0" in client.instructions
        elif expected_name == "gti-mcp":
            assert "standard YARA" in client.instructions


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("expected_name", "server_instance", "_version", "_title"),
    EXPECTED_SERVERS,
    ids=[entry[0] for entry in EXPECTED_SERVERS],
)
async def test_registered_tools_sep986_and_json_schema_2020_12_contract(
    expected_name: str,
    server_instance: MCPServer,
    _version: str,
    _title: str,
) -> None:
    """Verify every registered tool satisfies SEP-986, Draft 2020-12, and nullable typing."""
    async with Client(server_instance) as client:
        tools_result = await client.list_tools()

    assert len(tools_result.tools) > 0, f"{expected_name} registered zero tools"

    if expected_name == "secops-soar-mcp":
        tool_names = {t.name for t in tools_result.tools}
        assert any(name.startswith("csv_") for name in tool_names)
        assert any(name.startswith("active_directory_") for name in tool_names)
        assert any(name.startswith("siemplify_") for name in tool_names)

    invalid_names: list[str] = []
    invalid_schemas: list[str] = []
    non_nullable_none_defaults: list[str] = []

    for tool in tools_result.tools:
        if not SEP_986_TOOL_NAME_RE.fullmatch(tool.name):
            invalid_names.append(tool.name)

        schema = tool.input_schema
        if not isinstance(schema, dict):
            invalid_schemas.append(f"{tool.name}: input_schema is {type(schema).__name__}")
            continue

        try:
            jsonschema.Draft202012Validator.check_schema(schema)
        except jsonschema.exceptions.SchemaError as exc:
            invalid_schemas.append(f"{tool.name}: {exc.message}")

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for param_name, prop_schema in properties.items():
                if not isinstance(prop_schema, dict):
                    continue
                if "default" in prop_schema and prop_schema["default"] is None:
                    if not _schema_accepts_null(prop_schema):
                        non_nullable_none_defaults.append(
                            f"{expected_name}:{tool.name}.{param_name} -> {prop_schema}"
                        )

    assert invalid_names == [], f"Non-SEP-986 tool names in {expected_name}: {invalid_names}"
    assert invalid_schemas == [], f"Invalid JSON Schemas in {expected_name}: {invalid_schemas}"
    assert non_nullable_none_defaults == [], (
        f"Parameters with default=None missing null type in {expected_name}: "
        f"{non_nullable_none_defaults}"
    )
