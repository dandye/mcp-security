# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unit and contract tests for Antigravity Native MCP PoC."""

from pathlib import Path
import pytest
from pydantic import ValidationError

from google.antigravity import LocalAgentConfig
from google.antigravity.hooks import policy
from google.antigravity.types import McpStdioServer, McpStreamableHttpServer

# Import PoC helper
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from poc_native_mcp import build_server_configs


def test_mcp_stdio_server_construction():
    """Verifies that McpStdioServer creates properly with valid attributes."""
    server = McpStdioServer(
        name="secops",
        command="uv",
        args=["run", "secops-mcp"],
        timeout_seconds=45,
        enabled_tools=["lookup_entity", "search_udm"],
    )
    assert server.name == "secops"
    assert server.type == "stdio"
    assert server.command == "uv"
    assert server.args == ["run", "secops-mcp"]
    assert server.timeout_seconds == 45
    assert server.enabled_tools == ["lookup_entity", "search_udm"]
    assert server.disabled_tools is None


def test_mcp_streamable_http_server_construction():
    """Verifies that McpStreamableHttpServer creates properly for remote OneMCP."""
    server = McpStreamableHttpServer(
        name="chronicle_remote",
        url="https://chronicle.us.rep.googleapis.com/mcp",
        headers={"Authorization": "Bearer test-token"},
        timeout=30.0,
        disabled_tools=["create_feed", "update_feed"],
    )
    assert server.name == "chronicle_remote"
    assert server.type == "http"
    assert server.url == "https://chronicle.us.rep.googleapis.com/mcp"
    assert server.headers == {"Authorization": "Bearer test-token"}
    assert server.disabled_tools == ["create_feed", "update_feed"]


def test_mcp_server_mutually_exclusive_tool_filters():
    """Verifies that enabled_tools and disabled_tools cannot both be specified."""
    with pytest.raises(ValidationError):
        McpStdioServer(
            name="invalid_server",
            command="uv",
            enabled_tools=["tool_a"],
            disabled_tools=["tool_b"],
        )


def test_build_server_configs_modes():
    """Verifies build_server_configs generates the appropriate server suites."""
    repo_root = Path(__file__).resolve().parent.parent.parent

    gti_only = build_server_configs("gti", repo_root)
    assert len(gti_only) == 1
    assert gti_only[0].name == "gti"
    assert "search_threats" in gti_only[0].enabled_tools

    secops_only = build_server_configs("secops", repo_root)
    assert len(secops_only) == 1
    assert secops_only[0].name == "secops"
    assert "create_feed" in secops_only[0].disabled_tools

    both = build_server_configs("both", repo_root)
    assert len(both) == 2
    server_names = {s.name for s in both}
    assert server_names == {"gti", "secops"}


def test_local_agent_config_with_mcp_and_policies():
    """Verifies LocalAgentConfig accepts native MCP servers and policy guardrails."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    servers = build_server_configs("both", repo_root)

    deny_policy = policy.deny("secops/delete_data_table_rows")
    allow_policy = policy.allow("secops/search_udm")

    config = LocalAgentConfig(
        model="gemini-2.5-flash",
        vertex=True,
        project="secops-demo-env",
        location="us-central1",
        mcp_servers=servers,
        policies=[deny_policy, allow_policy],
    )

    assert len(config.mcp_servers) == 2
    assert config.vertex is True
    assert config.project == "secops-demo-env"
    assert config.location == "us-central1"
