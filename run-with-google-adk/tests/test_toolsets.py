"""Unit tests for mcp_security_agent.toolsets."""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add src directory to path
src_dir = str(Path(__file__).resolve().parents[1] / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Mock google.adk.tools.mcp_tool modules
mock_mcp_toolset_mod = MagicMock()
mock_mcp_session_manager = MagicMock()
mock_adk = MagicMock()
mock_adk_tools = MagicMock()
mock_adk_tools_mcp = MagicMock()

mock_adk_tools_mcp.mcp_toolset = mock_mcp_toolset_mod
mock_adk_tools_mcp.mcp_session_manager = mock_mcp_session_manager

sys.modules["google.adk"] = mock_adk
sys.modules["google.adk.tools"] = mock_adk_tools
sys.modules["google.adk.tools.mcp_tool"] = mock_adk_tools_mcp
sys.modules["google.adk.tools.mcp_tool.mcp_toolset"] = mock_mcp_toolset_mod
sys.modules["google.adk.tools.mcp_tool.mcp_session_manager"] = mock_mcp_session_manager


from mcp_security_agent.config import AgentSettings
from mcp_security_agent.toolsets import (
    BLOAT_FEED_TOOLS,
    build_mcp_toolsets,
    filter_bloat_feed_tools,
    get_default_gcp_header_provider,
)


def test_build_toolsets_none_enabled():
    settings = AgentSettings()
    toolsets = build_mcp_toolsets(settings)
    assert toolsets == []


def test_build_toolsets_stdio_secops_and_scc():
    settings = AgentSettings(LOAD_SECOPS_MCP="Y", LOAD_SCC_MCP="Y")
    mock_mcp_toolset_mod.McpToolset = MagicMock(side_effect=lambda *args, **kwargs: MagicMock())
    mock_mcp_session_manager.StdioConnectionParams.reset_mock()
    
    toolsets = build_mcp_toolsets(settings)
    assert len(toolsets) == 2
    assert mock_mcp_session_manager.StdioConnectionParams.call_count >= 2



def test_filter_bloat_feed_tools():
    # Bloat feed tools must be filtered out
    class DummyTool:
        def __init__(self, name: str):
            self.name = name

    for feed_tool in BLOAT_FEED_TOOLS:
        assert filter_bloat_feed_tools(DummyTool(feed_tool)) is False

    # Detection, search, and entity tools must be kept
    assert filter_bloat_feed_tools(DummyTool("udm_search")) is True
    assert filter_bloat_feed_tools(DummyTool("lookup_entity")) is True
    assert filter_bloat_feed_tools(DummyTool("list_security_alerts")) is True


def test_build_toolsets_canonical_features():
    settings = AgentSettings(
        LOAD_SECOPS_MCP="Y",
        LOAD_GTI_MCP="Y",
        ENABLE_TOOL_PREFIXING="Y",
        TOOL_LIST_CACHE_TTL_SECONDS=120.0,
        USE_MCP_RESOURCES="Y",
        REQUIRE_CONFIRMATION="Y",
    )
    captured_kwargs = []
    mock_mcp_toolset_mod.McpToolset = MagicMock(
        side_effect=lambda *args, **kwargs: captured_kwargs.append(kwargs) or MagicMock()
    )

    toolsets = build_mcp_toolsets(settings)
    assert len(toolsets) == 2

    # Check secops toolset
    secops_kwargs = captured_kwargs[0]
    assert secops_kwargs["tool_name_prefix"] == "secops_"
    assert secops_kwargs["tool_list_cache_ttl_seconds"] == 120.0
    assert secops_kwargs["use_mcp_resources"] is True
    assert secops_kwargs["require_confirmation"] is True
    assert callable(secops_kwargs["tool_filter"])

    # Check GTI toolset
    gti_kwargs = captured_kwargs[1]
    assert gti_kwargs["tool_name_prefix"] == "gti_"
    assert gti_kwargs["tool_list_cache_ttl_seconds"] == 120.0
    assert gti_kwargs["use_mcp_resources"] is True


def test_build_toolsets_remote_url():
    settings = AgentSettings(
        LOAD_SECOPS_MCP="Y",
        SECOPS_MCP_URL="https://chronicle.us.rep.googleapis.com/mcp",
    )
    captured_kwargs = []
    mock_mcp_toolset_mod.McpToolset = MagicMock(
        side_effect=lambda *args, **kwargs: captured_kwargs.append(kwargs) or MagicMock()
    )

    toolsets = build_mcp_toolsets(settings)
    assert len(toolsets) == 1
    kwargs = captured_kwargs[0]
    assert kwargs["header_provider"] is not None
    assert callable(kwargs["header_provider"])

