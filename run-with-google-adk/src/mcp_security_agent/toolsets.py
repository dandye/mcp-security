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
"""Multi-transport MCP toolsets builder for Google ADK.

Follows Google ADK canonical McpToolset design patterns:
1. Tool namespacing via `tool_name_prefix` to prevent multi-server tool collision.
2. Tool filtering via `tool_filter` predicates or allowlists to eliminate schema bloat.
3. Dynamic authentication headers via `header_provider` for remote OneMCP servers.
4. Response caching via `tool_list_cache_ttl_seconds` to eliminate redundant turn discovery.
5. Resource exposure via `use_mcp_resources`.
6. Human-in-the-loop gating via `require_confirmation`.
"""

import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from mcp_security_agent.config import AgentSettings

logger = logging.getLogger(__name__)

# Canonical feed tools in SecOps that bloat prompt context by ~68%
BLOAT_FEED_TOOLS = frozenset({
    "create_feed",
    "update_feed",
    "run_parser",
    "list_feeds",
    "get_feed",
    "disable_feed",
    "enable_feed",
})


def get_default_gcp_header_provider() -> Callable[[Any], Dict[str, str]]:
    """Returns a canonical header provider callback that acquires active GCP bearer credentials."""
    def _header_provider(ctx: Any = None) -> Dict[str, str]:
        try:
            import google.auth
            import google.auth.transport.requests
            credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            request = google.auth.transport.requests.Request()
            credentials.refresh(request)
            if credentials.token:
                return {"Authorization": f"Bearer {credentials.token}"}
        except Exception as e:
            logger.debug("Failed to resolve GCP access token via google.auth: %s", e)
        return {}

    return _header_provider


def filter_bloat_feed_tools(tool: Any, readonly_context: Any = None) -> bool:
    """Filters out heavy feed tools to optimize Gemini prompt context."""
    tool_name = getattr(tool, "name", str(tool))
    return tool_name not in BLOAT_FEED_TOOLS


def build_mcp_toolsets(settings: AgentSettings) -> List[Any]:
    """Builds and returns all configured MCP toolsets using canonical ADK transports.

    Args:
        settings: Initialized AgentSettings instance.

    Returns:
        List of initialized MCP toolset objects for the ADK agent.
    """
    toolsets = []

    # Locate repo server directory relative to this package
    pkg_dir = Path(__file__).resolve().parents[2]  # run-with-google-adk
    repo_root = pkg_dir.parent
    server_dir = repo_root / "server"

    try:
        from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
        from google.adk.tools.mcp_tool.mcp_session_manager import (
            StdioConnectionParams,
            StreamableHTTPConnectionParams,
            SseConnectionParams,
        )
        from mcp import StdioServerParameters
    except ImportError:
        logger.warning("google.adk.tools.mcp_tool not available; using mock/fallback toolset representation.")
        return toolsets

    header_provider = get_default_gcp_header_provider()

    # 1. Google SecOps SIEM MCP
    if settings.load_secops_mcp:
        secops_prefix = "secops_" if settings.enable_tool_prefixing else None
        secops_filter = filter_bloat_feed_tools if settings.filter_feed_tools else None

        if settings.secops_mcp_url:
            logger.info("Configuring SecOps SIEM MCP via Remote URL: %s", settings.secops_mcp_url)
            if settings.secops_mcp_url.endswith("/sse"):
                conn = SseConnectionParams(
                    url=settings.secops_mcp_url,
                    timeout=settings.stdio_timeout_seconds,
                )
            else:
                conn = StreamableHTTPConnectionParams(
                    url=settings.secops_mcp_url,
                    timeout=settings.stdio_timeout_seconds,
                )
            toolsets.append(
                McpToolset(
                    connection_params=conn,
                    tool_name_prefix=secops_prefix,
                    tool_filter=secops_filter,
                    header_provider=header_provider,
                    tool_list_cache_ttl_seconds=settings.tool_list_cache_ttl_seconds,
                    use_mcp_resources=settings.use_mcp_resources,
                    require_confirmation=settings.require_confirmation,
                )
            )
        else:
            secops_dir = server_dir / "secops"
            logger.info("Configuring SecOps SIEM MCP via Stdio subprocess at %s", secops_dir)
            conn = StdioConnectionParams(
                server_params=StdioServerParameters(
                    command="uv",
                    args=["--directory", str(secops_dir), "run", "secops_mcp/server.py"],
                ),
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(
                McpToolset(
                    connection_params=conn,
                    tool_name_prefix=secops_prefix,
                    tool_filter=secops_filter,
                    tool_list_cache_ttl_seconds=settings.tool_list_cache_ttl_seconds,
                    use_mcp_resources=settings.use_mcp_resources,
                    require_confirmation=settings.require_confirmation,
                )
            )

    # 2. Security Command Center (SCC) MCP
    if settings.load_scc_mcp:
        scc_prefix = "scc_" if settings.enable_tool_prefixing else None
        if settings.scc_mcp_url:
            logger.info("Configuring SCC MCP via Remote URL: %s", settings.scc_mcp_url)
            conn = StreamableHTTPConnectionParams(
                url=settings.scc_mcp_url,
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(
                McpToolset(
                    connection_params=conn,
                    tool_name_prefix=scc_prefix,
                    header_provider=header_provider,
                    tool_list_cache_ttl_seconds=settings.tool_list_cache_ttl_seconds,
                    use_mcp_resources=settings.use_mcp_resources,
                    require_confirmation=settings.require_confirmation,
                )
            )
        else:
            scc_dir = server_dir / "scc"
            logger.info("Configuring SCC MCP via Stdio subprocess at %s", scc_dir)
            conn = StdioConnectionParams(
                server_params=StdioServerParameters(
                    command="uv",
                    args=["--directory", str(scc_dir), "run", "scc_mcp.py"],
                ),
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(
                McpToolset(
                    connection_params=conn,
                    tool_name_prefix=scc_prefix,
                    tool_list_cache_ttl_seconds=settings.tool_list_cache_ttl_seconds,
                    use_mcp_resources=settings.use_mcp_resources,
                    require_confirmation=settings.require_confirmation,
                )
            )

    # 3. Google Threat Intelligence (GTI) MCP
    if settings.load_gti_mcp:
        gti_prefix = "gti_" if settings.enable_tool_prefixing else None
        if settings.gti_mcp_url:
            logger.info("Configuring GTI MCP via Remote URL: %s", settings.gti_mcp_url)
            conn = StreamableHTTPConnectionParams(
                url=settings.gti_mcp_url,
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(
                McpToolset(
                    connection_params=conn,
                    tool_name_prefix=gti_prefix,
                    header_provider=header_provider,
                    tool_list_cache_ttl_seconds=settings.tool_list_cache_ttl_seconds,
                    use_mcp_resources=settings.use_mcp_resources,
                    require_confirmation=settings.require_confirmation,
                )
            )
        else:
            gti_dir = server_dir / "gti"
            logger.info("Configuring GTI MCP via Stdio subprocess at %s", gti_dir)
            conn = StdioConnectionParams(
                server_params=StdioServerParameters(
                    command="uv",
                    args=["--directory", str(gti_dir), "run", "gti_mcp/server.py"],
                ),
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(
                McpToolset(
                    connection_params=conn,
                    tool_name_prefix=gti_prefix,
                    tool_list_cache_ttl_seconds=settings.tool_list_cache_ttl_seconds,
                    use_mcp_resources=settings.use_mcp_resources,
                    require_confirmation=settings.require_confirmation,
                )
            )

    # 4. SecOps SOAR MCP
    if settings.load_secops_soar_mcp:
        soar_prefix = "soar_" if settings.enable_tool_prefixing else None
        if settings.secops_soar_mcp_url:
            logger.info("Configuring SecOps SOAR MCP via Remote URL: %s", settings.secops_soar_mcp_url)
            conn = StreamableHTTPConnectionParams(
                url=settings.secops_soar_mcp_url,
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(
                McpToolset(
                    connection_params=conn,
                    tool_name_prefix=soar_prefix,
                    header_provider=header_provider,
                    tool_list_cache_ttl_seconds=settings.tool_list_cache_ttl_seconds,
                    use_mcp_resources=settings.use_mcp_resources,
                    require_confirmation=settings.require_confirmation,
                )
            )
        else:
            soar_dir = server_dir / "secops-soar"
            logger.info("Configuring SecOps SOAR MCP via Stdio subprocess at %s", soar_dir)
            conn = StdioConnectionParams(
                server_params=StdioServerParameters(
                    command="uv",
                    args=["--directory", str(soar_dir), "run", "secops_soar_mcp/server.py"],
                ),
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(
                McpToolset(
                    connection_params=conn,
                    tool_name_prefix=soar_prefix,
                    tool_list_cache_ttl_seconds=settings.tool_list_cache_ttl_seconds,
                    use_mcp_resources=settings.use_mcp_resources,
                    require_confirmation=settings.require_confirmation,
                )
            )

    return toolsets

