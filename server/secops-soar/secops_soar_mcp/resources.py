# Copyright 2026 Google LLC
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
"""URI-templated and static MCP resources for Google Security Operations SOAR."""

from __future__ import annotations

import re
from typing import Any

from logger_utils import get_logger
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError

from secops_soar_mcp import bindings
from secops_soar_mcp.utils.consts import Endpoints

logger = get_logger(__name__)

PROTOCOL_VERSION = "2026-07-28"
_UNSAFE_SEGMENT_RE = re.compile(r'[\s/\\?#\{\}"\'%\x00-\x1f\x7f]')


def _validate_resource_segment(param_name: str, value: str) -> str:
    """Validate a single decoded URI template segment against injection characters."""
    cleaned = value.strip()
    if not cleaned or cleaned in {".", ".."} or _UNSAFE_SEGMENT_RE.search(value):
        raise ResourceError(f"Invalid resource parameter '{param_name}'.")
    return cleaned


async def _fetch_soar_resource(resource_uri: str, endpoint: str) -> Any:
    """Execute a read-only GET against SOAR and raise ResourceError on failure."""
    if bindings.http_client is None:
        raise ResourceError(
            "SOAR HTTP client is not initialized. Verify SOAR_URL and SOAR_APP_KEY configuration."
        )
    try:
        resp = await bindings.http_client.get(endpoint)
    except Exception as exc:
        logger.error("Error reading %s: %s", resource_uri, exc)
        raise ResourceError(f"Error reading {resource_uri}: {exc}") from exc

    if resp is None:
        raise ResourceError(f"SOAR resource '{resource_uri}' returned no data.")
    if isinstance(resp, dict) and isinstance(resp.get("error"), str):
        raise ResourceError(resp["error"])
    return resp


def register_resources(mcp_server: MCPServer) -> None:
    """Register static catalog and URI-templated resources on the SecOps SOAR MCP server."""

    @mcp_server.resource(
        "soar://info/capabilities",
        name="soar_capabilities",
        title="Google Security Operations SOAR Capabilities",
        description=(
            "Static catalog summarizing Google Security Operations SOAR MCP "
            "server version, case lifecycle and marketplace response "
            "capabilities, resource URI templates, and incident prompts."
        ),
        mime_type="application/json",
    )
    def soar_capabilities() -> dict[str, Any]:
        """Return static Google Security Operations SOAR server capabilities."""
        return {
            "server": mcp_server.name,
            "version": "0.3.0",
            "protocol_version": PROTOCOL_VERSION,
            "platform": "Google Security Operations (SecOps) SOAR",
            "capabilities": [
                "SOAR case queue listing, manual case creation, priority, stage, and closure",
                "Alert group correlation and underlying SIEM event inspection",
                "Entity context lookup across active and historical SOAR cases",
                "Case wall audit-trail commenting and activity stream inspection",
                "Dynamic third-party marketplace integration actions",
            ],
            "resource_templates": [
                "soar://cases/{case_id}",
                "soar://cases/{case_id}/wall",
            ],
            "prompts": [
                "investigate_soar_case",
                "draft_case_closure_summary",
            ],
        }

    @mcp_server.resource(
        "soar://cases/{case_id}",
        name="soar_case_overview",
        title="Google Security Operations SOAR Case Overview",
        description=(
            "Read-only Google Security Operations SOAR case overview, status, "
            "priority, stage, tags, and metadata by case ID."
        ),
        mime_type="application/json",
    )
    async def read_soar_case(case_id: str) -> dict[str, Any]:
        """Fetch SOAR case overview details for case_id."""
        case_id = _validate_resource_segment("case_id", case_id)
        resp = await _fetch_soar_resource(
            f"soar://cases/{case_id}",
            Endpoints.BASE_SPECIFIC_CASE_URL.format(CASE_ID=case_id),
        )
        return {
            "case_id": case_id,
            "case": resp if isinstance(resp, dict) else {"items": resp},
        }

    @mcp_server.resource(
        "soar://cases/{case_id}/wall",
        name="soar_case_wall",
        title="Google Security Operations SOAR Case Wall Activity",
        description=(
            "Read-only Google Security Operations SOAR case wall comments "
            "and analyst activity stream by case ID."
        ),
        mime_type="application/json",
    )
    async def read_soar_case_wall(case_id: str) -> dict[str, Any]:
        """Fetch SOAR case wall comments and activity stream for case_id."""
        case_id = _validate_resource_segment("case_id", case_id)
        resp = await _fetch_soar_resource(
            f"soar://cases/{case_id}/wall",
            Endpoints.BASE_CASE_COMMENTS_URL.format(CASE_ID=case_id),
        )
        if isinstance(resp, list):
            return {
                "case_id": case_id,
                "count": len(resp),
                "comments": resp,
            }
        return {
            "case_id": case_id,
            "wall": resp,
        }
