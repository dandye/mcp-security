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
"""URI-templated and static MCP resources for Google Threat Intelligence."""

from __future__ import annotations

import logging
import re
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ResourceError

from gti_mcp import server as _server_mod
from gti_mcp import utils

logger = logging.getLogger("gti-mcp")

_UNSAFE_SEGMENT_RE = re.compile(r'[\s/\\?#\{\}"\'%\x00-\x1f\x7f]')


def _validate_resource_segment(param_name: str, value: str) -> str:
    """Validate a single decoded URI template segment against injection characters."""
    cleaned = value.strip()
    if not cleaned or cleaned in {".", ".."} or _UNSAFE_SEGMENT_RE.search(value):
        raise ResourceError(f"Invalid resource parameter '{param_name}'.")
    return cleaned

# Exposed at module scope so tests can patch either gti_mcp.server.vt_client
# or gti_mcp.resources.vt_client.
_ORIG_VT_CLIENT = _server_mod.vt_client
vt_client = _ORIG_VT_CLIENT


def _resolve_vt_client(ctx: Context):
    """Resolve the active VT client context manager, honoring module-level patches."""
    if vt_client is not _ORIG_VT_CLIENT:
        return vt_client(ctx)
    return _server_mod.vt_client(ctx)


def register_resources(mcp_server: MCPServer) -> None:
    """Register static catalog and URI-templated resources on the GTI MCP server."""

    @mcp_server.resource(
        "gti://info/capabilities",
        name="gti_capabilities",
        title="Google Threat Intelligence Capabilities",
        description=(
            "Static catalog summarizing Google Threat Intelligence (GTI) MCP "
            "server version, IOC and collection enrichment capabilities, "
            "standard YARA hunting rulesets, resource URI templates, and prompts."
        ),
        mime_type="application/json",
    )
    def gti_capabilities() -> dict[str, Any]:
        """Return static Google Threat Intelligence server capabilities."""
        return {
            "server": mcp_server.name,
            "version": "0.2.0",
            "protocol_version": _server_mod.PROTOCOL_VERSION,
            "platform": "Google Threat Intelligence (GTI) / VirusTotal v3",
            "hunting_rule_language": "Standard YARA",
            "hunting_rule_scope": (
                "Standard YARA rules match binary/file byte patterns in GTI "
                "Livehunt and Retrohunt; distinct from YARA-L 2.0 Google "
                "Security Operations SIEM UDM event detection rules in secops-mcp."
            ),
            "capabilities": [
                "File, domain, IP address, and URL threat reputation and sandbox telemetry",
                "Threat actor, malware family, campaign, toolkit, and vulnerability collections",
                "Multi-hop GTI entity relationship pivoting and MITRE ATT&CK trees",
                "Digital Threat Monitoring (DTM) intelligence search",
                "Standard YARA hunting ruleset inspection and notification file correlation",
            ],
            "resource_templates": [
                "gti://files/{file_hash}",
                "gti://collections/{collection_id}",
                "gti://hunting-rulesets/{ruleset_id}",
            ],
            "prompts": [
                "enrich_and_pivot_ioc",
                "profile_threat_collection",
            ],
        }

    @mcp_server.resource(
        "gti://files/{file_hash}",
        name="gti_file_report",
        title="Google Threat Intelligence File Threat Report",
        description=(
            "Read-only Google Threat Intelligence file analysis report, "
            "reputation summary, and key indicator relationships by MD5, "
            "SHA-1, or SHA-256 hash."
        ),
        mime_type="application/json",
    )
    async def read_gti_file_report(file_hash: str, ctx: Context) -> dict[str, Any]:
        """Fetch a GTI file threat report via files/{file_hash}."""
        file_hash = _validate_resource_segment("file_hash", file_hash)
        from gti_mcp.tools.files import FILE_KEY_RELATIONSHIPS

        try:
            async with _resolve_vt_client(ctx) as client:
                res = await utils.fetch_object(
                    client,
                    "files",
                    "file",
                    file_hash,
                    relationships=FILE_KEY_RELATIONSHIPS,
                    params={"exclude_attributes": "last_analysis_results"},
                )
        except Exception as exc:
            logger.error("Error reading gti://files/%s: %s", file_hash, exc)
            raise ResourceError(
                f"Failed to fetch GTI file report for '{file_hash}': {exc}"
            ) from exc

        if utils.is_error_dict(res):
            raise ResourceError(str(res.get("error", f"GTI file '{file_hash}' lookup failed")))
        return utils.sanitize_response(res)

    @mcp_server.resource(
        "gti://collections/{collection_id}",
        name="gti_collection_profile",
        title="Google Threat Intelligence Collection Profile",
        description=(
            "Read-only Google Threat Intelligence threat actor, campaign, "
            "malware family, software toolkit, or vulnerability collection "
            "profile by collection ID."
        ),
        mime_type="application/json",
    )
    async def read_gti_collection(collection_id: str, ctx: Context) -> dict[str, Any]:
        """Fetch a GTI collection profile via collections/{collection_id}."""
        collection_id = _validate_resource_segment("collection_id", collection_id)
        from gti_mcp.tools.collections import (
            COLLECTION_EXCLUDED_ATTRS,
            COLLECTION_KEY_RELATIONSHIPS,
        )

        try:
            async with _resolve_vt_client(ctx) as client:
                res = await utils.fetch_object(
                    client,
                    "collections",
                    "collection",
                    collection_id,
                    relationships=COLLECTION_KEY_RELATIONSHIPS,
                    params={"exclude_attributes": COLLECTION_EXCLUDED_ATTRS},
                )
        except Exception as exc:
            logger.error("Error reading gti://collections/%s: %s", collection_id, exc)
            raise ResourceError(
                f"Failed to fetch GTI collection '{collection_id}': {exc}"
            ) from exc

        if utils.is_error_dict(res):
            raise ResourceError(
                str(res.get("error", f"GTI collection '{collection_id}' lookup failed"))
            )
        return res

    @mcp_server.resource(
        "gti://hunting-rulesets/{ruleset_id}",
        name="gti_yara_hunting_ruleset",
        title="Google Threat Intelligence Standard YARA Hunting Ruleset",
        description=(
            "Read-only Google Threat Intelligence Livehunt standard YARA "
            "binary/file hunting ruleset source and metadata by ruleset ID "
            "(distinct from YARA-L 2.0 SIEM UDM rules)."
        ),
        mime_type="application/json",
    )
    async def read_gti_hunting_ruleset(
        ruleset_id: str, ctx: Context
    ) -> dict[str, Any]:
        """Fetch a standard YARA hunting ruleset via intelligence/hunting_rulesets/{ruleset_id}."""
        ruleset_id = _validate_resource_segment("ruleset_id", ruleset_id)
        try:
            async with _resolve_vt_client(ctx) as client:
                res = await utils.fetch_object(
                    client,
                    "intelligence/hunting_rulesets",
                    "hunting_ruleset",
                    ruleset_id,
                )
        except Exception as exc:
            logger.error("Error reading gti://hunting-rulesets/%s: %s", ruleset_id, exc)
            raise ResourceError(
                f"Failed to fetch GTI standard YARA hunting ruleset '{ruleset_id}': {exc}"
            ) from exc

        if utils.is_error_dict(res):
            raise ResourceError(
                str(res.get("error", f"GTI hunting ruleset '{ruleset_id}' lookup failed"))
            )
        return utils.sanitize_response(res)
