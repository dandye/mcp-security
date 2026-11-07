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
"""URI-templated and static MCP resources for Google Security Operations SIEM."""

from __future__ import annotations

import base64
import logging
import re
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError
from secops.chronicle import ReferenceListView

from secops_mcp import server as _server_mod

logger = logging.getLogger("secops-mcp")

_UNSAFE_SEGMENT_RE = re.compile(r'[\s/\\?#\{\}"\'%\x00-\x1f\x7f]')


def _validate_resource_segment(param_name: str, value: str) -> str:
    """Validate a single decoded URI template segment against injection characters."""
    cleaned = value.strip()
    if not cleaned or cleaned in {".", ".."} or _UNSAFE_SEGMENT_RE.search(value):
        raise ResourceError(f"Invalid resource parameter '{param_name}'.")
    return cleaned

# Exposed at module scope so tests can patch either secops_mcp.server.get_chronicle_client
# or secops_mcp.resources.get_chronicle_client.
_ORIG_GET_CHRONICLE_CLIENT = _server_mod.get_chronicle_client
get_chronicle_client = _ORIG_GET_CHRONICLE_CLIENT


def _resolve_chronicle_client() -> Any:
    """Resolve the active Chronicle client factory, honoring module-level patches."""
    if get_chronicle_client is not _ORIG_GET_CHRONICLE_CLIENT:
        return get_chronicle_client()
    return _server_mod.get_chronicle_client()


def _normalize_reference_list_entries(raw_entries: Any) -> list[str]:
    """Extract plain string values from Chronicle reference list entry records."""
    if not isinstance(raw_entries, list):
        return []
    values: list[str] = []
    for entry in raw_entries:
        if isinstance(entry, str):
            values.append(entry)
        elif isinstance(entry, dict):
            values.append(str(entry.get("value", "")))
        elif hasattr(entry, "value"):
            values.append(str(entry.value))
        else:
            values.append(str(entry))
    return values


def _extract_parser_code(parser_obj: dict[str, Any]) -> str:
    """Extract parser DSL text from a Chronicle parser dictionary."""
    parser_code = parser_obj.get("text", "")
    if parser_code:
        return str(parser_code)
    cbn_blob = parser_obj.get("cbn")
    if isinstance(cbn_blob, str) and cbn_blob:
        try:
            return base64.b64decode(cbn_blob).decode("utf-8")
        except Exception as exc:
            logger.warning("Failed to decode base64 CBN parser payload: %s", exc)
    return ""


def register_resources(mcp_server: MCPServer) -> None:
    """Register static catalog and URI-templated resources on the SecOps MCP server."""

    @mcp_server.resource(
        "secops://info/capabilities",
        name="secops_capabilities",
        title="Google Security Operations SIEM Capabilities",
        description=(
            "Static catalog summarizing Google Security Operations SIEM server "
            "version, YARA-L 2.0 UDM detection capabilities, resource URI "
            "templates, and SOC playbook prompts."
        ),
        mime_type="application/json",
    )
    def secops_capabilities() -> dict[str, Any]:
        """Return static Google Security Operations SIEM server capabilities."""
        return {
            "server": mcp_server.name,
            "version": "0.9.0",
            "protocol_version": _server_mod.PROTOCOL_VERSION,
            "platform": "Google Security Operations (SecOps) SIEM",
            "detection_rule_language": "YARA-L 2.0",
            "detection_rule_scope": (
                "YARA-L 2.0 (YL2) rules evaluate structured Unified Data Model "
                "(UDM) security telemetry in Google Security Operations SIEM; "
                "distinct from standard YARA binary/file payload rules in gti-mcp."
            ),
            "capabilities": [
                "UDM event search and CSV export",
                "Entity context and indicator graph lookup",
                "SIEM security alert retrieval and feedback triage",
                "IOC match correlation",
                "YARA-L 2.0 detection rule authoring, validation, and bounded retrohunts",
                "Reference list and custom data table management",
                "Log ingestion feed and custom parser lifecycle management",
            ],
            "resource_templates": [
                "secops://rules/{rule_id}",
                "secops://reference-lists/{name}",
                "secops://parsers/{log_type}",
                "secops://alerts/{alert_id}",
            ],
            "prompts": [
                "triage_siem_alert",
                "validate_yaral2_detection_rule",
                "hunt_entity_timeline",
            ],
        }

    @mcp_server.resource(
        "secops://rules/{rule_id}",
        name="secops_yaral2_rule",
        title="Google Security Operations YARA-L 2.0 Detection Rule",
        description=(
            "Read-only Google Security Operations YARA-L 2.0 SIEM UDM detection "
            "rule definition, metadata, and rule text by rule ID."
        ),
        mime_type="application/json",
    )
    async def read_secops_rule(rule_id: str) -> dict[str, Any]:
        """Fetch a YARA-L 2.0 detection rule from the Chronicle API."""
        rule_id = _validate_resource_segment("rule_id", rule_id)
        try:
            chronicle = _resolve_chronicle_client()
            rule = chronicle.get_rule(rule_id)
        except Exception as exc:
            logger.error("Error reading secops://rules/%s: %s", rule_id, exc)
            raise ResourceError(
                f"Failed to retrieve YARA-L 2.0 rule '{rule_id}': {exc}"
            ) from exc

        if not rule:
            raise ResourceError(f"YARA-L 2.0 rule '{rule_id}' was not found.")
        if isinstance(rule, dict) and isinstance(rule.get("error"), str):
            raise ResourceError(rule["error"])

        return {
            "rule_id": rule_id,
            "rule_language": "YARA-L 2.0",
            "rule": rule if isinstance(rule, dict) else {"raw": rule},
        }

    @mcp_server.resource(
        "secops://reference-lists/{name}",
        name="secops_reference_list",
        title="Google Security Operations Reference List",
        description=(
            "Read-only Google Security Operations SIEM reference list metadata, "
            "syntax type, and full indicator/string entries by list name."
        ),
        mime_type="application/json",
    )
    async def read_secops_reference_list(name: str) -> dict[str, Any]:
        """Fetch a reference list and its entries from the Chronicle API."""
        name = _validate_resource_segment("name", name)
        try:
            chronicle = _resolve_chronicle_client()
            ref_list = chronicle.get_reference_list(name, view=ReferenceListView.FULL)
        except Exception as exc:
            logger.error("Error reading secops://reference-lists/%s: %s", name, exc)
            raise ResourceError(
                f"Failed to retrieve reference list '{name}': {exc}"
            ) from exc

        if not ref_list:
            raise ResourceError(f"Reference list '{name}' was not found.")
        if isinstance(ref_list, dict) and isinstance(ref_list.get("error"), str):
            raise ResourceError(ref_list["error"])

        raw_dict = ref_list if isinstance(ref_list, dict) else {"raw": ref_list}
        entries = _normalize_reference_list_entries(raw_dict.get("entries", []))
        return {
            "name": name,
            "syntax_type": raw_dict.get("syntaxType", "Unknown"),
            "description": raw_dict.get("description", ""),
            "entry_count": len(entries),
            "entries": entries,
            "reference_list": raw_dict,
        }

    @mcp_server.resource(
        "secops://parsers/{log_type}",
        name="secops_active_parser",
        title="Google Security Operations Active Log Parser",
        description=(
            "Read-only active Google Security Operations log parser configuration "
            "and CBN/DSL transformation code for a given log type."
        ),
        mime_type="application/json",
    )
    async def read_secops_active_parser(log_type: str) -> dict[str, Any]:
        """Fetch the active log parser configuration for log_type from the Chronicle API."""
        log_type = _validate_resource_segment("log_type", log_type)
        try:
            chronicle = _resolve_chronicle_client()
            listed = chronicle.list_parsers(
                log_type=log_type,
                filter='STATE="ACTIVE"',
            )
            parsers = (
                listed
                if isinstance(listed, list)
                else listed.get("parsers", [])
                if isinstance(listed, dict)
                else []
            )
            if not parsers:
                raise ResourceError(
                    f"No active parser configuration found for log type '{log_type}'."
                )

            selected = next(
                (
                    item
                    for item in parsers
                    if isinstance(item, dict) and item.get("state") == "ACTIVE"
                ),
                parsers[0],
            )
            parser_dict: dict[str, Any] = (
                dict(selected) if isinstance(selected, dict) else {"raw": selected}
            )
            parser_id = str(parser_dict.get("name", "")).split("/")[-1]

            if parser_id and not parser_dict.get("text") and not parser_dict.get("cbn"):
                detailed = chronicle.get_parser(log_type=log_type, id=parser_id)
                if isinstance(detailed, dict):
                    parser_dict = detailed
        except ResourceError:
            raise
        except Exception as exc:
            logger.error("Error reading secops://parsers/%s: %s", log_type, exc)
            raise ResourceError(
                f"Failed to retrieve active parser for log type '{log_type}': {exc}"
            ) from exc

        return {
            "log_type": log_type,
            "parser_id": parser_id,
            "state": parser_dict.get("state", "ACTIVE"),
            "parser_code": _extract_parser_code(parser_dict),
            "parser": parser_dict,
        }

    @mcp_server.resource(
        "secops://alerts/{alert_id}",
        name="secops_security_alert",
        title="Google Security Operations SIEM Alert",
        description=(
            "Read-only Google Security Operations SIEM security alert details, "
            "detections, and analyst feedback summary by alert ID."
        ),
        mime_type="application/json",
    )
    async def read_secops_alert(alert_id: str) -> dict[str, Any]:
        """Fetch a SIEM security alert by ID from the Chronicle API."""
        alert_id = _validate_resource_segment("alert_id", alert_id)
        try:
            chronicle = _resolve_chronicle_client()
            alert = chronicle.get_alert(alert_id, True)
        except Exception as exc:
            logger.error("Error reading secops://alerts/%s: %s", alert_id, exc)
            raise ResourceError(
                f"Failed to retrieve security alert '{alert_id}': {exc}"
            ) from exc

        if not alert:
            raise ResourceError(f"Security alert '{alert_id}' was not found.")
        if isinstance(alert, dict) and isinstance(alert.get("error"), str):
            raise ResourceError(alert["error"])

        return {
            "alert_id": alert_id,
            "alert": alert if isinstance(alert, dict) else {"raw": alert},
        }
