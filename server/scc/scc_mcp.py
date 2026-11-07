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
import argparse
from collections.abc import Sequence
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from google.api_core import exceptions as google_exceptions
from google.cloud import asset_v1
from google.cloud import securitycenter_v2
from google.protobuf import json_format
from mcp.server.caching import CacheHint
from mcp.server.mcpserver import Context, DEFAULT_RESOURCE_SECURITY, MCPServer
from mcp.server.mcpserver.exceptions import ResourceError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, ResourceLink, TextContent, ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
import uvicorn

try:
    from mcp.server._otel import OpenTelemetryMiddleware
except ImportError:  # pragma: no cover
    OpenTelemetryMiddleware = None  # type: ignore[assignment,misc]

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scc-mcp")
logger.setLevel(logging.INFO)

# Add handler to see uvicorn/fastapi logs if they use standard logging
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logging.getLogger().addHandler(handler)

PROTOCOL_VERSION = "2026-07-28"
DEFAULT_MAX_REQUEST_BODY_SIZE = 4_194_304
DEFAULT_SESSION_IDLE_TIMEOUT = 1800
DEFAULT_MAX_SESSIONS = 10_000
DEFAULT_TOOLS_CACHE_TTL_MS = 300_000
DEFAULT_PROMPTS_CACHE_TTL_MS = 300_000
DEFAULT_RESOURCES_CACHE_TTL_MS = 60_000
_WILDCARD_BIND_HOSTS = frozenset({"0.0.0.0", "::", "[::]", "*", ""})


def _resolve_tools_cache_ttl_ms(default: int = DEFAULT_TOOLS_CACHE_TTL_MS) -> int:
    """Resolve the tools/list SEP-2549 cache TTL in milliseconds."""
    raw_ttl = os.getenv("MCP_TOOLS_CACHE_TTL_MS")
    if raw_ttl is None or not raw_ttl.strip():
        return default
    try:
        parsed = int(raw_ttl.strip())
    except ValueError:
        logger.warning(
            "Invalid MCP_TOOLS_CACHE_TTL_MS value %r; using default %d ms",
            raw_ttl,
            default,
        )
        return default
    if parsed < 0:
        logger.warning(
            "Negative MCP_TOOLS_CACHE_TTL_MS value %d; using default %d ms",
            parsed,
            default,
        )
        return default
    return parsed


def _build_cache_hints() -> dict[str, CacheHint]:
    """Build SEP-2549 list freshness cache hints for SCC MCP."""
    return {
        "tools/list": CacheHint(
            ttl_ms=_resolve_tools_cache_ttl_ms(),
            scope="public",
        ),
        "prompts/list": CacheHint(
            ttl_ms=DEFAULT_PROMPTS_CACHE_TTL_MS,
            scope="public",
        ),
        "resources/list": CacheHint(
            ttl_ms=DEFAULT_RESOURCES_CACHE_TTL_MS,
            scope="private",
        ),
    }


def _deduplicate_otel_middleware(server_instance: MCPServer) -> None:
    """Keep a single outermost OpenTelemetryMiddleware on the low-level server."""
    if OpenTelemetryMiddleware is None:
        return
    lowlevel = getattr(server_instance, "_lowlevel_server", None)
    mw_list = getattr(lowlevel, "middleware", None)
    if not isinstance(mw_list, list):
        return
    seen_otel = False
    deduped: list[Any] = []
    for item in mw_list:
        if isinstance(item, OpenTelemetryMiddleware):
            if seen_otel:
                continue
            seen_otel = True
        deduped.append(item)
    mw_list[:] = deduped


def _register_health_routes(server_instance: MCPServer) -> None:
    """Register /healthz and /readyz custom routes idempotently."""
    existing_routes = getattr(server_instance, "_custom_starlette_routes", [])
    existing_paths = {getattr(route, "path", None) for route in existing_routes}

    async def _probe_response(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "server": server_instance.name,
                "protocol_version": PROTOCOL_VERSION,
            }
        )

    if "/healthz" not in existing_paths:
        server_instance.custom_route("/healthz", methods=["GET"])(_probe_response)
    if "/readyz" not in existing_paths:
        server_instance.custom_route("/readyz", methods=["GET"])(_probe_response)


# Initialize MCPServer with rich 2026-07-28 discovery metadata, SEP-2549 cache hints, and OTel
mcp = MCPServer(
    name="scc-mcp",
    title="Google Cloud Security Command Center MCP Server",
    version="0.3.0",
    description=(
        "MCP server for Google Cloud Security Command Center (SCC v2) and "
        "Cloud Asset Inventory (CAI) posture findings, attack exposure "
        "prioritization, compliance control mapping, remediation guidance, "
        "and finding mute management."
    ),
    website_url="https://github.com/google/mcp-security",
    instructions=(
        "Use these tools to triage Google Cloud security posture and active "
        "threats in Security Command Center v2. Always supply either "
        "project_id or organization_id. Prioritize risk with "
        "top_vulnerability_findings (sorted by Attack Exposure Score) or "
        "query broadly with search_findings and search_findings_by_compliance, "
        "inspect full finding and Cloud Asset Inventory context with "
        "get_finding_details and get_finding_remediation, and update finding "
        "suppression state with set_finding_mute."
    ),
    cache_hints=_build_cache_hints(),
    resource_security=DEFAULT_RESOURCE_SECURITY,
    middleware=[OpenTelemetryMiddleware()] if OpenTelemetryMiddleware is not None else None,
)
_deduplicate_otel_middleware(mcp)
_register_health_routes(mcp)

# --- SCC Client Initialization ---
# The client automatically uses Application Default Credentials (ADC).
# Ensure ADC are configured in the environment where the server runs
# (e.g., by running `gcloud auth application-default login`).
try:
    scc_client = securitycenter_v2.SecurityCenterClient()
    logger.info("Successfully initialized Google Cloud Security Center v2 Client.")
except Exception as e:
    logger.error("Failed to initialize Security Center Client: %s", e, exc_info=True)
    # Depending on requirements, you might want to exit or prevent tool registration
    scc_client = None  # Indicate client is not available

# --- CAI Client Initialization ---
try:
    cai_client = asset_v1.AssetServiceClient()
    logger.info("Successfully initialized Google Cloud Asset Inventory Client.")
except Exception as e:
    logger.error("Failed to initialize Cloud Asset Inventory Client: %s", e, exc_info=True)
    cai_client = None  # Indicate client is not available

# --- Helper Function for Proto to Dict Conversion ---


def tool_error_result(error: str, **details: Any) -> CallToolResult:
    """Build a structured MCP error result with is_error=True."""
    payload: dict[str, Any] = {"error": error, **details}
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))],
        structured_content=payload,
        is_error=True,
    )


def proto_message_to_dict(message: Any) -> Dict[str, Any]:
    """Converts a protobuf message to a dictionary."""
    try:
        return json_format.MessageToDict(message._pb)
    except Exception as e:
        logger.error("Error converting protobuf message to dict: %s", e)
        return {"error": "Failed to serialize response part", "details": str(e)}


def _build_parent(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    location: str = "global",
) -> str:
    """Build the canonical SCC v2 parent resource path."""
    if organization_id:
        return f"organizations/{organization_id}/sources/-/locations/{location}"
    elif project_id:
        return f"projects/{project_id}/sources/-/locations/{location}"
    raise ValueError("Either project_id or organization_id must be provided.")


def _build_or_filter(field: str, value: str) -> str:
    """Build a SCC filter clause supporting OR-separated or comma-separated values."""
    parts = [
        p.strip().upper()
        for p in re.split(r"\s+or\s+|,", value, flags=re.IGNORECASE)
        if p.strip()
    ]
    if len(parts) > 1:
        return "(" + " OR ".join(f'{field}="{p}"' for p in parts) + ")"
    elif parts:
        return f'{field}="{parts[0]}"'
    return ""


# --- Security Command Center Tools ---

@mcp.tool(
    title="Search SCC Findings",
    annotations=ToolAnnotations(
        title="Search SCC Findings",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def search_findings(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    finding_class: Optional[str] = None,
    severity: Optional[str] = None,
    state: Optional[str] = "ACTIVE",
    category: Optional[str] = None,
    resource_name: Optional[str] = None,
    resource_type: Optional[str] = None,
    mute: Optional[str] = None,
    custom_filter: Optional[str] = None,
    max_findings: int = 50,
    location: str = "global",
    order_by: str = "event_time desc",
) -> dict[str, Any]:
    """Name: search_findings

    Description: Searches and lists ALL types of Security Command Center findings for a specific project
                 or organization with flexible filtering. Returns full finding details including descriptions,
                 remediation steps, severity, attack exposure, and all associated metadata. Supports filtering
                 by finding class (VULNERABILITY, THREAT, MISCONFIGURATION, OBSERVATION, SCC_ERROR,
                 POSTURE_VIOLATION, TOXIC_COMBINATION, SENSITIVE_DATA_RISK, CHOKEPOINT), severity,
                 state, category, resource name/type, and mute status.
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    finding_class (optional): Filter by finding class. Valid values: VULNERABILITY, THREAT,
        MISCONFIGURATION, OBSERVATION, SCC_ERROR, POSTURE_VIOLATION, TOXIC_COMBINATION,
        SENSITIVE_DATA_RISK, CHOKEPOINT. Can combine with OR (e.g., 'THREAT OR MISCONFIGURATION').
    severity (optional): Filter by severity. Valid values: CRITICAL, HIGH, MEDIUM, LOW.
        Can combine with OR (e.g., 'HIGH OR CRITICAL').
    state (optional): Filter by state. Valid values: ACTIVE, INACTIVE. Defaults to 'ACTIVE'.
        Set to None or empty string to search all states.
    category (optional): Filter by finding category (e.g., 'PUBLIC_BUCKET_ACL', 'XSS', 'SQL_INJECTION',
        'OPEN_FIREWALL', 'MFA_NOT_ENFORCED', etc.).
    resource_name (optional): Filter by the full resource name associated with the finding.
    resource_type (optional): Filter by resource type (e.g., 'google.compute.Instance', 'google.storage.Bucket').
    mute (optional): Filter by mute status. Valid values: MUTED, UNMUTED, UNDEFINED.
    custom_filter (optional): A raw SCC filter string that will be appended to any other filters using AND.
        Use this for advanced filtering not covered by other parameters.
    max_findings (optional): Maximum number of findings to return. Defaults to 50.
    location (optional): The Google Cloud location for SCC v2 (e.g., 'global', 'us-central1'). Defaults to 'global'.
    order_by (optional): Ordering of results. Defaults to 'event_time desc'. Other options include
        'severity desc', 'create_time desc'.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")

    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    filter_parts = []
    if state:
        filter_parts.append(f'state="{state}"')
    if finding_class:
        filter_parts.append(_build_or_filter("findingClass", finding_class))
    if severity:
        filter_parts.append(_build_or_filter("severity", severity))
    if category:
        filter_parts.append(f'category="{category}"')
    if resource_name:
        filter_parts.append(f'resourceName="{resource_name}"')
    if resource_type:
        filter_parts.append(f'resource.type="{resource_type}"')
    if mute:
        filter_parts.append(f'mute="{mute.upper()}"')
    if custom_filter:
        filter_parts.append(custom_filter)

    filter_str = " AND ".join(filter_parts) if filter_parts else ""
    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    logger.info("Searching findings for %s, filter: %s", target_label, filter_str)

    try:
        request_args = {
            "parent": parent,
            "filter": filter_str,
            "page_size": min(max_findings, 1000),
            "order_by": order_by,
        }

        response_pager = scc_client.list_findings(request=request_args)

        all_findings = []
        last_page = None
        for page in response_pager.pages:
            last_page = page
            for item in page.list_findings_results:
                if len(all_findings) >= max_findings:
                    break
                all_findings.append(proto_message_to_dict(item.finding))
            if len(all_findings) >= max_findings:
                break

        more_findings_may_exist = bool(
            last_page and getattr(last_page, "next_page_token", None)
        ) or len(all_findings) >= max_findings

        return {
            "findings": all_findings,
            "count": len(all_findings),
            "filter_applied": filter_str if filter_str else "No filter (all findings)",
            "more_findings_may_exist": more_findings_may_exist,
        }

    except google_exceptions.NotFound as e:
        logger.error("Target not found for search on %s: %s", parent, e)
        return tool_error_result(
            "Not Found",
            details=f"Could not find {target_label} or relevant resources. {str(e)}",
        )
    except google_exceptions.PermissionDenied as e:
        logger.error("Permission denied for search on %s: %s", parent, e)
        return tool_error_result("Permission Denied", details=str(e))
    except google_exceptions.InvalidArgument as e:
        logger.error("Invalid argument (check filter syntax?) for search on %s: %s", parent, e)
        return tool_error_result("Invalid Argument", details=str(e))
    except Exception as e:
        logger.error("An unexpected error occurred searching findings: %s", e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


@mcp.tool(
    title="Get SCC Finding Details",
    annotations=ToolAnnotations(
        title="Get SCC Finding Details",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def get_finding_details(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    location: str = "global",
    include_resource_details: bool = True,
) -> dict[str, Any]:
    """Name: get_finding_details

    Description: Gets the full details of a specific finding by its finding ID, including description,
                 remediation steps, severity, attack exposure, compliance information, MITRE ATT&CK data,
                 vulnerability details, and optionally the affected resource details from Cloud Asset
                 Inventory (CAI). Works for any finding class (VULNERABILITY, THREAT, MISCONFIGURATION, etc.).
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    finding_id (required): The ID of the finding to retrieve.
    location (optional): The Google Cloud location for SCC v2 (e.g., 'global', 'us-central1'). Defaults to 'global'.
    include_resource_details (optional): Whether to fetch additional resource details from Cloud Asset
        Inventory. Defaults to True.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")

    if not finding_id:
        return tool_error_result("finding_id is required.")

    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    if organization_id:
        finding_name_filter = f"organizations/{organization_id}/sources/-/locations/{location}/findings/{finding_id}"
    else:
        finding_name_filter = f"projects/{project_id}/sources/-/locations/{location}/findings/{finding_id}"

    filter_str = f'name="{finding_name_filter}"'
    logger.info("Getting details for finding %s in %s", finding_id, target_label)

    try:
        scc_request_args = {
            "parent": parent,
            "filter": filter_str,
            "page_size": 1,
        }

        response_pager = scc_client.list_findings(request=scc_request_args)
        first_finding = None
        page = next(iter(response_pager.pages), None)
        if page and page.list_findings_results:
            results = list(page.list_findings_results)
            if results:
                first_finding = results[0].finding

        if not first_finding:
            return tool_error_result(
                "Finding not found",
                details=f"No finding with ID '{finding_id}' found in {target_label}.",
            )

        finding_dict = proto_message_to_dict(first_finding)

        result = {
            "finding": finding_dict,
            "finding_id": finding_id,
        }

        # Optionally fetch resource details from CAI
        resource_name_from_finding = finding_dict.get("resourceName")
        if include_resource_details and resource_name_from_finding and cai_client:
            try:
                cai_scope = f"organizations/{organization_id}" if organization_id else f"projects/{project_id}"
                cai_request = asset_v1.SearchAllResourcesRequest(
                    scope=cai_scope,
                    query=f'name="{resource_name_from_finding}"',
                    page_size=1,
                )
                cai_response = cai_client.search_all_resources(request=cai_request)
                asset_result = next(iter(cai_response), None)
                if asset_result:
                    result["resource_details_cai"] = proto_message_to_dict(asset_result)
                    logger.info("Successfully fetched CAI details for %s", resource_name_from_finding)
                else:
                    result["resource_details_cai"] = {"warning": "Resource not found in CAI.", "resource_name": resource_name_from_finding}
            except Exception as cai_e:
                logger.error("Error fetching CAI details: %s", cai_e)
                result["resource_details_cai"] = {"error": "Failed to fetch resource details from CAI.", "details": str(cai_e)}
        elif include_resource_details and not cai_client:
            result["resource_details_cai"] = {"error": "Cloud Asset Inventory Client not initialized."}

        return result

    except google_exceptions.NotFound as e:
        logger.error("Resource not found: %s", e)
        return tool_error_result("Not Found", details=str(e))
    except google_exceptions.PermissionDenied as e:
        logger.error("Permission denied: %s", e)
        return tool_error_result("Permission Denied", details=str(e))
    except google_exceptions.InvalidArgument as e:
        logger.error("Invalid argument: %s", e)
        return tool_error_result("Invalid Argument", details=str(e))
    except Exception as e:
        logger.error("Unexpected error getting finding details: %s", e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


@mcp.tool(
    title="Search SCC Findings by Compliance",
    annotations=ToolAnnotations(
        title="Search SCC Findings by Compliance",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def search_findings_by_compliance(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    search_text: Optional[str] = None,
    compliance_standard: Optional[str] = None,
    compliance_version: Optional[str] = None,
    compliance_id: Optional[str] = None,
    severity: Optional[str] = None,
    state: Optional[str] = "ACTIVE",
    max_findings: int = 50,
    location: str = "global",
) -> dict[str, Any]:
    """Name: search_findings_by_compliance

    Description: Searches Security Command Center findings by compliance framework information (e.g., CIS benchmarks,
                 PCI DSS, NIST 800-53, ISO 27001) or by free-text search on finding descriptions and categories.
                 Use this tool when you have a compliance control name or description (e.g.,
                 'ServiceAccount should not have Admin privileges', 'Ensure log metric filter and alerts exist')
                 and want to find the corresponding SCC findings. Also supports filtering by specific compliance
                 standard name, version, and control ID.
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    search_text (optional): Free-text to search across finding descriptions, categories, and compliance standard names.
        Matches if any of these fields contain the search text (case-insensitive). Examples:
        'ServiceAccount should not have Admin privileges', 'log metric filter', 'MFA', 'firewall'.
    compliance_standard (optional): Filter by compliance standard name (case-insensitive partial match).
        Examples: 'CIS', 'CIS Google Cloud Platform', 'PCI DSS', 'NIST 800-53', 'ISO 27001'.
    compliance_version (optional): Filter by compliance standard version (exact match). Examples: '1.3.0', '2.0'.
    compliance_id (optional): Filter by compliance control ID (exact match). Examples: '1.5', '4.1', '6.2.1'.
    severity (optional): Pre-filter by severity at the API level. Valid values: CRITICAL, HIGH, MEDIUM, LOW.
        Supports OR (e.g., 'HIGH OR CRITICAL').
    state (optional): Filter by state. Valid values: ACTIVE, INACTIVE. Defaults to 'ACTIVE'.
        Set to None or empty string to search all states.
    max_findings (optional): Maximum number of matching findings to return. Defaults to 50.
    location (optional): The Google Cloud location for SCC v2. Defaults to 'global'.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")

    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    if not search_text and not compliance_standard and not compliance_id:
        return tool_error_result(
            "Missing parameters",
            details="At least one of search_text, compliance_standard, or compliance_id must be provided.",
        )

    filter_parts = []
    if state:
        filter_parts.append(f'state="{state}"')
    if severity:
        filter_parts.append(_build_or_filter("severity", severity))

    filter_str = " AND ".join(filter_parts) if filter_parts else ""
    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    logger.info(
        "Searching findings by compliance for %s, search_text=%r, standard=%r, version=%r, id=%r",
        target_label,
        search_text,
        compliance_standard,
        compliance_version,
        compliance_id,
    )

    try:
        # Fetch findings from the API (with API-level filters only)
        # We fetch more than max_findings because client-side filtering will reduce the count
        fetch_limit = max_findings * 10  # Overfetch to account for client-side filtering
        request_args = {
            "parent": parent,
            "filter": filter_str,
            "page_size": min(fetch_limit, 1000),
        }

        response_pager = scc_client.list_findings(request=request_args)

        matched_findings = []
        scanned_count = 0
        search_text_lower = search_text.lower() if search_text else None

        for page in response_pager.pages:
            for item in page.list_findings_results:
                if len(matched_findings) >= max_findings:
                    break
                if scanned_count >= fetch_limit:
                    break

                scanned_count += 1
                finding_dict = proto_message_to_dict(item.finding)

                # --- Client-side compliance filtering ---
                compliances = finding_dict.get("compliances", [])
                description = finding_dict.get("description", "")
                category = finding_dict.get("category", "")

                # Check compliance_standard filter
                if compliance_standard:
                    standard_lower = compliance_standard.lower()
                    has_standard = any(
                        standard_lower in c.get("standard", "").lower()
                        for c in compliances
                    )
                    if not has_standard:
                        continue

                # Check compliance_version filter
                if compliance_version:
                    has_version = any(
                        c.get("version") == compliance_version
                        for c in compliances
                    )
                    if not has_version:
                        continue

                # Check compliance_id filter
                if compliance_id:
                    has_id = any(
                        compliance_id in c.get("ids", [])
                        for c in compliances
                    )
                    if not has_id:
                        continue

                # Check search_text filter (matches description, category, or compliance standard names)
                if search_text_lower:
                    text_match = (
                        search_text_lower in description.lower()
                        or search_text_lower in category.lower()
                        or any(
                            search_text_lower in c.get("standard", "").lower()
                            for c in compliances
                        )
                    )
                    if not text_match:
                        continue

                # Finding passed all filters — enrich with compliance summary
                compliance_summary = []
                for c in compliances:
                    comp_entry = {
                        "standard": c.get("standard"),
                        "version": c.get("version"),
                        "ids": c.get("ids", []),
                    }
                    compliance_summary.append(comp_entry)

                finding_dict["compliance_summary"] = compliance_summary
                matched_findings.append(finding_dict)

            if len(matched_findings) >= max_findings or scanned_count >= fetch_limit:
                break

        return {
            "findings": matched_findings,
            "count": len(matched_findings),
            "scanned_count": scanned_count,
            "filters_applied": {
                "search_text": search_text,
                "compliance_standard": compliance_standard,
                "compliance_version": compliance_version,
                "compliance_id": compliance_id,
                "severity": severity,
                "state": state,
            },
            "more_findings_may_exist": scanned_count >= fetch_limit and len(matched_findings) >= max_findings,
        }

    except google_exceptions.NotFound as e:
        logger.error("Target not found for compliance search on %s: %s", parent, e)
        return tool_error_result("Not Found", details=f"Could not find {target_label}. {str(e)}")
    except google_exceptions.PermissionDenied as e:
        logger.error("Permission denied for compliance search on %s: %s", parent, e)
        return tool_error_result("Permission Denied", details=str(e))
    except google_exceptions.InvalidArgument as e:
        logger.error("Invalid argument for compliance search on %s: %s", parent, e)
        return tool_error_result("Invalid Argument", details=str(e))
    except Exception as e:
        logger.error("Unexpected error in compliance search: %s", e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


_ORG_FINDING_NAME_RE = re.compile(
    r"^organizations/([^/]+)/sources/[^/]+/(?:locations/[^/]+/)?findings/([^/]+)$"
)
_ANY_FINDING_ID_RE = re.compile(r"/findings/([^/]+)$")


def _build_scc_finding_resource_links(
    findings: list[dict[str, Any]],
    organization_id: Optional[str] = None,
) -> list[ResourceLink]:
    """Build scc://findings/{organization_id}/{finding_id} ResourceLink items."""
    links: list[ResourceLink] = []
    seen_uris: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        raw_name = str(finding.get("name") or "").strip()
        resolved_org = (organization_id or "").strip()
        resolved_finding_id = ""

        org_match = _ORG_FINDING_NAME_RE.match(raw_name)
        if org_match:
            resolved_org = org_match.group(1)
            resolved_finding_id = org_match.group(2)
        elif resolved_org and raw_name:
            id_match = _ANY_FINDING_ID_RE.search(raw_name)
            if id_match:
                resolved_finding_id = id_match.group(1)
            elif "/" not in raw_name:
                resolved_finding_id = raw_name

        if not resolved_org or not resolved_finding_id:
            continue

        uri = f"scc://findings/{resolved_org}/{resolved_finding_id}"
        if uri in seen_uris:
            continue
        seen_uris.add(uri)

        category = str(finding.get("category") or resolved_finding_id)
        severity = str(finding.get("severity") or "UNKNOWN")
        links.append(
            ResourceLink(
                type="resource_link",
                uri=uri,
                name=f"{category} ({resolved_finding_id})",
                title=f"SCC {severity} Finding: {category}",
                description=(
                    f"Google Cloud SCC v2 finding {resolved_finding_id} "
                    f"in organization {resolved_org}"
                ),
                mime_type="application/json",
            )
        )
    return links


@mcp.tool(
    title="List Top SCC Vulnerability Findings",
    annotations=ToolAnnotations(
        title="List Top SCC Vulnerability Findings",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def top_vulnerability_findings(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    max_findings: int = 20,
    location: str = "global",
    ctx: Optional[Context] = None,
) -> dict[str, Any]:
    """Name: top_vulnerability_findings

    Description: Lists the top ACTIVE, HIGH or CRITICAL severity findings of class VULNERABILITY for a specific project
                 or organization, sorted by Attack Exposure Score (descending). Includes the Attack Exposure score in the
                 output if available. Aids prioritization for remediation.
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    max_findings (optional): The maximum number of findings to return. Defaults to 20.
    location (optional): The Google Cloud location for SCC v2 (e.g., 'global', 'us-central1'). Defaults to 'global'.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")

    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    filter_str = 'state="ACTIVE" AND findingClass="VULNERABILITY" AND (severity="HIGH" OR severity="CRITICAL")'

    # Fetch significantly more than max_findings so sort-by-attack-exposure is meaningful
    # across the full population, not just the first page.
    final_max = max(max_findings if max_findings and max_findings > 0 else 20, 1)
    fetch_size = min(final_max * 10, 1000)

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    logger.info(
        "Getting top vulnerability findings for %s, fetching up to %d for sorting",
        target_label,
        fetch_size,
    )

    try:
        response_pager = scc_client.list_findings(request={
            "parent": parent,
            "filter": filter_str,
            "page_size": min(fetch_size, 1000),
        })

        all_fetched = []
        for page in response_pager.pages:
            for item in page.list_findings_results:
                if len(all_fetched) >= fetch_size:
                    break
                finding_dict = proto_message_to_dict(item.finding)
                all_fetched.append({
                    "name": finding_dict.get("name"),
                    "category": finding_dict.get("category"),
                    "resourceName": finding_dict.get("resourceName"),
                    "severity": finding_dict.get("severity"),
                    "description": finding_dict.get("description", "No description provided."),
                    "nextSteps": finding_dict.get("nextSteps", ""),
                    "attackExposureScore": (
                        finding_dict.get("attackExposure") or {}
                    ).get("score"),
                })
            if len(all_fetched) >= fetch_size:
                break

        all_fetched.sort(
            key=lambda f: float(f["attackExposureScore"]) if f["attackExposureScore"] is not None else -1.0,
            reverse=True,
        )
        sorted_findings = all_fetched[:final_max]

        payload: dict[str, Any] = {
            "top_findings": sorted_findings,
            "count": len(sorted_findings),
            "fetched_for_sorting": len(all_fetched),
            "more_findings_exist_beyond_fetch_limit": len(all_fetched) >= fetch_size,
        }
        if ctx is not None:
            resource_links = _build_scc_finding_resource_links(
                sorted_findings,
                organization_id=organization_id,
            )
            return CallToolResult(  # type: ignore[return-value]
                content=[
                    TextContent(
                        type="text",
                        text=json.dumps(payload, indent=2),
                    ),
                    *resource_links,
                ],
                structured_content=payload,
            )
        return payload

    except google_exceptions.NotFound as e:
        logger.error("Target or resource not found for top findings on %s: %s", parent, e)
        return tool_error_result(
            "Not Found",
            details=f"Could not find {target_label} or relevant resources. {str(e)}",
        )
    except google_exceptions.PermissionDenied as e:
        logger.error("Permission denied for top findings on %s: %s", parent, e)
        return tool_error_result("Permission Denied", details=str(e))
    except google_exceptions.InvalidArgument as e:
        logger.error("Invalid argument (check filter syntax?) for top findings on %s: %s", parent, e)
        return tool_error_result("Invalid Argument", details=str(e))
    except Exception as e:
        logger.error("An unexpected error occurred getting top findings: %s", e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


@mcp.tool(
    title="Get SCC Finding Remediation",
    annotations=ToolAnnotations(
        title="Get SCC Finding Remediation",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def get_finding_remediation(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    resource_name: Optional[str] = None,
    category: Optional[str] = None,
    finding_id: Optional[str] = None,
    location: str = "global",
) -> dict[str, Any]:
    """Name: get_finding_remediation

    Description: Gets the remediation steps (nextSteps) for a specific finding within a project or organization,
                 along with details of the affected resource fetched from Cloud Asset Inventory (CAI).
                 The finding can be identified either by its resource_name and category (for ACTIVE findings)
                 or directly by its finding_id (regardless of state).
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    resource_name (optional): The full resource name associated with the finding.
        (e.g., '//container.googleapis.com/projects/my-project/locations/us-central1/clusters/my-cluster')
    category (optional): The category of the finding (e.g., 'GKE_SECURITY_BULLETIN').
    finding_id (optional): The ID of the finding to search for directly.
    location (optional): The Google Cloud location for SCC v2 (e.g., 'global', 'us-central1'). Defaults to 'global'.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")
    # Also check CAI client
    if not cai_client:
        return tool_error_result("Cloud Asset Inventory Client not initialized.")

    # Input validation
    if not resource_name and not category and not finding_id:
        return tool_error_result(
            "Missing required parameters",
            details="Either resource_name and category or finding_id must be provided.",
        )
    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    first_finding_result = None
    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    filter_str = ""

    try:
        if finding_id:
            # --- Use list_findings with name filter for finding_id (SCC v2 Client) ---
            # v2 finding names include /locations/{location}/
            if organization_id:
                finding_name_to_filter = f"organizations/{organization_id}/sources/-/locations/{location}/findings/{finding_id}"
            else:
                finding_name_to_filter = f"projects/{project_id}/sources/-/locations/{location}/findings/{finding_id}"
            filter_str = f'name="{finding_name_to_filter}"'
            logger.info("Attempting to list findings by name filter: %s", filter_str)
            scc_request_args = {
                "parent": parent,
                "filter": filter_str,
                "page_size": 1,  # Expecting only one result for a unique name
            }
        elif resource_name and category:
            # --- Use list_findings for resource/category ---
            filter_str = f'state="ACTIVE" AND resourceName="{resource_name}" AND category="{category}"'
            logger.info(
                "Attempting to list active findings for resource: %s, category: %s",
                resource_name,
                category,
            )
            scc_request_args = {
                "parent": parent,
                "filter": filter_str,
                "page_size": 2,  # Fetch 2 to detect multiple matches
            }
        else:
            # This case should be caught by initial validation, but safety check.
            return tool_error_result("Invalid Arguments", details="No valid criteria provided.")

        # --- Perform the list_findings call ---
        logger.debug(
            "Executing list_findings with parent=%r, filter=%r, page_size=%d",
            parent,
            filter_str,
            scc_request_args["page_size"],
        )
        scc_response_pager = scc_client.list_findings(request=scc_request_args)

        results = []
        page = next(iter(scc_response_pager.pages), None)
        if page and page.list_findings_results:
            results = list(page.list_findings_results)

        # --- Process results ---
        if len(results) >= 1:
            if len(results) > 1 and resource_name:  # Warning only needed for resource/category search
                logger.warning(
                    "Multiple (%d) ACTIVE findings found for resource %r and category %r. Using the first one.",
                    len(results),
                    resource_name,
                    category,
                )
            first_finding_result = results[0].finding
            logger.info("Successfully retrieved finding matching criteria.")
        else:
            first_finding_result = None

        # --- Process the found finding (if any) ---
        if first_finding_result:
            finding_dict = proto_message_to_dict(first_finding_result)
            remediation_steps = finding_dict.get("nextSteps", "No remediation steps provided for this finding.")
            finding_name = finding_dict.get("name")
            description = finding_dict.get("description", "No description available.")
            resource_name_from_finding = finding_dict.get("resourceName")

            logger.info("Processing finding %s. Fetching CAI details...", finding_name)
            asset_details = None
            if resource_name_from_finding:
                try:
                    cai_scope = f"organizations/{organization_id}" if organization_id else f"projects/{project_id}"
                    cai_request = asset_v1.SearchAllResourcesRequest(
                        scope=cai_scope,
                        query=f'name="{resource_name_from_finding}"',
                        page_size=1,
                    )
                    logger.debug(
                        "Attempting CAI search with scope=%r, query=%r, page_size=1",
                        cai_scope,
                        cai_request.query,
                    )
                    cai_response = cai_client.search_all_resources(request=cai_request)
                    asset_result = next(iter(cai_response), None)
                    if asset_result:
                        asset_details = proto_message_to_dict(asset_result)
                        logger.info("Successfully fetched CAI details for %s", resource_name_from_finding)
                    else:
                        logger.warning(
                            "Could not find asset details in CAI for resource: %s within scope %s",
                            resource_name_from_finding,
                            cai_scope,
                        )
                        asset_details = {"error": "Resource details not found in CAI.", "resource_name": resource_name_from_finding}
                except google_exceptions.PermissionDenied as cai_e:
                    logger.error(
                        "Permission denied fetching CAI details for %s: %s",
                        resource_name_from_finding,
                        cai_e,
                    )
                    asset_details = {"error": "Permission Denied fetching resource details from CAI.", "details": str(cai_e)}
                except google_exceptions.InvalidArgument as cai_e:
                    logger.error(
                        "Invalid argument fetching CAI details for %s: %s",
                        resource_name_from_finding,
                        cai_e,
                    )
                    asset_details = {"error": "Invalid Argument fetching resource details from CAI.", "details": str(cai_e)}
                except Exception as cai_e:
                    logger.error(
                        "An unexpected error occurred fetching CAI details for %s: %s",
                        resource_name_from_finding,
                        cai_e,
                        exc_info=True,
                    )
                    asset_details = {"error": "An unexpected error occurred fetching resource details from CAI.", "details": str(cai_e)}
            else:
                logger.warning("Finding %s does not have a resourceName, cannot fetch CAI details.", finding_name)
                asset_details = {"warning": "Finding does not have an associated resource name."}

            return {
                "remediation_steps": remediation_steps,
                "finding_name": finding_name,
                "description": description,
                "resource_name": resource_name_from_finding,
                "resource_details_cai": asset_details,
                "finding_details": finding_dict,
            }
        else:
            # --- Handle case where no finding was found ---
            search_criteria = f"finding ID '{finding_id}' (using name filter)" if finding_id else f"active finding for resource '{resource_name}' and category '{category}'"
            logger.warning(
                "No finding found matching %s in %s. Filter: %s",
                search_criteria,
                target_label,
                filter_str,
            )
            return tool_error_result(
                "Finding not found",
                message=f"No finding found matching the specified criteria ({search_criteria}).",
            )

    # --- Outer Exception Handling ---
    except google_exceptions.NotFound as e:
        logger.error(
            "Resource not found during SCC operation for %s (finding_id: %s, resource: %s): %s",
            target_label,
            finding_id,
            resource_name,
            e,
        )
        return tool_error_result(
            "Not Found",
            details=f"Could not find {target_label} or related SCC resources. {str(e)}",
        )
    except google_exceptions.PermissionDenied as e:
        logger.error(
            "Permission denied during SCC operation for %s (finding_id: %s, resource: %s): %s",
            target_label,
            finding_id,
            resource_name,
            e,
        )
        return tool_error_result("Permission Denied", details=str(e))
    except google_exceptions.InvalidArgument as e:
        logger.error(
            "Invalid argument during SCC operation for %s (finding_id: %s, resource: %s): %s",
            target_label,
            finding_id,
            resource_name,
            e,
        )
        return tool_error_result(
            "Invalid Argument",
            details=f"Check SCC filter syntax or input parameters. {str(e)}",
        )
    except Exception as e:
        # General fallback, including potential CAI client errors not caught inside
        logger.error("An unexpected error occurred in get_finding_remediation: %s", e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


@mcp.tool(
    title="Set SCC Finding Mute State",
    annotations=ToolAnnotations(
        title="Set SCC Finding Mute State",
        read_only_hint=False,
        destructive_hint=True,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def set_finding_mute(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    mute: Optional[str] = None,
    location: str = "global",
) -> dict[str, Any]:
    """Name: set_finding_mute

    Description: Mutes or unmutes a specific Security Command Center finding. Muted findings are
                 hidden from default views but remain in the system for compliance purposes. Use
                 MUTED to suppress known/accepted risks and UNMUTED to resurface them.
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    finding_id (required): The ID of the finding to mute or unmute.
    mute (required): The mute state to set. Valid values: MUTED, UNMUTED.
    location (optional): The Google Cloud location for SCC v2. Defaults to 'global'.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")

    if not finding_id:
        return tool_error_result("finding_id is required.")

    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    if not mute:
        return tool_error_result("mute parameter is required.")

    mute_upper = mute.upper()
    if mute_upper not in ("MUTED", "UNMUTED"):
        return tool_error_result("Invalid mute value", details="Must be 'MUTED' or 'UNMUTED'.")

    # set_mute requires the canonical finding name (with actual source ID, not wildcard).
    # Look up the finding first via list_findings to resolve the full name.
    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    if organization_id:
        filter_str = f'name="organizations/{organization_id}/sources/-/locations/{location}/findings/{finding_id}"'
    else:
        filter_str = f'name="projects/{project_id}/sources/-/locations/{location}/findings/{finding_id}"'

    logger.info("Resolving finding %s for mute operation in %s", finding_id, target_label)

    try:
        response_pager = scc_client.list_findings(request={
            "parent": parent,
            "filter": filter_str,
            "page_size": 1,
        })
        page = next(iter(response_pager.pages), None)
        finding = None
        if page and page.list_findings_results:
            finding = list(page.list_findings_results)[0].finding

        if not finding:
            return tool_error_result(
                "Finding not found",
                details=f"No finding with ID '{finding_id}' in {target_label}.",
            )

        full_name = finding.name
        mute_enum = securitycenter_v2.Finding.Mute[mute_upper]

        request = securitycenter_v2.SetMuteRequest(
            name=full_name,
            mute=mute_enum,
        )
        updated = scc_client.set_mute(request=request)

        return {
            "success": True,
            "finding_name": full_name,
            "mute_state": mute_upper,
            "finding": proto_message_to_dict(updated),
        }

    except google_exceptions.NotFound as e:
        logger.error("Finding not found: %s", e)
        return tool_error_result("Not Found", details=str(e))
    except google_exceptions.PermissionDenied as e:
        logger.error("Permission denied setting mute: %s", e)
        return tool_error_result("Permission Denied", details=str(e))
    except KeyError:
        return tool_error_result(
            "Invalid mute value",
            details=f"'{mute}' is not a valid Mute enum value. Use MUTED or UNMUTED.",
        )
    except Exception as e:
        logger.error("Unexpected error setting mute on %s: %s", finding_id, e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


# --- MCP Resources and Prompts ---


@mcp.resource(
    "scc://info/capabilities",
    name="scc_capabilities",
    title="Google Cloud Security Command Center Capabilities",
    description=(
        "Static catalog summarizing Google Cloud Security Command Center "
        "(SCC v2) MCP server version, posture and vulnerability prioritization "
        "capabilities, resource URI templates, and cloud exposure prompts."
    ),
    mime_type="application/json",
)
def scc_capabilities() -> dict[str, Any]:
    """Return static Google Cloud Security Command Center server capabilities."""
    return {
        "server": mcp.name,
        "version": "0.3.0",
        "protocol_version": PROTOCOL_VERSION,
        "platform": "Google Cloud Security Command Center (SCC v2) & Cloud Asset Inventory (CAI)",
        "capabilities": [
            "SCC v2 active threat, vulnerability, misconfiguration, and toxic combination search",
            "Attack Exposure Score ranking for top vulnerability findings",
            "CIS, PCI DSS, NIST 800-53, and ISO 27001 compliance control mapping",
            "Cloud Asset Inventory (CAI) resource metadata enrichment and remediation steps",
            "Finding mute state lifecycle management",
        ],
        "resource_templates": [
            "scc://findings/{organization_id}/{finding_id}",
        ],
        "prompts": [
            "triage_cloud_finding_exposure",
        ],
    }


_UNSAFE_RESOURCE_SEGMENT_RE = re.compile(r'[\s/\\?#\{\}"\'%\x00-\x1f\x7f]')


def _validate_scc_resource_segment(param_name: str, value: str) -> str:
    """Validate a single decoded SCC URI template segment against injection characters."""
    cleaned = value.strip()
    if not cleaned or cleaned in {".", ".."} or _UNSAFE_RESOURCE_SEGMENT_RE.search(value):
        raise ResourceError(f"Invalid resource parameter '{param_name}'.")
    return cleaned


@mcp.resource(
    "scc://findings/{organization_id}/{finding_id}",
    name="scc_finding_details",
    title="Google Cloud SCC v2 Finding Details",
    description=(
        "Read-only Google Cloud Security Command Center v2 finding details, "
        "Attack Exposure Score, compliance mappings, and Cloud Asset Inventory "
        "resource metadata for organizations/{organization_id}/sources/-/findings/{finding_id}."
    ),
    mime_type="application/json",
)
async def read_scc_finding(
    organization_id: str,
    finding_id: str,
) -> dict[str, Any]:
    """Fetch SCC v2 finding details and CAI resource metadata by organization_id and finding_id."""
    organization_id = _validate_scc_resource_segment("organization_id", organization_id)
    finding_id = _validate_scc_resource_segment("finding_id", finding_id)
    details = await get_finding_details(
        organization_id=organization_id,
        finding_id=finding_id,
        include_resource_details=True,
    )
    if isinstance(details, CallToolResult):
        err_payload = details.structured_content or {}
        err_msg = str(err_payload.get("error") or "Failed to fetch SCC finding")
        extra = str(err_payload.get("details") or "").strip()
        full_msg = f"{err_msg}: {extra}" if extra else err_msg
        raise ResourceError(full_msg)
    if isinstance(details, dict) and isinstance(details.get("error"), str):
        raise ResourceError(details["error"])
    return {
        "organization_id": organization_id,
        **details,
    }


@mcp.prompt(
    title="Triage Google Cloud SCC Finding Exposure",
    description=(
        "Google Cloud Security Command Center (SCC v2) cloud vulnerability and "
        "misconfiguration triage workflow: evaluate Attack Exposure Score, "
        "Cloud Asset Inventory blast radius, compliance impact, and remediation."
    ),
)
def triage_cloud_finding_exposure(finding_id: str, organization_id: str) -> str:
    """Build a structured Google Cloud SCC v2 finding exposure triage prompt."""
    return (
        f"Execute a Google Cloud Security Command Center (SCC v2) exposure "
        f"and blast-radius triage workflow for finding `{finding_id}` in "
        f"organization `{organization_id}`:\n\n"
        f"1. **Finding & Asset Context Inspection**\n"
        f"   - Read resource `scc://findings/{organization_id}/{finding_id}` "
        f"(or call `get_finding_details(organization_id=\"{organization_id}\", "
        f"finding_id=\"{finding_id}\", include_resource_details=True)`) to "
        f"retrieve finding class, category, severity, state, CVE/CVSS data, "
        f"MITRE ATT&CK mappings, and Cloud Asset Inventory (CAI) resource "
        f"configuration.\n\n"
        f"2. **Attack Exposure Score & Blast-Radius Assessment**\n"
        f"   - Evaluate the `attackExposure` score, internet reachability, "
        f"attached service accounts, IAM bindings, and project/folder "
        f"criticality.\n"
        f"   - Call `search_findings(organization_id=\"{organization_id}\", "
        f"resource_name=...)` on the affected `resourceName` to check for "
        f"co-existing `TOXIC_COMBINATION`, `CHOKEPOINT`, `THREAT`, or "
        f"`MISCONFIGURATION` findings on the same cloud asset.\n\n"
        f"3. **Compliance & Remediation Plan**\n"
        f"   - Call `get_finding_remediation(organization_id=\"{organization_id}\", "
        f"finding_id=\"{finding_id}\")` to extract prescriptive `nextSteps` "
        f"and affected compliance controls (CIS, PCI DSS, NIST 800-53, ISO 27001).\n\n"
        f"4. **Prioritized Disposition**\n"
        f"   - Deliver a risk-ranked remediation recommendation (Immediate "
        f"Mitigation, Scheduled Patch/Config Fix, or Documented Risk Acceptance "
        f"prior to any `set_finding_mute` action)."
    )


# --- Main execution ---


def _resolve_allowed_hosts(
    host: str = "127.0.0.1",
    allowed_hosts: Optional[list[str]] = None,
) -> list[str]:
    """Build the Host-header allowlist for DNS-rebinding protection."""
    candidates: list[str] = [
        "127.0.0.1:*",
        "127.0.0.1",
        "localhost:*",
        "localhost",
        "[::1]:*",
        "[::1]",
    ]
    normalized_host = host.strip()
    if normalized_host and normalized_host not in _WILDCARD_BIND_HOSTS:
        if ":" in normalized_host and not normalized_host.startswith("["):
            bracketed = f"[{normalized_host}]"
            candidates.extend([bracketed, f"{bracketed}:*"])
        else:
            candidates.append(normalized_host)
            if not normalized_host.endswith(":*") and ":" not in normalized_host.lstrip("["):
                candidates.append(f"{normalized_host}:*")
            elif normalized_host.startswith("[") and normalized_host.endswith("]"):
                candidates.append(f"{normalized_host}:*")

    env_hosts = os.getenv("MCP_ALLOWED_HOSTS", "")
    if env_hosts.strip():
        for entry in env_hosts.split(","):
            cleaned = entry.strip()
            if cleaned:
                candidates.append(cleaned)

    if allowed_hosts:
        for entry in allowed_hosts:
            cleaned = entry.strip()
            if cleaned:
                candidates.append(cleaned)

    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _resolve_allowed_origins(
    resolved_hosts: Sequence[str],
    allowed_origins: Optional[list[str]] = None,
) -> list[str]:
    """Build the Origin-header allowlist from resolved allowed_hosts and MCP_ALLOWED_ORIGINS."""
    candidates: list[str] = []
    for host_pattern in resolved_hosts:
        cleaned = host_pattern.strip()
        if not cleaned:
            continue
        candidates.append(f"http://{cleaned}")
        candidates.append(f"https://{cleaned}")
        if cleaned.endswith(":*"):
            base_host = cleaned[:-2]
            if base_host:
                candidates.append(f"http://{base_host}")
                candidates.append(f"https://{base_host}")

    env_origins = os.getenv("MCP_ALLOWED_ORIGINS", "")
    if env_origins.strip():
        for entry in env_origins.split(","):
            cleaned = entry.strip()
            if cleaned:
                candidates.append(cleaned)

    if allowed_origins:
        for entry in allowed_origins:
            cleaned = entry.strip()
            if cleaned:
                candidates.append(cleaned)

    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def build_streamable_http_app(
    server_instance: MCPServer = mcp,
    *,
    host: str = "127.0.0.1",
    stateless_http: bool = True,
    allowed_hosts: Optional[list[str]] = None,
    allowed_origins: Optional[list[str]] = None,
) -> Starlette:
    """Build the bounded Streamable HTTP ASGI application with health probes."""
    _register_health_routes(server_instance)
    resolved_hosts = _resolve_allowed_hosts(host=host, allowed_hosts=allowed_hosts)
    resolved_origins = _resolve_allowed_origins(
        resolved_hosts,
        allowed_origins=allowed_origins,
    )
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=resolved_hosts,
        allowed_origins=resolved_origins,
    )
    return server_instance.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=stateless_http,
        max_request_body_size=DEFAULT_MAX_REQUEST_BODY_SIZE,
        session_idle_timeout=DEFAULT_SESSION_IDLE_TIMEOUT,
        max_sessions=DEFAULT_MAX_SESSIONS,
        transport_security=transport_security,
        host=host,
    )


def _resolve_default_stateless_http() -> bool:
    """Resolve default stateless HTTP mode from MCP_STATELESS_HTTP (defaults True)."""
    raw = os.getenv("MCP_STATELESS_HTTP")
    if raw is None or not raw.strip():
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def _normalize_transport(raw_transport: str) -> str:
    """Normalize CLI/environment transport aliases."""
    normalized = raw_transport.strip().lower()
    if normalized == "http":
        return "streamable-http"
    return normalized


def _first_nonempty_env(*names: str, default: str) -> str:
    """Return the first non-empty stripped environment variable value, or default."""
    for name in names:
        raw = os.getenv(name)
        if raw is not None and raw.strip():
            return raw.strip()
    return default


class _MCPArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that validates MCP_* environment defaults on parse."""

    def parse_known_args(
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
    ) -> tuple[argparse.Namespace, list[str]]:
        parsed_ns, remaining = super().parse_known_args(args, namespace)
        if getattr(parsed_ns, "transport", None) is None:
            raw_transport = _first_nonempty_env("MCP_TRANSPORT", default="stdio")
            normalized_transport = _normalize_transport(raw_transport)
            if normalized_transport not in {"stdio", "streamable-http"}:
                self.error(
                    f"invalid MCP_TRANSPORT value {raw_transport!r} "
                    "(choose from 'stdio', 'streamable-http', 'http')"
                )
            parsed_ns.transport = normalized_transport
        else:
            parsed_ns.transport = _normalize_transport(parsed_ns.transport)

        if getattr(parsed_ns, "host", None) is None:
            parsed_ns.host = _first_nonempty_env("MCP_HOST", default="127.0.0.1")

        if getattr(parsed_ns, "port", None) is None:
            raw_port = _first_nonempty_env("MCP_PORT", default="8000")
            try:
                parsed_port = int(raw_port)
            except ValueError:
                self.error(f"invalid MCP_PORT integer value: {raw_port!r}")
            if not (1 <= parsed_port <= 65535):
                self.error(f"MCP_PORT must be between 1 and 65535, got {parsed_port}")
            parsed_ns.port = parsed_port
        elif not (1 <= parsed_ns.port <= 65535):
            self.error(f"--port must be between 1 and 65535, got {parsed_ns.port}")

        return parsed_ns, remaining


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for SCC MCP."""
    parser = _MCPArgumentParser(
        description="Google Cloud Security Command Center MCP Server",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "http"),
        default=None,
        help="MCP transport to serve (default: MCP_TRANSPORT or stdio).",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Bind host for streamable-http transport (default: MCP_HOST or 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port for streamable-http transport (default: MCP_PORT or 8000).",
    )
    parser.add_argument(
        "--stateless-http",
        action=argparse.BooleanOptionalAction,
        default=_resolve_default_stateless_http(),
        help="Serve stateless Streamable HTTP requests (default: MCP_STATELESS_HTTP or true).",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Runs the SCC MCP server."""
    args = build_arg_parser().parse_args(argv)
    if not scc_client:
        logger.critical("SCC Client failed to initialize. MCP server cannot serve SCC tools.")

    transport = _normalize_transport(args.transport)
    if transport == "streamable-http":
        app = build_streamable_http_app(
            mcp,
            host=args.host,
            stateless_http=args.stateless_http,
        )
        logger.info(
            "Starting %s over streamable-http on %s:%d (stateless_http=%s)",
            mcp.name,
            args.host,
            args.port,
            args.stateless_http,
        )
        uvicorn.run(app, host=args.host, port=args.port)
    elif transport == "stdio":
        logger.info("Starting SCC MCP server...")
        mcp.run(transport="stdio")
    else:  # pragma: no cover
        raise ValueError(f"Unsupported MCP transport: {transport!r}")


if __name__ == "__main__":
    main()
