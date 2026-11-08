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
"""Phase 4 suite: MCP Resources (DEFAULT_RESOURCE_SECURITY), ResourceLink, and SOC Prompts."""

from __future__ import annotations

import base64
from contextlib import asynccontextmanager
import json
from pathlib import Path
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from mcp.client import Client
from mcp.server.mcpserver import DEFAULT_RESOURCE_SECURITY, MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import ResourceLink, TextContent
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
from secops_mcp.tools.security_alerts import get_security_alerts  # noqa: E402
from secops_mcp.tools.security_rules import list_security_rules  # noqa: E402
from secops_soar_mcp import bindings as soar_bindings  # noqa: E402
from secops_soar_mcp import server as soar_server_mod  # noqa: E402

scc_server = scc_mcp.mcp

SAMPLE_RULE_ID = "ru_a1b2c3d4-e5f6-4321-abcd-ef1234567890"
SAMPLE_ALERT_ID = "de_a1b2c3d4-e5f6-4321-abcd-ef1234567890"
SAMPLE_CUSTOMER_ID = "a1b2c3d4-e5f6-4321-abcd-ef1234567890"
SAMPLE_SHA256 = (
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
)

EXPECTED_RESOURCES_BY_SERVER: list[tuple[str, MCPServer, str, set[str]]] = [
    (
        "secops-mcp",
        secops_server,
        "secops://info/capabilities",
        {
            "secops://rules/{rule_id}",
            "secops://reference-lists/{name}",
            "secops://parsers/{log_type}",
            "secops://alerts/{alert_id}",
        },
    ),
    (
        "gti-mcp",
        gti_server,
        "gti://info/capabilities",
        {
            "gti://files/{file_hash}",
            "gti://collections/{collection_id}",
            "gti://hunting-rulesets/{ruleset_id}",
        },
    ),
    (
        "secops-soar-mcp",
        soar_server_mod.mcp,
        "soar://info/capabilities",
        {
            "soar://cases/{case_id}",
            "soar://cases/{case_id}/wall",
        },
    ),
    (
        "scc-mcp",
        scc_server,
        "scc://info/capabilities",
        {
            "scc://findings/{organization_id}/{finding_id}",
        },
    ),
]


def _parse_resource_json(read_result: Any) -> dict[str, Any]:
    """Assert ReadResourceResult has 1 JSON content entry and return parsed dict."""
    assert len(read_result.contents) == 1
    entry = read_result.contents[0]
    assert entry.mime_type == "application/json"
    assert isinstance(entry.text, str) and entry.text.strip()
    parsed = json.loads(entry.text)
    assert isinstance(parsed, dict)
    return parsed


# ---------------------------------------------------------------------------
# 1. list_resources, list_resource_templates, and DEFAULT_RESOURCE_SECURITY
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("server_name", "server_instance", "expected_static_uri", "expected_templates"),
    EXPECTED_RESOURCES_BY_SERVER,
    ids=[row[0] for row in EXPECTED_RESOURCES_BY_SERVER],
)
async def test_servers_expose_static_capabilities_and_uri_templates_with_default_security(
    server_name: str,
    server_instance: MCPServer,
    expected_static_uri: str,
    expected_templates: set[str],
) -> None:
    """Verify static capabilities, resource URI templates, and DEFAULT_RESOURCE_SECURITY."""
    # Verify DEFAULT_RESOURCE_SECURITY is enforced on MCPServer and every URI template
    assert server_instance._resource_security == DEFAULT_RESOURCE_SECURITY
    assert server_instance._resource_security.reject_path_traversal is True
    assert server_instance._resource_security.reject_absolute_paths is True
    assert server_instance._resource_security.reject_null_bytes is True
    assert server_instance._resource_security.exempt_params == frozenset()
    rm = server_instance._resource_manager
    assert len(rm._templates) >= len(expected_templates)
    for tmpl in rm._templates.values():
        assert tmpl.security == DEFAULT_RESOURCE_SECURITY

    async with Client(server_instance) as client:
        resources_res = await client.list_resources()
        templates_res = await client.list_resource_templates()
        cap_read = await client.read_resource(expected_static_uri)

    static_uris = {str(r.uri) for r in resources_res.resources}
    assert expected_static_uri in static_uris, (
        f"{server_name} missing static capability resource {expected_static_uri}"
    )
    for res in resources_res.resources:
        if str(res.uri).startswith("ui://"):
            assert res.mime_type == "text/html;profile=mcp-app"
        else:
            assert res.mime_type == "application/json"
        assert res.title and res.title.strip()
        assert res.description and res.description.strip()

    advertised_templates = {t.uri_template for t in templates_res.resource_templates}
    assert expected_templates.issubset(advertised_templates), (
        f"{server_name} missing expected templates: "
        f"{expected_templates - advertised_templates}"
    )
    for tmpl in templates_res.resource_templates:
        assert tmpl.mime_type == "application/json"
        assert tmpl.title and tmpl.title.strip()
        assert tmpl.description and tmpl.description.strip()

    cap_json = _parse_resource_json(cap_read)
    assert cap_json["server"] == server_name
    assert cap_json["protocol_version"] == "2026-07-28"
    assert set(cap_json["resource_templates"]) == expected_templates
    if server_name == "secops-mcp":
        assert cap_json["detection_rule_language"] == "YARA-L 2.0"
        assert "YARA-L 2.0" in cap_json["detection_rule_scope"]
    elif server_name == "gti-mcp":
        assert cap_json["hunting_rule_language"] == "Standard YARA"
        assert "Standard YARA" in cap_json["hunting_rule_scope"]


# ---------------------------------------------------------------------------
# 2. read_resource Happy Paths, Error Propagation, & DEFAULT_RESOURCE_SECURITY
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_resource_happy_paths_across_all_servers() -> None:
    """Verify reading all 10 URI-templated resources returns expected JSON payloads."""
    # 1. secops-mcp
    fake_chronicle = MagicMock()
    fake_chronicle.get_rule.return_value = {
        "name": f"projects/p/locations/us/instances/c/rules/{SAMPLE_RULE_ID}",
        "ruleName": "suspicious_powershell_download",
        "text": "rule suspicious_powershell_download { condition: true }",
    }
    fake_chronicle.get_reference_list.return_value = {
        "name": "projects/p/locations/us/instances/c/referenceLists/trusted_admins",
        "description": "Approved admin principals",
        "syntaxType": "REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING",
        "entries": [{"value": "alice@example.com"}, {"value": "bob@example.com"}],
    }
    encoded_cbn = base64.b64encode(b'filter { mutate { merge => { "@output" => "event" } } }').decode("ascii")
    fake_chronicle.list_parsers.return_value = [
        {
            "name": "projects/p/locations/us/instances/c/logTypes/OKTA/parsers/pa_a1b2c3d4-e5f6-4321-abcd-ef1234567890",
            "state": "ACTIVE",
            "cbn": encoded_cbn,
        }
    ]
    fake_chronicle.get_alert.return_value = {
        "id": SAMPLE_ALERT_ID,
        "severity": "HIGH",
        "detection": [{"ruleName": "suspicious_powershell_download"}],
    }

    with patch("secops_mcp.server.get_chronicle_client", return_value=fake_chronicle):
        async with Client(secops_server) as client:
            rule_doc = _parse_resource_json(
                await client.read_resource(f"secops://rules/{SAMPLE_RULE_ID}")
            )
            ref_doc = _parse_resource_json(
                await client.read_resource("secops://reference-lists/trusted_admins")
            )
            parser_doc = _parse_resource_json(
                await client.read_resource("secops://parsers/OKTA")
            )
            alert_doc = _parse_resource_json(
                await client.read_resource(f"secops://alerts/{SAMPLE_ALERT_ID}")
            )

    assert rule_doc["rule_id"] == SAMPLE_RULE_ID
    assert rule_doc["rule_language"] == "YARA-L 2.0"
    assert rule_doc["rule"]["ruleName"] == "suspicious_powershell_download"
    assert ref_doc["name"] == "trusted_admins"
    assert ref_doc["entries"] == ["alice@example.com", "bob@example.com"]
    assert parser_doc["log_type"] == "OKTA"
    assert parser_doc["state"] == "ACTIVE"
    assert "@output" in parser_doc["parser_code"]
    assert alert_doc["alert_id"] == SAMPLE_ALERT_ID
    assert alert_doc["alert"]["severity"] == "HIGH"

    # 2. gti-mcp
    fake_vt_client = MagicMock()

    @asynccontextmanager
    async def _fake_vt_cm(_ctx: Any):
        yield fake_vt_client

    async def _fake_fetch_object(
        _client: Any,
        endpoint: str,
        obj_type: str,
        obj_id: str,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        return {
            "id": obj_id,
            "type": obj_type,
            "endpoint": endpoint,
            "attributes": {"name": f"mock-{obj_type}-{obj_id}"},
        }

    with (
        patch("gti_mcp.server.vt_client", _fake_vt_cm),
        patch("gti_mcp.resources.utils.fetch_object", side_effect=_fake_fetch_object),
    ):
        async with Client(gti_server) as client:
            file_doc = _parse_resource_json(
                await client.read_resource(f"gti://files/{SAMPLE_SHA256}")
            )
            col_doc = _parse_resource_json(
                await client.read_resource("gti://collections/collection-apt41")
            )
            ruleset_doc = _parse_resource_json(
                await client.read_resource("gti://hunting-rulesets/ruleset-9001")
            )

    assert file_doc["id"] == SAMPLE_SHA256
    assert file_doc["type"] == "file"
    assert col_doc["id"] == "collection-apt41"
    assert col_doc["type"] == "collection"
    assert ruleset_doc["id"] == "ruleset-9001"
    assert ruleset_doc["type"] == "hunting_ruleset"

    # 3. secops-soar-mcp
    fake_soar_http = MagicMock()

    async def _fake_soar_get(endpoint: str, **_kwargs: Any) -> Any:
        if endpoint.endswith("/comments"):
            return [{"id": 1, "comment": "Initial analyst triage note"}]
        return {"id": "101", "title": "Ransomware Containment Case", "priority": "High"}

    fake_soar_http.get = AsyncMock(side_effect=_fake_soar_get)
    with patch.object(soar_bindings, "http_client", fake_soar_http):
        async with Client(soar_server_mod.mcp) as client:
            case_doc = _parse_resource_json(
                await client.read_resource("soar://cases/101")
            )
            wall_doc = _parse_resource_json(
                await client.read_resource("soar://cases/101/wall")
            )

    assert case_doc["case_id"] == "101"
    assert case_doc["case"]["title"] == "Ransomware Containment Case"
    assert wall_doc["case_id"] == "101"
    assert wall_doc["count"] == 1
    assert wall_doc["comments"][0]["comment"] == "Initial analyst triage note"

    # 4. scc-mcp
    mock_finding_item = MagicMock()
    finding_payload = {
        "name": "organizations/123456/sources/999/locations/global/findings/finding789",
        "category": "OPEN_FIREWALL",
        "severity": "CRITICAL",
        "resourceName": "//compute.googleapis.com/projects/prod-net/global/firewalls/fw-open",
        "attackExposure": {"score": 9.4},
    }
    mock_page = MagicMock()
    mock_page.list_findings_results = [mock_finding_item]
    fake_scc = MagicMock()
    fake_scc.list_findings.return_value.pages = [mock_page]
    fake_cai = MagicMock()
    fake_cai.search_all_resources.return_value = [MagicMock()]

    with (
        patch.object(scc_mcp, "scc_client", fake_scc),
        patch.object(scc_mcp, "cai_client", fake_cai),
        patch.object(
            scc_mcp,
            "proto_message_to_dict",
            side_effect=[finding_payload, {"assetType": "compute.googleapis.com/Firewall"}],
        ),
    ):
        async with Client(scc_server) as client:
            scc_doc = _parse_resource_json(
                await client.read_resource("scc://findings/123456/finding789")
            )

    assert scc_doc["organization_id"] == "123456"
    assert scc_doc["finding_id"] == "finding789"
    assert scc_doc["finding"]["category"] == "OPEN_FIREWALL"
    assert scc_doc["resource_details_cai"]["assetType"] == "compute.googleapis.com/Firewall"


@pytest.mark.asyncio
async def test_resource_security_rejects_path_traversal_absolute_paths_and_null_bytes() -> None:
    """Verify DEFAULT_RESOURCE_SECURITY blocks malicious URIs before invoking backend clients."""
    fake_chronicle = MagicMock()
    fake_vt_factory = MagicMock()
    fake_soar_http = MagicMock()
    fake_soar_http.get = AsyncMock()
    fake_scc = MagicMock()

    with (
        patch("secops_mcp.server.get_chronicle_client", fake_chronicle),
        patch("gti_mcp.server.vt_client_factory", fake_vt_factory),
        patch.object(soar_bindings, "http_client", fake_soar_http),
        patch.object(scc_mcp, "scc_client", fake_scc),
    ):
        # 1. secops-mcp traversal, percent-encoded traversal, absolute path, and query injection
        async with Client(secops_server) as secops_client:
            for malicious_uri in (
                "secops://rules/../../etc/passwd",
                "secops://rules/%2e%2e/etc/passwd",
                "secops://parsers/%2Fetc%2Fpasswd",
                "secops://alerts/de_123%00injected",
                "secops://rules/ru_123%3Falt%3Dmedia",
                "secops://reference-lists/.",
            ):
                with pytest.raises(MCPError):
                    await secops_client.read_resource(malicious_uri)

        # 2. gti-mcp encoded slash traversal, null byte, and format-brace injection
        async with Client(gti_server) as gti_client:
            for malicious_uri in (
                "gti://files/..%2F..%2Fsecret",
                "gti://collections/%2e%2e%2fadmin",
                "gti://hunting-rulesets/rs%00evil",
                "gti://files/%7Bformat_injection%7D",
                "gti://collections/apt41%23fragment",
            ):
                with pytest.raises(MCPError):
                    await gti_client.read_resource(malicious_uri)

        # 3. secops-soar-mcp null byte, multi-segment traversal, and fragment truncation
        async with Client(soar_server_mod.mcp) as soar_client:
            for malicious_uri in (
                "soar://cases/101%00evil",
                "soar://cases/..%2Fadmin/wall",
                "soar://cases/%2Fetc%2Fshadow",
                "soar://cases/101%23truncate/wall",
            ):
                with pytest.raises(MCPError):
                    await soar_client.read_resource(malicious_uri)

        # 4. scc-mcp traversal and filter-quote injection in either parameter
        async with Client(scc_server) as scc_client:
            for malicious_uri in (
                "scc://findings/123456/..%2F..%2Fsecret",
                "scc://findings/..%2F123456/finding789",
                "scc://findings/123456/finding%00evil",
                "scc://findings/123456/finding%22%20OR%20state%3D%22ACTIVE",
            ):
                with pytest.raises(MCPError):
                    await scc_client.read_resource(malicious_uri)

    # Confirm zero backend client calls executed on rejected URIs
    fake_chronicle.assert_not_called()
    fake_vt_factory.assert_not_called()
    fake_soar_http.get.assert_not_called()
    fake_scc.list_findings.assert_not_called()


@pytest.mark.asyncio
async def test_read_resource_backend_errors_raise_clean_mcp_error() -> None:
    """Verify upstream missing/error states raise ResourceError -> MCPError cleanly."""
    failing_chronicle = MagicMock()
    failing_chronicle.list_parsers.return_value = []

    with patch("secops_mcp.server.get_chronicle_client", return_value=failing_chronicle):
        async with Client(secops_server) as client:
            with pytest.raises(MCPError, match="No active parser"):
                await client.read_resource("secops://parsers/UNKNOWN_LOG")

    with patch.object(soar_bindings, "http_client", None):
        async with Client(soar_server_mod.mcp) as client:
            with pytest.raises(MCPError, match="not initialized"):
                await client.read_resource("soar://cases/101")

    empty_page = MagicMock()
    empty_page.list_findings_results = []
    fake_scc = MagicMock()
    fake_scc.list_findings.return_value.pages = [empty_page]
    with patch.object(scc_mcp, "scc_client", fake_scc):
        async with Client(scc_server) as client:
            with pytest.raises(MCPError, match="Finding not found"):
                await client.read_resource("scc://findings/123456/missing-finding")


# ---------------------------------------------------------------------------
# 3. ResourceLink Context Compaction on High-Volume List/Search Tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resource_link_emission_on_all_five_list_and_search_tools() -> None:
    """Verify ResourceLink items are emitted alongside structured_content on all 5 list/search tools."""
    # 1 & 2: secops-mcp list_security_rules & get_security_alerts
    fake_chronicle = MagicMock()
    fake_chronicle.list_rules.return_value = {
        "rules": [
            {
                "name": (
                    "projects/proj-1/locations/us/instances/"
                    f"{SAMPLE_CUSTOMER_ID}/rules/{SAMPLE_RULE_ID}@v_1700000000_0"
                ),
                "ruleName": "suspicious_powershell_download",
            }
        ]
    }
    fake_chronicle.get_alerts.return_value = {
        "alerts": {
            "alerts": [
                {
                    "id": SAMPLE_ALERT_ID,
                    "detection": [{"ruleName": "suspicious_powershell_download"}],
                    "createdTime": "2026-11-07T12:00:00Z",
                    "feedbackSummary": {
                        "status": "OPEN",
                        "verdict": "TRUE_POSITIVE",
                        "severityDisplay": "High",
                    },
                }
            ]
        }
    }

    with (
        patch("secops_mcp.tools.security_rules.get_chronicle_client", return_value=fake_chronicle),
        patch("secops_mcp.tools.security_alerts.get_chronicle_client", return_value=fake_chronicle),
    ):
        # Verify direct Python backward compatibility returns plain dicts
        direct_rules = await list_security_rules(
            project_id="proj-1", customer_id=SAMPLE_CUSTOMER_ID
        )
        direct_alerts = await get_security_alerts(
            project_id="proj-1", customer_id=SAMPLE_CUSTOMER_ID
        )
        assert type(direct_rules) is dict
        assert type(direct_alerts) is dict

        # Verify MCP Client receives both structured_content and ResourceLink items
        async with Client(secops_server) as client:
            rules_res = await client.call_tool(
                "list_security_rules",
                {"project_id": "proj-1", "customer_id": SAMPLE_CUSTOMER_ID},
            )
            alerts_res = await client.call_tool(
                "get_security_alerts",
                {"project_id": "proj-1", "customer_id": SAMPLE_CUSTOMER_ID},
            )

    assert rules_res.is_error is False
    assert isinstance(rules_res.structured_content, dict)
    assert len(rules_res.structured_content["rules"]) == 1
    rule_links = [c for c in rules_res.content if isinstance(c, ResourceLink)]
    assert len(rule_links) == 1
    assert str(rule_links[0].uri) == f"secops://rules/{SAMPLE_RULE_ID}"
    assert rule_links[0].mime_type == "application/json"

    assert alerts_res.is_error is False
    assert isinstance(alerts_res.structured_content, dict)
    assert alerts_res.structured_content["count"] == 1
    alert_links = [c for c in alerts_res.content if isinstance(c, ResourceLink)]
    assert len(alert_links) == 1
    assert str(alert_links[0].uri) == f"secops://alerts/{SAMPLE_ALERT_ID}"
    assert alert_links[0].mime_type == "application/json"

    # 3: gti-mcp search_threats
    fake_vt_client = MagicMock()

    @asynccontextmanager
    async def _fake_vt_cm(_ctx: Any):
        yield fake_vt_client

    fake_vt_obj = MagicMock()
    fake_vt_obj.to_dict.return_value = {
        "id": "col-apt41",
        "type": "collection",
        "attributes": {
            "name": "APT41",
            "collection_type": "threat-actor",
        },
    }

    with (
        patch("gti_mcp.tools.collections.vt_client", _fake_vt_cm),
        patch(
            "gti_mcp.tools.collections.utils.consume_vt_iterator",
            new=AsyncMock(return_value=[fake_vt_obj]),
        ),
    ):
        async with Client(gti_server) as client:
            threats_res = await client.call_tool(
                "search_threats",
                {"query": "APT41", "collection_type": "threat-actor"},
            )

    assert threats_res.is_error is False
    assert isinstance(threats_res.structured_content, dict)
    assert threats_res.structured_content["result"][0]["id"] == "col-apt41"
    threat_links = [c for c in threats_res.content if isinstance(c, ResourceLink)]
    assert len(threat_links) == 1
    assert str(threat_links[0].uri) == "gti://collections/col-apt41"
    assert threat_links[0].name == "APT41"
    assert threat_links[0].mime_type == "application/json"

    # 4: secops-soar-mcp list_cases (and verify get_case_full_details error-dict guard)
    fake_soar_http = MagicMock()
    fake_soar_http.get = AsyncMock(
        return_value=[
            {"Id": 101, "Title": "Suspicious DNS Tunneling"},
            {"Id": 202, "Title": "Cloud Honeytoken Trigger"},
        ]
    )
    with patch.object(soar_bindings, "http_client", fake_soar_http):
        async with Client(soar_server_mod.mcp) as client:
            cases_res = await client.call_tool("list_cases", {})

    assert cases_res.is_error is False
    assert isinstance(cases_res.structured_content, dict)
    assert cases_res.structured_content["count"] == 2
    case_links = [c for c in cases_res.content if isinstance(c, ResourceLink)]
    assert [str(link.uri) for link in case_links] == [
        "soar://cases/101",
        "soar://cases/202",
    ]

    err_soar_http = MagicMock()
    err_soar_http.get = AsyncMock(
        side_effect=[{"error": "Case 999 not found"}, [], []]
    )
    with patch.object(soar_bindings, "http_client", err_soar_http):
        async with Client(soar_server_mod.mcp) as client:
            err_case_res = await client.call_tool(
                "get_case_full_details", {"case_id": "999"}
            )
    assert err_case_res.is_error is True
    assert "Case 999 not found" in err_case_res.structured_content["error"]

    # 5: scc-mcp top_vulnerability_findings
    mock_item = MagicMock()
    finding_dict = {
        "name": "organizations/123456/sources/999/locations/global/findings/finding789",
        "category": "CVE_2026_12345_RCE",
        "severity": "CRITICAL",
        "findingClass": "VULNERABILITY",
        "resourceName": "//compute.googleapis.com/projects/p1/zones/us-central1-a/instances/vm-1",
        "description": "Remote code execution vulnerability",
        "nextSteps": "Upgrade package immediately.",
        "attackExposure": {"score": 9.8},
    }
    mock_page = MagicMock()
    mock_page.list_findings_results = [mock_item]
    fake_scc = MagicMock()
    fake_scc.list_findings.return_value.pages = [mock_page]

    with (
        patch.object(scc_mcp, "scc_client", fake_scc),
        patch.object(scc_mcp, "proto_message_to_dict", return_value=finding_dict),
    ):
        direct_scc = await scc_mcp.top_vulnerability_findings(organization_id="123456")
        assert type(direct_scc) is dict

        async with Client(scc_server) as client:
            scc_res = await client.call_tool(
                "top_vulnerability_findings",
                {"organization_id": "123456", "max_findings": 5},
            )

    assert scc_res.is_error is False
    assert isinstance(scc_res.structured_content, dict)
    assert scc_res.structured_content["count"] == 1
    assert isinstance(scc_res.content[0], TextContent)
    scc_links = [c for c in scc_res.content if isinstance(c, ResourceLink)]
    assert len(scc_links) == 1
    assert str(scc_links[0].uri) == "scc://findings/123456/finding789"
    assert scc_links[0].mime_type == "application/json"


# ---------------------------------------------------------------------------
# 4. Built-In SOC Playbook Prompts (list_prompts & get_prompt)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_eight_soc_playbook_prompts_list_and_render_cleanly() -> None:
    """Verify all 8 built-in SOC prompts advertise metadata and render domain-accurate workflows."""
    # 1. secops-mcp (3 prompts)
    async with Client(secops_server) as client:
        secops_prompts = {p.name: p for p in (await client.list_prompts()).prompts}
        assert set(secops_prompts) == {
            "triage_siem_alert",
            "validate_yaral2_detection_rule",
            "hunt_entity_timeline",
        }
        for p in secops_prompts.values():
            assert p.title and p.title.strip()
            assert p.description and p.description.strip()

        triage_args = {a.name: a.required for a in (secops_prompts["triage_siem_alert"].arguments or [])}
        assert triage_args == {"alert_id": True, "lookback_hours": False}

        p_triage = await client.get_prompt(
            "triage_siem_alert",
            {"alert_id": SAMPLE_ALERT_ID, "lookback_hours": "168"},
        )
        triage_text = p_triage.messages[0].content.text
        assert f"secops://alerts/{SAMPLE_ALERT_ID}" in triage_text
        assert "168" in triage_text

        p_yaral2 = await client.get_prompt(
            "validate_yaral2_detection_rule",
            {"rule_text": "rule demo { condition: true }"},
        )
        yaral2_text = p_yaral2.messages[0].content.text
        assert "YARA-L 2.0" in yaral2_text
        assert "standard YARA" in yaral2_text
        assert "validate_rule" in yaral2_text
        assert "test_rule" in yaral2_text

        p_hunt = await client.get_prompt(
            "hunt_entity_timeline",
            {"entity_value": "wkstn-prod-01"},
        )
        hunt_text = p_hunt.messages[0].content.text
        assert "wkstn-prod-01" in hunt_text
        assert "72" in hunt_text

    # 2. gti-mcp (2 prompts)
    async with Client(gti_server) as client:
        gti_prompts = {p.name: p for p in (await client.list_prompts()).prompts}
        assert set(gti_prompts) == {
            "enrich_and_pivot_ioc",
            "profile_threat_collection",
        }
        for p in gti_prompts.values():
            assert p.title and p.title.strip()
            assert p.description and p.description.strip()

        p_ioc = await client.get_prompt(
            "enrich_and_pivot_ioc",
            {"indicator": "evil-c2.example"},
        )
        assert "evil-c2.example" in p_ioc.messages[0].content.text
        assert "passive" in p_ioc.messages[0].content.text.lower() or "resolutions" in p_ioc.messages[0].content.text

        p_col = await client.get_prompt(
            "profile_threat_collection",
            {"collection_id": "collection-apt41"},
        )
        col_text = p_col.messages[0].content.text
        assert "gti://collections/collection-apt41" in col_text
        assert "standard YARA" in col_text
        assert "YARA-L 2.0" in col_text

    # 3. secops-soar-mcp (2 prompts)
    async with Client(soar_server_mod.mcp) as client:
        soar_prompts = {p.name: p for p in (await client.list_prompts()).prompts}
        assert set(soar_prompts) == {
            "investigate_soar_case",
            "draft_case_closure_summary",
        }
        for p in soar_prompts.values():
            assert p.title and p.title.strip()
            assert p.description and p.description.strip()

        p_inv = await client.get_prompt("investigate_soar_case", {"case_id": "101"})
        inv_text = p_inv.messages[0].content.text
        assert "soar://cases/101" in inv_text
        assert "soar://cases/101/wall" in inv_text

        p_close = await client.get_prompt(
            "draft_case_closure_summary", {"case_id": "101"}
        )
        close_text = p_close.messages[0].content.text
        assert "soar://cases/101" in close_text
        assert "close_case" in close_text

    # 4. scc-mcp (1 prompt)
    async with Client(scc_server) as client:
        scc_prompts = {p.name: p for p in (await client.list_prompts()).prompts}
        assert set(scc_prompts) == {"triage_cloud_finding_exposure"}
        p_meta = scc_prompts["triage_cloud_finding_exposure"]
        assert p_meta.title and p_meta.title.strip()
        assert p_meta.description and p_meta.description.strip()

        p_scc = await client.get_prompt(
            "triage_cloud_finding_exposure",
            {"finding_id": "finding789", "organization_id": "123456"},
        )
        scc_text = p_scc.messages[0].content.text
        assert "scc://findings/123456/finding789" in scc_text
        assert "attackExposure" in scc_text


def test_tool_submodule_first_import_order_has_no_circular_import() -> None:
    """Verify importing tools submodules before server.py succeeds cleanly in a fresh interpreter."""
    import subprocess

    for pkg_dir, stmt in (
        (REPO_ROOT / "server" / "gti", "from gti_mcp.tools import collections, files"),
        (REPO_ROOT / "server" / "secops", "from secops_mcp.tools import security_rules, security_alerts"),
        (REPO_ROOT / "server" / "secops-soar", "from secops_soar_mcp import case_management, server"),
    ):
        proc = subprocess.run(
            [sys.executable, "-c", stmt],
            cwd=str(pkg_dir),
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(pkg_dir)},
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, (
            f"Fresh import failed in {pkg_dir} ({stmt}):\n{proc.stderr}"
        )
