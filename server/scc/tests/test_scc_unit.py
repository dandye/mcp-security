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
"""Unit tests for Security Command Center (SCC v2) MCP server and tools."""

import json
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

from google.cloud import securitycenter_v2
from mcp.client import Client
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scc_mcp  # noqa: E402
from scc_mcp import (  # noqa: E402
    _build_or_filter,
    _build_parent,
    get_finding_details,
    get_finding_remediation,
    mcp as scc_server,
    search_findings,
    search_findings_by_compliance,
    set_finding_mute,
    top_vulnerability_findings,
)


def test_build_parent_project() -> None:
    """Verify _build_parent formats project-level v2 paths with location."""
    assert (
        _build_parent(project_id="my-proj", location="global")
        == "projects/my-proj/sources/-/locations/global"
    )
    assert (
        _build_parent(project_id="my-proj", location="us-central1")
        == "projects/my-proj/sources/-/locations/us-central1"
    )


def test_build_parent_org() -> None:
    """Verify _build_parent formats organization-level v2 paths."""
    assert (
        _build_parent(organization_id="123456789", location="global")
        == "organizations/123456789/sources/-/locations/global"
    )


def test_build_parent_missing() -> None:
    """Verify _build_parent raises ValueError if neither project nor org is given."""
    with pytest.raises(
        ValueError, match="Either project_id or organization_id must be provided"
    ):
        _build_parent()


def test_build_or_filter_case_insensitivity() -> None:
    """Verify _build_or_filter splits on lowercase, uppercase, and commas."""
    assert (
        _build_or_filter("severity", "HIGH OR CRITICAL")
        == '(severity="HIGH" OR severity="CRITICAL")'
    )
    assert (
        _build_or_filter("severity", "high or critical")
        == '(severity="HIGH" OR severity="CRITICAL")'
    )
    assert (
        _build_or_filter("severity", "High or Critical")
        == '(severity="HIGH" OR severity="CRITICAL")'
    )
    assert (
        _build_or_filter("severity", "HIGH, CRITICAL")
        == '(severity="HIGH" OR severity="CRITICAL")'
    )
    assert _build_or_filter("findingClass", "THREAT") == 'findingClass="THREAT"'
    assert _build_or_filter("findingClass", "") == ""


def _create_mock_finding_result(
    finding_id: str = "find-123",
    category: str = "OPEN_FIREWALL",
    severity: str = "HIGH",
    finding_class: str = "VULNERABILITY",
    attack_score: float = 0.85,
    resource_name: str = "//compute.googleapis.com/projects/my-proj/zones/us-central1-a/instances/inst-1",
    compliances: list | None = None,
    next_steps: str = "Close the port in firewall rules.",
):
    mock_item = MagicMock()
    finding_pb = MagicMock()

    finding_dict = {
        "name": f"projects/my-proj/sources/123/locations/global/findings/{finding_id}",
        "category": category,
        "severity": severity,
        "findingClass": finding_class,
        "resourceName": resource_name,
        "description": f"Test finding description for {category}",
        "nextSteps": next_steps,
        "attackExposure": {"score": attack_score},
        "compliances": compliances or [],
    }

    mock_item.finding._pb = finding_pb
    mock_item.finding.name = finding_dict["name"]

    return mock_item, finding_dict


@pytest.mark.asyncio
async def test_scc_mcp_client_tool_listing_and_metadata() -> None:
    """Verify Client(scc_server) exposes 2026-07-28 metadata and all 6 tools."""
    async with Client(scc_server) as client:
        assert client.protocol_version == "2026-07-28"
        assert client.server_info is not None
        assert client.server_info.name == "scc-mcp"
        assert (
            client.server_info.title
            == "Google Cloud Security Command Center MCP Server"
        )
        assert client.server_info.version == "0.3.0"
        assert (
            str(client.server_info.website_url)
            == "https://github.com/google/mcp-security"
        )
        assert client.instructions is not None
        assert "top_vulnerability_findings" in client.instructions

        tools_result = await client.list_tools()
        names = {tool.name for tool in tools_result.tools}
        assert names == {
            "search_findings",
            "get_finding_details",
            "search_findings_by_compliance",
            "top_vulnerability_findings",
            "get_finding_remediation",
            "set_finding_mute",
        }
        for tool in tools_result.tools:
            assert isinstance(tool.input_schema, dict)


@pytest.mark.asyncio
async def test_search_findings_success() -> None:
    """Verify search_findings executes list_findings and formats response."""
    mock_item, finding_dict = _create_mock_finding_result()

    with (
        patch.object(scc_mcp, "scc_client") as mock_scc,
        patch.object(scc_mcp, "proto_message_to_dict", return_value=finding_dict),
    ):
        mock_page = MagicMock()
        mock_page.list_findings_results = [mock_item]
        mock_page.next_page_token = ""
        mock_scc.list_findings.return_value.pages = [mock_page]

        result = await search_findings(
            project_id="my-proj",
            finding_class="VULNERABILITY",
            severity="high or critical",
            max_findings=10,
        )

        assert result["count"] == 1
        assert len(result["findings"]) == 1
        assert result["findings"][0]["category"] == "OPEN_FIREWALL"
        assert 'findingClass="VULNERABILITY"' in result["filter_applied"]
        assert 'severity="HIGH" OR severity="CRITICAL"' in result["filter_applied"]


@pytest.mark.asyncio
async def test_get_finding_details_success() -> None:
    """Verify get_finding_details retrieves finding and enriches from CAI."""
    mock_item, finding_dict = _create_mock_finding_result(finding_id="find-999")

    with (
        patch.object(scc_mcp, "scc_client") as mock_scc,
        patch.object(scc_mcp, "cai_client") as mock_cai,
        patch.object(
            scc_mcp,
            "proto_message_to_dict",
            side_effect=[finding_dict, {"asset": "details"}],
        ),
    ):
        mock_page = MagicMock()
        mock_page.list_findings_results = [mock_item]
        mock_scc.list_findings.return_value.pages = [mock_page]

        mock_cai.search_all_resources.return_value = [MagicMock()]

        result = await get_finding_details(
            project_id="my-proj",
            finding_id="find-999",
            include_resource_details=True,
        )

        assert "error" not in result
        assert result["finding_id"] == "find-999"
        assert result["finding"]["category"] == "OPEN_FIREWALL"
        assert result["resource_details_cai"] == {"asset": "details"}


@pytest.mark.asyncio
async def test_search_findings_by_compliance() -> None:
    """Verify search_findings_by_compliance filters by benchmark and control ID."""
    mock_item, finding_dict = _create_mock_finding_result(
        compliances=[
            {
                "standard": "CIS Google Cloud Platform",
                "version": "1.3.0",
                "ids": ["1.5", "1.6"],
            }
        ]
    )

    with (
        patch.object(scc_mcp, "scc_client") as mock_scc,
        patch.object(scc_mcp, "proto_message_to_dict", return_value=finding_dict),
    ):
        mock_page = MagicMock()
        mock_page.list_findings_results = [mock_item]
        mock_scc.list_findings.return_value.pages = [mock_page]

        result = await search_findings_by_compliance(
            organization_id="123456789",
            compliance_standard="CIS",
            compliance_id="1.5",
        )

        assert result["count"] == 1
        assert len(result["findings"]) == 1
        assert (
            result["findings"][0]["compliance_summary"][0]["standard"]
            == "CIS Google Cloud Platform"
        )


@pytest.mark.asyncio
async def test_top_vulnerability_findings_via_mcp_client() -> None:
    """Verify top_vulnerability_findings sorts by Attack Exposure over Client(mcp)."""
    item1, dict1 = _create_mock_finding_result(finding_id="low-risk", attack_score=0.20)
    item2, dict2 = _create_mock_finding_result(finding_id="high-risk", attack_score=0.95)

    with (
        patch.object(scc_mcp, "scc_client") as mock_scc,
        patch.object(scc_mcp, "proto_message_to_dict", side_effect=[dict1, dict2]),
    ):
        mock_page = MagicMock()
        mock_page.list_findings_results = [item1, item2]
        mock_scc.list_findings.return_value.pages = [mock_page]

        async with Client(scc_server) as client:
            call_res = await client.call_tool(
                "top_vulnerability_findings",
                {
                    "project_id": "my-proj",
                    "organization_id": None,
                    "max_findings": 2,
                },
            )

        assert call_res.is_error is False
        result = json.loads(call_res.content[0].text)
        assert result["count"] == 2
        assert result["top_findings"][0]["attackExposureScore"] == 0.95
        assert result["top_findings"][1]["attackExposureScore"] == 0.20
        assert (
            result["top_findings"][0]["nextSteps"]
            == "Close the port in firewall rules."
        )


@pytest.mark.asyncio
async def test_get_finding_remediation_via_mcp_client() -> None:
    """Verify get_finding_remediation returns nextSteps and CAI details over Client(mcp)."""
    mock_item, finding_dict = _create_mock_finding_result(finding_id="rem-123")

    with (
        patch.object(scc_mcp, "scc_client") as mock_scc,
        patch.object(scc_mcp, "cai_client") as mock_cai,
        patch.object(
            scc_mcp,
            "proto_message_to_dict",
            side_effect=[finding_dict, {"cai": "info"}],
        ),
    ):
        mock_page = MagicMock()
        mock_page.list_findings_results = [mock_item]
        mock_scc.list_findings.return_value.pages = [mock_page]
        mock_cai.search_all_resources.return_value = [MagicMock()]

        async with Client(scc_server) as client:
            call_res = await client.call_tool(
                "get_finding_remediation",
                {
                    "project_id": "my-proj",
                    "organization_id": None,
                    "resource_name": None,
                    "category": None,
                    "finding_id": "rem-123",
                },
            )

        assert call_res.is_error is False
        result = json.loads(call_res.content[0].text)
        assert result["remediation_steps"] == "Close the port in firewall rules."
        assert result["resource_details_cai"] == {"cai": "info"}


@pytest.mark.asyncio
async def test_set_finding_mute_uses_set_mute_request_via_mcp_client() -> None:
    """Verify set_finding_mute constructs securitycenter_v2.SetMuteRequest cleanly."""
    mock_item, _ = _create_mock_finding_result(finding_id="mute-me")
    mock_updated = MagicMock()

    with (
        patch.object(scc_mcp, "scc_client") as mock_scc,
        patch.object(scc_mcp, "proto_message_to_dict", return_value={"mute": "MUTED"}),
    ):
        mock_page = MagicMock()
        mock_page.list_findings_results = [mock_item]
        mock_scc.list_findings.return_value.pages = [mock_page]
        mock_scc.set_mute.return_value = mock_updated

        async with Client(scc_server) as client:
            call_res = await client.call_tool(
                "set_finding_mute",
                {
                    "project_id": "my-proj",
                    "organization_id": None,
                    "finding_id": "mute-me",
                    "mute": "MUTED",
                },
            )

        assert call_res.is_error is False
        result = json.loads(call_res.content[0].text)
        assert result["success"] is True
        assert result["mute_state"] == "MUTED"
        assert (
            result["finding_name"]
            == "projects/my-proj/sources/123/locations/global/findings/mute-me"
        )

        mock_scc.set_mute.assert_called_once()
        sent_req = mock_scc.set_mute.call_args.kwargs["request"]
        assert isinstance(sent_req, securitycenter_v2.SetMuteRequest)
        assert (
            sent_req.name
            == "projects/my-proj/sources/123/locations/global/findings/mute-me"
        )
        assert sent_req.mute == securitycenter_v2.Finding.Mute.MUTED
