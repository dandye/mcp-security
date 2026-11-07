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
"""Built-in SOC incident response prompts for Google Security Operations SOAR."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer


def register_prompts(mcp_server: MCPServer) -> None:
    """Register parameterized SOAR playbook prompts on the SecOps SOAR MCP server."""

    @mcp_server.prompt(
        title="Investigate Google SecOps SOAR Case",
        description=(
            "Structured Google Security Operations SOAR incident investigation "
            "workflow: inspect soar://cases/{case_id} and "
            "soar://cases/{case_id}/wall, enumerate alert groups and entities, "
            "check duplicate cases, and coordinate enrichment."
        ),
    )
    def investigate_soar_case(case_id: str) -> str:
        """Build a structured SOAR case investigation prompt."""
        return (
            f"Execute a structured Google Security Operations (SecOps) SOAR "
            f"case investigation workflow for case `{case_id}`:\n\n"
            f"1. **Case Overview & Wall Audit Trail**\n"
            f"   - Read `soar://cases/{case_id}` and `soar://cases/{case_id}/wall` "
            f"(or call `get_case_full_details(case_id=\"{case_id}\")`) to review "
            f"current priority, stage, environment, tags, prior playbook runs, "
            f"and existing analyst notes.\n\n"
            f"2. **Alert Grouping & Underlying Telemetry**\n"
            f"   - Call `list_alerts_by_case(case_id=\"{case_id}\")` and "
            f"`list_alert_group_identifiers_by_case(case_id=\"{case_id}\")`.\n"
            f"   - For each alert, inspect underlying raw events via "
            f"`list_events_by_alert` and extract involved entities via "
            f"`get_entities_by_alert_group_identifiers`.\n\n"
            f"3. **Duplicate Case & Historical Entity Correlation**\n"
            f"   - Use `search_entity` and `get_entity_details` across key "
            f"hosts, users, IPs, domains, and hashes to check whether active or "
            f"recently closed SOAR cases (`list_cases`) share the same entities.\n\n"
            f"4. **Cross-Stack Enrichment & Next Steps**\n"
            f"   - Correlate extracted entities in Google Security Operations "
            f"SIEM (`secops-mcp`) and Google Threat Intelligence (`gti-mcp`), "
            f"record findings on the case wall via `post_case_comment`, and "
            f"recommend priority adjustment or verified containment."
        )

    @mcp_server.prompt(
        title="Draft Google SecOps SOAR Case Closure Summary",
        description=(
            "Structured Google Security Operations SOAR case closure workflow: "
            "verify root cause and containment status from case evidence and "
            "draft an executive and technical closure summary."
        ),
    )
    def draft_case_closure_summary(case_id: str) -> str:
        """Build a structured SOAR case closure summary prompt."""
        return (
            f"Prepare a structured Google Security Operations (SecOps) SOAR "
            f"case closure summary for case `{case_id}`:\n\n"
            f"1. **Evidence & Containment Review**\n"
            f"   - Read `soar://cases/{case_id}` and `soar://cases/{case_id}/wall`, "
            f"and inspect linked alerts (`list_alerts_by_case(case_id=\"{case_id}\")`) "
            f"to confirm every alert and involved entity has been accounted for.\n"
            f"   - Verify that all required containment or remediation actions "
            f"(for example host isolation, credential reset, or IOC blocking) "
            f"are completed and documented on the case wall, or confirm why "
            f"containment was unnecessary (Benign Positive / False Positive).\n\n"
            f"2. **Executive & Technical Closure Report**\n"
            f"   - Draft a concise closure report covering:\n"
            f"     * **Disposition & Severity**: True Positive, Benign Positive, "
            f"or False Positive.\n"
            f"     * **Root Cause & Close Reason**: Mapped to valid SOAR `close_case` "
            f"`reason` (`Malicious`, `Maintenance`, `Inconclusive`, `Unknown`) "
            f"and `root_cause` values.\n"
            f"     * **Timeline & Blast Radius**: Key UTC timestamps and affected "
            f"assets/identities.\n"
            f"     * **Follow-Up Actions**: Detection rule tuning or posture "
            f"hardening recommendations.\n\n"
            f"3. **Operator Sign-Off**\n"
            f"   - Present the closure summary and proposed `post_case_comment` / "
            f"`close_case` parameters for confirmation before closing the case."
        )
