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
"""Built-in SOC playbook prompts for Google Security Operations SIEM."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer


def register_prompts(mcp_server: MCPServer) -> None:
    """Register parameterized SOC playbook prompts on the SecOps MCP server."""

    @mcp_server.prompt(
        title="Triage Google SecOps SIEM Alert",
        description=(
            "Structured SOC alert triage workflow for Google Security Operations "
            "SIEM: inspect secops://alerts/{alert_id}, reconstruct UDM entity "
            "timelines over lookback_hours, correlate IOC matches, and record a "
            "defensible disposition."
        ),
    )
    def triage_siem_alert(alert_id: str, lookback_hours: int = 168) -> str:
        """Build a structured SIEM alert triage prompt."""
        return (
            f"Execute a structured Google Security Operations (SecOps) SIEM alert "
            f"triage workflow for alert `{alert_id}` over a `{lookback_hours}`-hour "
            f"UDM lookback window:\n\n"
            f"1. **Alert & Detection Rule Inspection**\n"
            f"   - Read resource `secops://alerts/{alert_id}` (or call "
            f"`get_security_alert_by_id(alert_id=\"{alert_id}\", include_detections=True)`) "
            f"to extract the triggering YARA-L 2.0 detection rule ID, rule name, "
            f"severity, feedback status, associated SOAR case, and involved UDM "
            f"entities (principal/target/src hostnames, IPs, users, hashes, domains).\n"
            f"   - If a YARA-L 2.0 rule ID is present, read `secops://rules/{{rule_id}}` "
            f"to inspect the exact UDM event logic and exclusions.\n\n"
            f"2. **Entity Context & IOC Correlation ({lookback_hours}h Horizon)**\n"
            f"   - Run `lookup_entity` for each primary asset, user, IP, domain, "
            f"and file hash extracted from the alert detections.\n"
            f"   - Check `get_ioc_matches` to verify whether any observed network "
            f"or file artifacts match active threat intelligence feeds.\n\n"
            f"3. **UDM Telemetry Timeline Reconstruction**\n"
            f"   - Query `search_security_events` over `hours_back={lookback_hours}` "
            f"around the alert timestamp to reconstruct parent-child process "
            f"execution (`PROCESS_LAUNCH`), authentication (`USER_LOGIN`), DNS "
            f"queries (`NETWORK_DNS`), and outbound network connections "
            f"(`NETWORK_CONNECTION`).\n\n"
            f"4. **Disposition & Recommended Actions**\n"
            f"   - Classify the alert as True Positive, Benign Positive, or False "
            f"Positive with concrete UDM evidence.\n"
            f"   - Summarize scope, affected entities, and whether `do_update_security_alert` "
            f"or SOAR containment escalation is warranted."
        )

    @mcp_server.prompt(
        title="Validate and Tune YARA-L 2.0 SIEM Detection Rule",
        description=(
            "Detection engineering workflow for Google Security Operations "
            "YARA-L 2.0 (YL2) SIEM UDM event detection rules (distinct from "
            "standard YARA file/payload rules): validate syntax, run bounded "
            "retrohunt via test_rule, assess false positives, and tune performance."
        ),
    )
    def validate_yaral2_detection_rule(rule_text: str) -> str:
        """Build a YARA-L 2.0 SIEM UDM rule validation and tuning prompt."""
        return (
            "Execute a Google Security Operations (SecOps) SIEM detection "
            "engineering validation and tuning workflow for the following "
            "**YARA-L 2.0 (YL2)** UDM event detection rule.\n\n"
            "Important distinction: YARA-L 2.0 rules match structured Unified Data "
            "Model (UDM) security telemetry (`meta`, `events`, `match`, `outcome`, "
            "`condition` sections) in Google Security Operations SIEM. Do NOT "
            "confuse YARA-L 2.0 with standard YARA binary/file byte-pattern "
            "rulesets managed in `gti-mcp`.\n\n"
            f"```yaral\n{rule_text}\n```\n\n"
            "Workflow steps:\n"
            "1. **Syntax & Schema Validation**: Call `validate_rule` with `rule_text` "
            "to verify YARA-L 2.0 grammar, UDM field paths, `outcome` aggregations, "
            "and `match` window variables. If validation fails, diagnose the exact "
            "line/field error and propose a corrected YARA-L 2.0 rule.\n"
            "2. **Bounded Retrohunt (`test_rule`)**: Once `validate_rule` passes, "
            "run `test_rule` over a bounded historical UDM window (for example "
            "24 to 72 hours) to measure detection volume and inspect sample UDM "
            "detections.\n"
            "3. **False-Positive & Reference List Review**: Analyze sample matches "
            "for benign administrative tools, vulnerability scanners, or known "
            "service accounts. Check relevant `secops://reference-lists/{name}` "
            "allowlists via `list_reference_lists` / `get_reference_list`.\n"
            "4. **Performance & Precision Tuning**: Ensure event predicates filter "
            "early on indexed UDM fields (`metadata.event_type`, exact string "
            "comparisons before unanchored regular expressions) and summarize the "
            "final deployment recommendation before calling `create_rule` or `update_rule`."
        )

    @mcp_server.prompt(
        title="Hunt UDM Entity Timeline in Google SecOps",
        description=(
            "Proactive threat hunting workflow across Google Security Operations "
            "UDM telemetry for a target entity (hostname, username, IP, domain, "
            "or hash) with process-lineage and lateral-movement reconstruction."
        ),
    )
    def hunt_entity_timeline(entity_value: str, hours: int = 72) -> str:
        """Build a proactive UDM entity timeline threat hunt prompt."""
        return (
            f"Conduct a proactive Google Security Operations (SecOps) SIEM threat "
            f"hunt for entity `{entity_value}` across a `{hours}`-hour UDM "
            f"telemetry window:\n\n"
            f"1. **Baseline Entity Context**\n"
            f"   - Call `lookup_entity(entity_value=\"{entity_value}\", hours_back={hours})` "
            f"to establish asset/user identity, prevalence, first/last seen "
            f"timestamps, and related alerts.\n\n"
            f"2. **Process Lineage & Execution Hunt**\n"
            f"   - Use `search_security_events` (`hours_back={hours}`) to query "
            f"`PROCESS_LAUNCH`, `FILE_CREATION`, and `REGISTRY_MODIFICATION` UDM "
            f"events involving `{entity_value}`, reconstructing parent-child "
            f"command lines, living-off-the-land binaries, and unsigned executables.\n\n"
            f"3. **Authentication, DNS, & Lateral Movement Pivot**\n"
            f"   - Query `USER_LOGIN`, `NETWORK_DNS`, `NETWORK_HTTP`, and "
            f"`NETWORK_CONNECTION` UDM events over `{hours}` hours to identify "
            f"anomalous logons, rare external destinations, beaconing intervals, "
            f"or internal SMB/RDP/WinRM/SSH lateral movement.\n\n"
            f"4. **Timeline Synthesis & Detection Gap Check**\n"
            f"   - Produce a chronological UTC timeline of suspicious activity, "
            f"check `search_security_rules` for existing YARA-L 2.0 UDM coverage, "
            f"and highlight any detection gaps or IOCs requiring `gti-mcp` enrichment."
        )
