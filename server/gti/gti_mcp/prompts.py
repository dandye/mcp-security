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
"""Built-in threat intelligence playbook prompts for Google Threat Intelligence."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer


def register_prompts(mcp_server: MCPServer) -> None:
    """Register parameterized threat intelligence prompts on the GTI MCP server."""

    @mcp_server.prompt(
        title="Enrich and Pivot on IOC in Google Threat Intelligence",
        description=(
            "Multi-hop Google Threat Intelligence (GTI) indicator workflow: "
            "classify observable type, fetch reputation and WHOIS/passive DNS "
            "context, pivot across communicating/downloaded files, and map "
            "threat actor or campaign attribution."
        ),
    )
    def enrich_and_pivot_ioc(indicator: str) -> str:
        """Build a multi-hop GTI IOC enrichment and graph-pivoting prompt."""
        return (
            f"Perform a multi-hop Google Threat Intelligence (GTI) enrichment "
            f"and infrastructure pivot on indicator `{indicator}`:\n\n"
            f"1. **Observable Classification & Direct Reputation**\n"
            f"   - Identify whether `{indicator}` is a file hash (MD5/SHA-1/SHA-256), "
            f"domain, IPv4/IPv6 address, or URL.\n"
            f"   - Retrieve its primary report (`gti://files/{{file_hash}}` / "
            f"`get_file_report`, `get_domain_report`, `get_ip_address_report`, "
            f"or `get_url_report`) and record GTI verdict, detection prevalence, "
            f"first/last seen dates, and threat categories.\n\n"
            f"2. **Infrastructure & Passive DNS / WHOIS Pivots**\n"
            f"   - For domains and IPs: inspect `resolutions`, `historical_whois`, "
            f"`historical_ssl_certificates`, `subdomains`, and `urls` via "
            f"`get_entities_related_to_a_domain` or "
            f"`get_entities_related_to_an_ip_address`.\n"
            f"   - For files: inspect `contacted_domains`, `contacted_ips`, "
            f"`contacted_urls`, `dropped_files`, `execution_parents`, and "
            f"`get_file_behavior_summary`.\n\n"
            f"3. **Communicating Files & Campaign Attribution**\n"
            f"   - Pivot on `communicating_files`, `downloaded_files`, or "
            f"`referrer_files` for network indicators, and `associations` / "
            f"`campaigns` / `related_threat_actors` / `malware_families` to "
            f"identify attributed GTI collections (`gti://collections/{{collection_id}}`).\n\n"
            f"4. **Actionable Intelligence Summary**\n"
            f"   - Deliver a confidence-rated assessment (Malicious, Suspicious, "
            f"Benign/Shared Infrastructure, or Unknown), high-confidence "
            f"co-occurring IOCs suitable for Google Security Operations SIEM "
            f"retrohunting, and MITRE ATT&CK techniques."
        )

    @mcp_server.prompt(
        title="Profile GTI Threat Collection and Standard YARA Rules",
        description=(
            "Google Threat Intelligence collection profiling workflow for a "
            "threat actor, malware family, or campaign: inspect "
            "gti://collections/{collection_id}, extract MITRE ATT&CK TTPs, "
            "high-confidence IOCs, and standard YARA file/payload hunting rules."
        ),
    )
    def profile_threat_collection(collection_id: str) -> str:
        """Build a GTI threat collection profiling and standard YARA extraction prompt."""
        return (
            f"Profile Google Threat Intelligence (GTI) collection "
            f"`{collection_id}` and extract actionable hunting artifacts:\n\n"
            f"1. **Collection Overview & Attribution**\n"
            f"   - Read resource `gti://collections/{collection_id}` (or call "
            f"`get_collection_report(id=\"{collection_id}\")`) to determine "
            f"`collection_type` (`threat-actor`, `malware-family`, `campaign`, "
            f"`software-toolkit`, `vulnerability`, or `report`), aliases, "
            f"targeted industries/regions, and active timeline.\n\n"
            f"2. **MITRE ATT&CK TTPs & Relational Graph**\n"
            f"   - Call `get_collection_mitre_tree(id=\"{collection_id}\")` and "
            f"`get_collection_timeline_events(id=\"{collection_id}\")`.\n"
            f"   - Enumerate related `malware_families`, `software_toolkits`, "
            f"`campaigns`, and `vulnerabilities` via "
            f"`get_entities_related_to_a_collection`.\n\n"
            f"3. **High-Confidence IOCs & Infrastructure Commonalities**\n"
            f"   - Retrieve associated `files`, `domains`, `ip_addresses`, and "
            f"`urls` via `get_entities_related_to_a_collection`, and run "
            f"`get_collections_commonalities(collection_id=\"{collection_id}\")` "
            f"to surface shared registrars, ASNs, JA3/JARM, or TLS certificates.\n\n"
            f"4. **Standard YARA Hunting Rulesets**\n"
            f"   - Query the `hunting_rulesets` relationship on `{collection_id}` "
            f"and read `gti://hunting-rulesets/{{ruleset_id}}` (or call "
            f"`get_hunting_ruleset`) to extract **standard YARA** binary/file "
            f"payload matching rules.\n"
            f"   - Important distinction: GTI hunting rulesets contain **standard "
            f"YARA** rules for binary and file payload pattern matching, NOT "
            f"**YARA-L 2.0** UDM event detection rules (use `secops-mcp` to "
            f"author and validate YARA-L 2.0 SIEM telemetry rules)."
        )
