# Copyright 2025 Google LLC
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
"""Security Operations MCP tools for entity lookup."""

import logging
from typing import Optional

from secops_mcp.server import server
from secops_mcp.tools.entity_logic import lookup_entity_impl


# Configure logging
logger = logging.getLogger('secops-mcp')

@server.tool()
async def lookup_entity(
    entity_value: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    hours_back: int = 24,
    region: Optional[str] = None,
) -> str:
    """Look up an entity (IP, domain, hash, user, etc.) in Chronicle SIEM for enrichment.

    Provides a comprehensive summary of an entity's activity based on historical log data
    within Chronicle over a specified time period. This tool queries Chronicle SIEM directly.
    Chronicle automatically attempts to detect the entity type from the value provided.

    **Workflow Integration:**
    - Use this tool after identifying key entities (IPs, domains, users, hashes) from any source
      (e.g., an alert, a SOAR case, threat intelligence report, cloud posture finding).
    - Provides historical context and activity summary for an entity directly from SIEM logs.
    - Complements information available in other security platforms (SOAR, EDR, Cloud Security)
      by offering a log-centric perspective.

    **Use Cases:**
    - Quickly understand the context and prevalence of indicators (e.g., '192.168.1.1',
      'evil.com', 'user@example.com', 'hashvalue') by examining SIEM log data.
    - Reveal historical context, broader relationships, or activity patterns potentially
      missed by other tools.
    - Enrich entities identified in alerts, cases, or reports with SIEM-derived context.

    **Output Summary:**
    The summary includes information observed within the specified time window (`hours_back`):
    - Primary entity details (type, first/last seen within the window).
    - Related entities observed interacting with the primary entity in logs.
    - Associated Chronicle alerts triggered involving the entity within the window.
    - Timeline summary (event/alert counts over the specified period).
    - Prevalence information (if available).

    Args:
        entity_value (str): Value to look up (e.g., IP address, domain name, file hash, username).
        project_id (Optional[str]): Google Cloud project ID. Defaults to environment configuration.
        customer_id (Optional[str]): Chronicle customer ID. Defaults to environment configuration.
        hours_back (int): How many hours of historical data to consider for the summary. Defaults to 24.
        region (Optional[str]): Chronicle region (e.g., "us", "europe"). Defaults to environment configuration.

    Returns:
        str: A formatted string summarizing the entity information found in Chronicle within the specified time window,
             including first/last seen, related entities, and associated alerts.
             Returns 'No information found...' if the entity is not found in the specified timeframe.

    Example Usage:
        lookup_entity(entity_value="198.51.100.10", hours_back=72)

    Next Steps (using MCP-enabled tools):
        - Analyze the summary for suspicious patterns or relationships.
        - If more detailed event logs are needed, use a tool to search SIEM events
          (like `search_security_events`) targeting this entity's value.
        - Correlate findings with data from other security tools (e.g., EDR IoAs, network alerts,
          cloud posture findings, user risk scores) via their respective MCP tools.
        - Document findings in a relevant case management or ticketing system using an appropriate MCP tool.
    """
    return lookup_entity_impl(
        entity_value=entity_value,
        project_id=project_id,
        customer_id=customer_id,
        hours_back=hours_back,
        region=region,
    )
