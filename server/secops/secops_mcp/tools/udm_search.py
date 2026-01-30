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
"""Security Operations MCP tools for UDM search and export."""

import logging
from typing import Any, Dict, List, Optional

from secops_mcp.server import server
from secops_mcp.tools.udm_search_logic import (
    export_udm_search_csv_impl,
    find_udm_field_values_impl,
)

# Configure logging
logger = logging.getLogger("secops-mcp")


@server.tool()
async def export_udm_search_csv(
    query: str,
    fields: List[str],
    hours_back: int = 24,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    case_insensitive: bool = True,
    project_id: str = None,
    customer_id: str = None,
    region: str = None,
) -> str:
    """Export UDM search results to CSV format for analysis and reporting.

    Executes a UDM query and returns results in CSV format with specified fields.
    This tool is ideal for exporting security event data for offline analysis,
    reporting, or integration with other security tools.

    **Workflow Integration:**
    - Use after identifying relevant events through search_security_events to export detailed data.
    - Essential for creating reports, conducting forensic analysis, or sharing findings.
    - Enables data export for further analysis in spreadsheet applications or data science tools.
    - Supports compliance reporting by extracting event data in standard formats.

    **Use Cases:**
    - Export authentication events for user behavior analysis in external tools.
    - Extract network connection logs for threat hunting in data analysis platforms.
    - Generate CSV reports of security incidents for management review.
    - Export IOC-related events for correlation with threat intelligence platforms.
    - Create audit trails by exporting specific event types over time periods.

    **Common Field Examples:**
    - metadata.event_timestamp: Event occurrence time
    - principal.user.userid: User performing the action
    - target.hostname: Target system name
    - network.ip: IP addresses involved
    - security_result.summary: Security outcome
    - metadata.event_type: Type of security event
    - principal.ip: Source IP address
    - target.url: Target URL accessed
    - metadata.product_name: Source product generating the event

    Args:
        query (str): UDM query to search for events. Use Chronicle query syntax.
                    Examples:
                    - 'metadata.event_type = "USER_LOGIN"'
                    - 'principal.ip = "192.168.1.100"'
                    - 'target.hostname = "server1" AND metadata.event_type = "FILE_MODIFICATION"'
        fields (List[str]): List of UDM fields to include in the CSV export.
                           Each field will become a column in the output.
        hours_back (int): How many hours back from the current time to search. Used if start_time is not provided.
        start_time (Optional[str]): Start time in ISO 8601 format (e.g. "2023-01-01T00:00:00Z"). Overrides hours_back.
        end_time (Optional[str]): End time in ISO 8601 format. Defaults to current time if not provided.
        case_insensitive (bool): Whether to perform case-insensitive search. Defaults to True.
        project_id (Optional[str]): Google Cloud project ID. Defaults to environment configuration.
        customer_id (Optional[str]): Chronicle customer ID. Defaults to environment configuration.
        region (Optional[str]): Chronicle region (e.g., "us", "europe"). Defaults to environment configuration.

    Returns:
        str: CSV formatted string with header row and data rows. Empty result returns header row only.
             Returns error message if the export fails.

    Example Usage:
        # Export login events with specific fields
        export_udm_search_csv(
            query='metadata.event_type = "USER_LOGIN"',
            fields=[
                "metadata.event_timestamp",
                "principal.user.userid",
                "principal.ip",
                "target.hostname",
                "security_result.summary"
            ],
            hours_back=48
        )

        # Export network connections to specific IP
        export_udm_search_csv(
            query='network.ip = "10.0.0.5"',
            fields=[
                "metadata.event_timestamp",
                "principal.hostname",
                "target.ip",
                "network.sent_bytes",
                "network.received_bytes"
            ],
            hours_back=72
        )

    Next Steps (using MCP-enabled tools):
        - Import the CSV into data analysis tools for statistical analysis or visualization.
        - Use exported data to create detection rules based on observed patterns.
        - Share CSV reports with stakeholders through appropriate communication channels.
        - Archive exports for compliance or forensic purposes.
        - Correlate exported data with information from other security platforms.

    **Troubleshooting:**
    - If no results are returned, verify the query syntax and time range.
    - For large datasets, consider using more specific queries to reduce result size.
    - Check field names against Chronicle's UDM schema for correct paths.
    - Use case_insensitive=False for exact matching when needed.
    """
    return export_udm_search_csv_impl(
        query=query,
        fields=fields,
        hours_back=hours_back,
        start_time=start_time,
        end_time=end_time,
        case_insensitive=case_insensitive,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
    )


@server.tool()
async def find_udm_field_values(
    query: str,
    page_size: Optional[int] = None,
    project_id: str = None,
    customer_id: str = None,
    region: str = None,
) -> Dict[str, Any]:
    """Find and autocomplete UDM field values in Chronicle SIEM.

    Searches for UDM field values that match a partial query string, providing
    autocomplete functionality for building queries and understanding available
    data in your Chronicle instance. This tool helps discover valid field values
    without needing to know exact matches.

    **Workflow Integration:**
    - Use before building complex UDM queries to discover valid field values.
    - Essential for understanding what data is available in your Chronicle instance.
    - Helps validate IOCs or entity values exist before creating detection rules.
    - Supports investigation by finding variations of usernames, hostnames, or IPs.

    **Use Cases:**
    - Find all hostnames starting with "server" to build targeted queries.
    - Discover user account variations (e.g., searching "john" finds "john.doe", "johnson").
    - Validate if specific IP addresses or domains exist in your data.
    - Explore available event types or product names for query building.
    - Find all values for enumerated fields to understand data patterns.

    **Common Search Patterns:**
    - Partial hostname: "web-" to find "web-server-01", "web-app-02"
    - Username prefix: "admin" to find "administrator", "admin_user"
    - IP subnet: "192.168" to find IPs in that range
    - Domain search: ".example.com" to find all subdomains
    - Event type discovery: "USER_" to find all user-related event types

    Args:
        query (str): The partial UDM field value to search for. Supports prefix, suffix,
                    or substring matching depending on Chronicle's implementation.
        page_size (Optional[int]): Maximum number of matching values to return.
                                  If not specified, uses Chronicle's default limit.
        project_id (Optional[str]): Google Cloud project ID. Defaults to environment configuration.
        customer_id (Optional[str]): Chronicle customer ID. Defaults to environment configuration.
        region (Optional[str]): Chronicle region (e.g., "us", "europe"). Defaults to environment configuration.

    Returns:
        Dict[str, Any]: A dictionary containing:
            - 'values' (List[Dict]): List of matching field values with metadata.
            - 'total_count' (int): Total number of matching values found.
            - Additional metadata fields as provided by Chronicle.
            Returns error details if the search fails.

    Example Usage:
        # Find all hostnames containing "prod"
        find_udm_field_values(
            query="prod",
            page_size=50
        )

        # Discover usernames starting with "service"
        find_udm_field_values(
            query="service",
            page_size=100
        )

        # Find IP addresses in a specific range
        find_udm_field_values(
            query="10.0.0.",
            page_size=200
        )

    Next Steps (using MCP-enabled tools):
        - Use discovered values to build precise UDM queries with search_security_events.
        - Create detection rules targeting specific field values found.
        - Build reference lists from discovered values for use in detection logic.
        - Investigate specific entities by using exact values in entity lookup tools.
        - Document common field values for team reference and query templates.

    **Tips for Effective Use:**
    - Start with broad prefixes and narrow down based on results.
    - Use this tool to validate entity existence before deep investigation.
    - Combine with search_security_events to understand context around values.
    - Regular use helps maintain awareness of data patterns in your environment.
    """
    return find_udm_field_values_impl(
        query=query,
        page_size=page_size,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
    )
