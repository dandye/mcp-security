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
"""Security Operations MCP tools for reference list management."""

import logging
from typing import Any, Dict, List, Optional

from secops_mcp.server import server
from secops_mcp.tools.reference_list_logic import (
    create_reference_list_impl,
    get_reference_list_impl,
    update_reference_list_impl,
)

# Configure logging
logger = logging.getLogger('secops-mcp')

@server.tool()
async def create_reference_list(
    name: str,
    description: str,
    entries: List[str],
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    syntax_type: str = "STRING",
) -> str:
    """Create a new reference list in Chronicle SIEM.

    Creates a reference list containing a collection of values that can be referenced in
    detection rules. Reference lists are useful for maintaining lists of known entities
    like IP addresses, domains, usernames, or other indicators that enhance detection logic.

    **Workflow Integration:**
    - Use to create curated lists of security-relevant entities for detection enhancement.
    - Essential for maintaining allowlists, blocklists, or other categorized entity collections.
    - Enables dynamic detection rule behavior without hardcoding values in rule logic.
    - Supports threat intelligence integration by storing IOC lists in a searchable format.

    **Use Cases:**
    - Create lists of trusted domains or IP ranges to reduce false positives.
    - Maintain lists of privileged user accounts for monitoring access patterns.
    - Store lists of malicious file hashes for detection and blocking.
    - Build collections of known bad domains from threat intelligence feeds.
    - Create regex patterns for detecting specific attack signatures or behaviors.

    **Syntax Types:**
    - STRING: Exact string matching (default)
    - CIDR: IP address ranges and CIDR blocks  
    - REGEX: Regular expression patterns for flexible matching

    Args:
        name (str): Unique name for the reference list (used to reference in detection rules).
        description (str): Description of the reference list's purpose and contents.
        entries (List[str]): List of values to include in the reference list.
        project_id (str): Google Cloud project ID (required).
        customer_id (str): Chronicle customer ID (required).
        region (str): Chronicle region (e.g., "us", "europe") (required).
        syntax_type (str): Type of matching to use. Valid values: "STRING", "CIDR", "REGEX". Defaults to "STRING".

    Returns:
        str: Success message with the created reference list details.
             Returns error message if list creation fails.

    Example Usage:
        # Create a list of administrative accounts
        create_reference_list(
            name="admin_accounts",
            description="Administrative user accounts for privilege monitoring",
            entries=["admin", "administrator", "root", "system", "service"],
            project_id="my-project",
            customer_id="my-customer",
            region="us",
            syntax_type="STRING"
        )

        # Create a list of trusted networks
        create_reference_list(
            name="trusted_networks",
            description="Internal network ranges that are considered trusted",
            entries=["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
            project_id="my-project",
            customer_id="my-customer",
            region="us",
            syntax_type="CIDR"
        )

        # Create regex patterns for suspicious email patterns
        create_reference_list(
            name="suspicious_email_patterns",
            description="Email patterns that may indicate phishing attempts",
            entries=[".*@suspicious\\.com", "malicious_.*@.*\\.org", ".*phishing.*@.*"],
            project_id="my-project",
            customer_id="my-customer",
            region="us",
            syntax_type="REGEX"
        )

    Next Steps (using MCP-enabled tools):
        - Reference the list in detection rules using the list name (e.g., reference_list.admin_accounts).
        - Update the list using `update_reference_list` as your data changes.
        - Retrieve the list contents using `get_reference_list` to verify entries.
        - Create detection rules that leverage the list for enhanced threat detection.
        - Set up automated processes to maintain the list with current threat intelligence.
    """
    return create_reference_list_impl(
        name=name,
        description=description,
        entries=entries,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
        syntax_type=syntax_type,
    )

@server.tool()
async def get_reference_list(
    name: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    include_entries: bool = True,
) -> str:
    """Get details and contents of a reference list in Chronicle SIEM.

    Retrieves the metadata and optionally the full contents of a reference list. This is
    useful for reviewing list contents, verifying data integrity, and understanding what
    data is available for detection rules.



    **Workflow Integration:**
    - Use to verify reference list contents before creating or modifying detection rules.
    - Essential for auditing data quality and consistency in security reference data.
    - Helps understand available data when troubleshooting detection rule issues.
    - Supports data governance by providing visibility into managed security datasets.

    **Use Cases:**
    - Review threat intelligence lists before implementing new detection rules.
    - Verify that allowlists or blocklists contain the expected entries.
    - Audit reference list contents for compliance or security reviews.
    - Troubleshoot detection rule issues by examining referenced list data.
    - Generate reports on security reference data for operational documentation.

    Args:
        name (str): Name of the reference list to retrieve.
        project_id (str): Google Cloud project ID (required).
        customer_id (str): Chronicle customer ID (required).
        region (str): Chronicle region (e.g., "us", "europe") (required).
        include_entries (bool): Whether to include the full list of entries. Defaults to True.

    Returns:
        str: Formatted reference list details including metadata and entries.
             Returns error message if retrieval fails.

    Example Usage:
        # Get full details of an admin accounts list
        get_reference_list(
            name="admin_accounts",
            project_id="my-project",
            customer_id="my-customer",
            region="us",
            include_entries=True
        )

        # Get metadata only for a large reference list
        get_reference_list(
            name="threat_ip_addresses",
            project_id="my-project",
            customer_id="my-customer",
            region="us",
            include_entries=False
        )

    Next Steps (using MCP-enabled tools):
        - Update the list using `update_reference_list` if changes are needed.
        - Reference the list data in detection rules to enhance security monitoring.
        - Compare with external threat intelligence sources to identify updates needed.
        - Document the list contents and update procedures for operational teams.
        - Set up regular reviews to maintain data quality and relevance.
    """
    return get_reference_list_impl(
        name=name,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
        include_entries=include_entries,
    )

@server.tool()
async def update_reference_list(
    name: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    entries: Optional[List[str]] = None,
    description: Optional[str] = None,
) -> str:
    """Update an existing reference list in Chronicle SIEM.

    Updates the contents or description of an existing reference list. This is useful for
    maintaining current threat intelligence, updating allowlists/blocklists, or modifying
    reference data as your security requirements evolve.



    **Workflow Integration:**
    - Use to keep reference lists current with the latest threat intelligence or policy changes.
    - Essential for maintaining accurate security reference data used in detection rules.
    - Enables automated reference list updates as part of threat intelligence feeds.
    - Supports operational workflows that modify security policies or allowlists.

    **Use Cases:**
    - Update threat intelligence lists with newly discovered IOCs.
    - Modify allowlists to include new trusted domains or IP ranges.
    - Remove outdated or invalid entries from reference lists.
    - Update user lists as organizational structure changes.
    - Refresh regex patterns to improve detection accuracy.

    **Update Behavior:**
    - If entries are provided, they completely replace the existing entries.
    - If description is provided, it updates the reference list description.
    - At least one of entries or description must be provided.

    Args:
        name (str): Name of the existing reference list to update.
        project_id (str): Google Cloud project ID (required).
        customer_id (str): Chronicle customer ID (required).
        region (str): Chronicle region (e.g., "us", "europe") (required).
        entries (Optional[List[str]]): New list of entries to replace existing ones. If provided, completely replaces current entries.
        description (Optional[str]): New description for the reference list.

    Returns:
        str: Success message with details about the updated reference list.
             Returns error message if update fails.

    Example Usage:
        # Update entries in an admin accounts list
        update_reference_list(
            name="admin_accounts",
            entries=["admin", "administrator", "root", "system", "service", "superuser"],
            project_id="my-project",
            customer_id="my-customer",
            region="us"
        )

        # Update description only
        update_reference_list(
            name="admin_accounts",
            description="Updated administrative user accounts for enhanced privilege monitoring",
            project_id="my-project",
            customer_id="my-customer",
            region="us"
        )

        # Update both entries and description
        update_reference_list(
            name="trusted_networks",
            entries=["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "203.0.113.0/24"],
            description="Updated trusted network ranges including new office location",
            project_id="my-project",
            customer_id="my-customer",
            region="us"
        )

    Next Steps (using MCP-enabled tools):
        - Verify the updates using `get_reference_list` to confirm changes were applied correctly.
        - Test detection rules that reference the updated list to ensure they work as expected.
        - Monitor detection rule performance to assess the impact of the changes.
        - Document the reason for updates for audit and operational tracking.
        - Communicate significant changes to teams that rely on the reference list.
    """
    return update_reference_list_impl(
        name=name,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
        entries=entries,
        description=description,
    )
