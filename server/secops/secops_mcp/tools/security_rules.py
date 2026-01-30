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
"""Security Operations MCP tools for security rules."""

import logging
from typing import Any, Dict, Optional

from secops_mcp.server import server
from secops_mcp.tools.rules_logic import (
    create_rule_impl,
    get_detection_rule_impl,
    get_rule_detections_impl,
    list_rule_errors_impl,
    list_rules_impl,
    search_security_rules_impl,
    test_rule_impl,
    validate_rule_impl,
)


# Configure logging
logger = logging.getLogger("secops-mcp")


@server.tool()
async def list_security_rules(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    page_size: int = 100,
    page_token: str | None = None,
) -> Dict[str, Any]:
    """List security detection rules configured in Chronicle SIEM, with support for pagination.

    Retrieves the definitions of detection rules currently active or configured
    within the Chronicle SIEM instance.



    **Workflow Integration:**
    - Useful for understanding the detection capabilities currently deployed in the SIEM.
    - Can help identify the specific rule that generated a SIEM alert (obtained via SIEM alert tools
      or from case management/SOAR system details).
    - Provides context for rule tuning, development, or understanding alert logic.

    **Use Cases:**
    - Review the logic or scope of a specific detection rule identified from an alert.
    - Audit the set of active detection rules within the SIEM.
    - Understand which rules might be relevant to a particular threat scenario or TTP.

    Args:
        project_id (str): Google Cloud project ID (required).
        customer_id (str): Chronicle customer ID (required).
        region (str): Chronicle region (e.g., "us", "europe") (required).
        page_size (int): Maximum number of rules to return. Defaults to 100. Max is 1000.
        page_token (str | None): Page token for pagination.

    Returns:
        Dict[str, Any]: Raw response from the Chronicle API, typically containing a list
                        of rule objects with their definitions and metadata. Returns an
                        error structure if the API call fails.

    Next Steps (using MCP-enabled tools):
        - Analyze the rule definition (e.g., the YARA-L code) to understand its trigger conditions.
        - Correlate rule details with specific alerts retrieved from the SIEM or case management system.
        - Use insights for rule optimization, false positive analysis, or developing related detections.
        - Document relevant rule information in associated cases using a case management tool.
    """
    return list_rules_impl(
        project_id=project_id,
        customer_id=customer_id,
        region=region,
        page_size=page_size,
        page_token=page_token,
    )


@server.tool()
async def search_security_rules(
    query: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Search security detection rules configured in Chronicle SIEM.

    Retrieves the definitions of detection rules currently active or configured
    within the Chronicle SIEM instance based on a regex pattern.

    **Workflow Integration:**
    - Useful for understanding the detection capabilities currently deployed in the SIEM.
    - Can help identify the specific rule that generated a SIEM alert (obtained via SIEM alert tools
      or from case management/SOAR system details).
    - Provides context for rule tuning, development, or understanding alert logic.

    **Use Cases:**
    - Review the logic or scope of a specific detection rule identified from an alert.
    - Audit the set of active detection rules within the SIEM.
    - Understand which rules might be relevant to a particular threat scenario or TTP.

    **Examples:**
    - Searching for all rules related to a specific MITRE technique like "TA0005" for defense evasion detections.
    - Searching for static data coded into detections like a specific hostname or IP address like "192.168.1.1".
    - Searching for rules that reference a specific log_type like "WORKSPACE"

    Args:
        query (str): Regex string to use for searching SecOps rules.
        project_id (Optional[str]): Google Cloud project ID. Defaults to environment configuration.
        customer_id (Optional[str]): Chronicle customer ID. Defaults to environment configuration.
        region (Optional[str]): Chronicle region (e.g., "us", "europe"). Defaults to environment configuration.

    Returns:
        Dict[str, Any]: Raw response from the Chronicle API, typically containing a list
                        of rule objects with their definitions and metadata. Returns an
                        error structure if the API call fails.

    Next Steps (using MCP-enabled tools):
        - Analyze the rule definition (e.g., the YARA-L code) to understand its trigger conditions.
        - Correlate rule details with specific alerts retrieved from the SIEM or case management system.
        - Use insights for rule optimization, false positive analysis, or developing related detections.
        - Document relevant rule information in associated cases using a case management tool.
    """
    return search_security_rules_impl(
        query=query,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
    )


@server.tool()
async def get_detection_rule(
    rule_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieve the complete definition and metadata of a specific detection rule from Chronicle SIEM.

    Fetches the full rule content including YARA-L code, metadata, configuration,
    and status information for a specific detection rule by its RuleId. This is essential
    for reviewing, analyzing, or modifying existing detection rules.

    **Workflow Integration:**
    - Use when you need to examine the complete logic and configuration of a specific detection rule.
    - Essential for rule analysis, debugging, or understanding how a particular alert was generated.
    - Useful for copying or modifying existing rules as templates for new detections.
    - Critical for compliance audits or rule documentation processes.

    **Use Cases:**
    - Retrieve rule content to understand detection logic after an alert is triggered.
    - Copy existing rule definitions as starting points for new custom rules.
    - Analyze rule metadata and configuration for operational documentation.
    - Review rule syntax and conditions for troubleshooting or optimization.
    - Extract rule content for backup, version control, or migration purposes.
    - Examine rule versioning and modification history.

    **Rule Analysis Capabilities:**
    - Complete YARA-L 2.0 rule text with all conditions and logic
    - Rule metadata including description, author, severity, and MITRE mappings
    - Rule configuration including severity, author, and scheduling frequency
    - Version information and timestamps
    - Associated rule ID, display name, and revision tracking

    Args:
        rule_id (str): Unique ID of the detection rule to retrieve.
                      Examples: "ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (latest version),
                      "ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@v_12345_67890" (specific version).
                      If no version suffix is provided, the latest version is returned.
        project_id (Optional[str]): Google Cloud project ID. Defaults to environment configuration.
        customer_id (Optional[str]): Chronicle customer ID. Defaults to environment configuration.
        region (Optional[str]): Chronicle region (e.g., "us", "europe"). Defaults to environment configuration.

    Returns:
        Dict[str, Any]: Complete rule information including:
                       - Rule text (YARA-L code)
                       - Metadata (description, author, severity, etc.)
                       - Configuration and status information
                       - Version and timestamp details
                       Returns error structure if the API call fails.

    Example Usage:
        # Get the latest version of a rule
        rule_content = get_detection_rule("ru_661a3961-7370-4be7-abda-f233f7ff29ac")

        # Get a specific version of a rule
        rule_content = get_detection_rule("ru_661a3961-7370-4be7-abda-f233f7ff29ac@v_1234567890_123456789")

    Next Steps (using MCP-enabled tools):
        - Analyze the rule text to understand detection logic and conditions.
        - Use the rule content as a template for creating similar detection rules with `create_rule`.
        - Test rule modifications using `test_rule` before deploying changes.
        - Validate rule syntax using `validate_rule` if making modifications.
        - Monitor rule performance using `get_rule_detections` and `list_rule_errors`.
        - Document rule purpose and logic for operational teams and compliance audits.
    """
    return get_detection_rule_impl(
        rule_id=rule_id,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
    )


@server.tool()
async def get_rule_detections(
    rule_id: str,
    alert_state: Optional[str] = None,
    page_size: Optional[int] = None,
    page_token: Optional[str] = None,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Retrieves historical detections generated by a specific Chronicle SIEM rule.

    This tool fetches detections based on a rule ID, allowing for investigation
    and analysis of rule performance and threat activity.

    **Workflow Integration:**
    - **Alert Triage:** When an alert is generated by a rule, use this tool to retrieve all historical detections for that rule to understand the context and frequency.
    - **Rule Effectiveness Analysis:** Analyze the volume, timestamps, and details of detections to determine if a rule is too noisy, too quiet, or performing as expected.
    - **Threat Hunting:** If a rule is designed to detect a specific TTP or indicator, use this tool to find all instances where the rule has matched historical data.
    - **Incident Scoping:** During an incident, if a particular rule is relevant, retrieve its detections to help identify the scope and timeline of related events.
    - **Compliance Reporting:** Gather detections for specific rules related to compliance mandates over a certain period.

    **Use Cases:**
    - Retrieve all detections for a rule ID obtained from a SIEM alert or a case management system.
    - Filter detections by their alert state (e.g., "ALERTING", "NOT_ALERTING") to focus on actionable events.
    - Paginate through a large number of detections if a rule is particularly verbose.
    - Monitor the output of a newly deployed or recently modified detection rule.
    - Investigate past occurrences of a threat detected by a specific rule.
    - Assess the Alert to determine liklihood of maliciousness

    Args:
        rule_id (str): Unique ID of the rule to list detections for.
                        Examples: "ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (latest version),
                        "ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@v_12345_67890" (specific version),
                        "ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@-" (all versions).
        alert_state (Optional[str]): If provided, filter by alert state.
                                     Valid values: "UNSPECIFIED", "NOT_ALERTING", "ALERTING".
        page_size (Optional[int]): If provided, the maximum number of detections to return in a single response.
        page_token (Optional[str]): If provided, a token to retrieve the next page of results for pagination.
        project_id (Optional[str]): Google Cloud project ID. Defaults to environment configuration.
        customer_id (Optional[str]): Chronicle customer ID. Defaults to environment configuration.
        region (Optional[str]): Chronicle region (e.g., "us", "europe"). Defaults to environment configuration.

    Returns:
        Dict[str, Any]: A dictionary containing the list of detections (under a 'detections' key, typically)
                        and pagination information (e.g., 'nextPageToken'). Returns an error
                        structure if the API call fails. The exact structure depends on the
                        Chronicle API version and client implementation.

    Next Steps (using MCP-enabled tools):
        - **Analyze Composite Detections:** If the CollectionElments contain additional Detection IDs, retrieve those detections and analyze the events as well
        - **Enrich Observables:** Extract indicators (IPs, domains, hashes) from the detection details or related UDM events and use threat intelligence tools for enrichment.
        - **Case Management:** If detections reveal significant activity, create or update incidents in a case management or SOAR system.
        - **Rule Tuning:** Based on the nature and volume of detections (e.g., many false positives), consider modifying the rule logic (using a hypothetical `update_rule` tool) or its alerting configuration (using `enable_rule` or similar).
        - **Retro-Hunting:** If the rule was recently updated or if you want to test variations, initiate a new retrohunt (e.g., using `create_retrohunt`).
        - **Error Checking:** If detections are missing or behavior is unexpected, check for rule execution errors (e.g., using `list_errors`).
        - **Visualize Detections:** Export detection data and use data visualization tools to identify trends or patterns over time.
    """
    return get_rule_detections_impl(
        rule_id=rule_id,
        alert_state=alert_state,
        page_size=page_size,
        page_token=page_token,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
    )


# Example of how list_errors might be defined as an MCP tool, if needed later.
# This is based on the second function in the first code block provided by the user.
@server.tool()
async def list_rule_errors(
    rule_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Lists execution errors for a specific Chronicle SIEM rule.

    Helps in troubleshooting rules that might not be generating detections as expected
    or are failing during execution.

    **Workflow Integration:**
    - **Rule Troubleshooting:** If a rule is not producing expected detections or alerts, check for execution errors.
    - **Rule Development:** After deploying a new or modified rule, check for errors to ensure it's syntactically correct and running properly.
    - **SIEM Health Monitoring:** Periodically check for rules with high error counts to maintain SIEM operational health.

    **Use Cases:**
    - Investigate why a specific rule (e.g., "ru_...") has not generated any detections.
    - Check for errors after modifying and saving a YARA-L rule.
    - Get details of compilation or runtime errors for a given rule version.

    Args:
        rule_id (str): Unique ID of the rule to list errors for.
                        Examples: "ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (latest version),
                        "ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@v_12345_67890" (specific version),
                        "ru_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@-" (all versions).
        project_id (Optional[str]): Google Cloud project ID. Defaults to environment configuration.
        customer_id (Optional[str]): Chronicle customer ID. Defaults to environment configuration.
        region (Optional[str]): Chronicle region (e.g., "us", "europe"). Defaults to environment configuration.

    Returns:
        Dict[str, Any]: A dictionary containing rule execution errors. The structure depends on the API.
                        Returns an error structure if the API call fails.

    Next Steps (using MCP-enabled tools):
        - **Review Rule Code:** If errors are found, retrieve the rule definition using `list_security_rules` or a hypothetical `get_rule_definition` tool and analyze the YARA-L code.
        - **Validate Rule Syntax:** Use a rule validation tool (like a hypothetical `validate_rule_syntax` tool or offline YARA-L validators) to check for syntax issues.
        - **Modify Rule:** Correct the rule based on error messages and update it in Chronicle.
        - **Re-check Detections:** After fixing errors, use `get_rule_detections` to see if the rule now produces detections.
    """
    return list_rule_errors_impl(
        rule_id=rule_id,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
    )


@server.tool()
async def create_rule(
    rule_text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Create a new detection rule in Chronicle SIEM.

    Creates a new YARA-L 2.0 detection rule in Chronicle that can generate alerts when
    the rule conditions are met by ingested events. Rules are the core mechanism for
    automated threat detection and response in Chronicle.



    **Workflow Integration:**
    - Essential for implementing custom detection logic based on your organization's security requirements.
    - Use after analyzing events, entities, or threat intelligence to codify detection patterns.
    - Complements existing detection capabilities by addressing specific use cases or threat scenarios.
    - Enables automated detection of TTPs, IOCs, or behavioral patterns identified through investigations.

    **Use Cases:**
    - Create rules to detect specific attack patterns discovered during threat hunting.
    - Implement custom detection logic for proprietary applications or unique network configurations.
    - Detect compliance violations or policy breaches specific to your organization.
    - Create behavioral detection rules based on user or entity activity patterns.
    - Implement detection for specific threat intelligence indicators relevant to your environment.

    **Rule Development Best Practices:**
    - Start with a clear understanding of what you want to detect and the data sources available.
    - Use precise conditions to minimize false positives while maintaining detection efficacy.
    - Include appropriate metadata (description, author, severity, MITRE ATT&CK mappings).
    - Test rules thoroughly using `test_rule` before deploying to production.
    - Consider the rule's performance impact on Chronicle's processing capabilities.

    Args:
        rule_text (str): Complete YARA-L 2.0 rule definition including rule metadata, events, and conditions.
        project_id (str): Google Cloud project ID (required).
        customer_id (str): Chronicle customer ID (required).
        region (str): Chronicle region (e.g., "us", "europe") (required).

    Returns:
        str: Success message with the created rule ID and status information.
             Returns error message if rule creation fails.

    Example Usage:
        rule_text = '''
        rule suspicious_powershell_download {
            meta:
                description = "Detects PowerShell downloading files"
                author = "Security Team"
                severity = "Medium"
                priority = "Medium"
                yara_version = "YL2.0"
                rule_version = "1.0"
                mitre_attack_tactic = "TA0011"
                mitre_attack_technique = "T1059.001"
            events:
                $process.metadata.event_type = "PROCESS_LAUNCH"
                $process.principal.process.command_line = /powershell.*downloadfile/i
                $process.principal.hostname != ""
            condition:
                $process
        }
        '''

        create_rule(
            rule_text=rule_text,
            project_id="my-project",
            customer_id="my-customer",
            region="us"
        )

    Next Steps (using MCP-enabled tools):
        - Test the rule using `test_rule` with historical data to validate its effectiveness.
        - Enable the rule using `enable_rule` to start generating alerts.
        - Monitor the rule's performance and adjust thresholds or conditions as needed.
        - Review generated alerts using `get_security_alerts` to assess rule quality.
        - Document the rule's purpose and expected behavior for operational teams.
    """
    return create_rule_impl(
        rule_text=rule_text,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
    )


@server.tool()
async def test_rule(
    rule_text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    hours_back: int = 168,  # 7 days default
    max_results: int = 100,
) -> str:
    """Test a detection rule against historical data in Chronicle SIEM.

    Tests a YARA-L 2.0 detection rule against historical data to validate its effectiveness
    and tune its parameters before deployment. This is essential for ensuring rules work
    as expected and generate appropriate alerts without excessive false positives.



    **Workflow Integration:**
    - Critical testing step before creating or modifying detection rules in production.
    - Use during rule development to iteratively refine detection logic and thresholds.
    - Essential for validating rule effectiveness against real historical data.
    - Helps optimize rule performance and reduce false positive rates.

    **Use Cases:**
    - Test new rule logic against historical data to validate detection accuracy.
    - Tune rule thresholds and conditions based on historical event patterns.
    - Validate rule modifications before deploying changes to production.
    - Assess rule performance impact by measuring detection volume and processing time.
    - Compare different rule variations to determine the most effective detection approach.

    **Rule Testing Best Practices:**
    - Test against a representative time period that includes both normal and suspicious activity.
    - Review detected events to ensure they align with your intended detection objectives.
    - Adjust rule conditions based on test results to optimize precision and recall.
    - Consider the rule's computational complexity and potential impact on Chronicle performance.
    - Test with different time windows to understand detection patterns and false positive rates.

    Args:
        rule_text (str): Complete YARA-L 2.0 rule definition to test.
        project_id (str): Google Cloud project ID (required).
        customer_id (str): Chronicle customer ID (required).
        region (str): Chronicle region (e.g., "us", "europe") (required).
        hours_back (int): How many hours of historical data to test against. Defaults to 168 (7 days).
        max_results (int): Maximum number of detection results to return. Defaults to 100.

    Returns:
        str: Formatted test results showing detection count, sample detections, and analysis summary.
             Returns error message if testing fails.

    Example Usage:
        rule_text = '''
        rule test_network_connection {
            meta:
                description = "Test rule for network connections"
                author = "Security Team"
                severity = "Low"
                yara_version = "YL2.0"
                rule_version = "1.0"
            events:
                $e.metadata.event_type = "NETWORK_CONNECTION"
                $e.target.port = 443
            condition:
                $e
        }
        '''

        test_rule(
            rule_text=rule_text,
            project_id="my-project",
            customer_id="my-customer",
            region="us",
            hours_back=24,
            max_results=50
        )

    Next Steps (using MCP-enabled tools):
        - Analyze the test results to determine if the rule meets your detection objectives.
        - Refine the rule based on the test results and retest as needed.
        - Create the rule using `create_rule` once testing shows satisfactory results.
        - Enable the rule using `enable_rule` to start generating production alerts.
        - Monitor the rule's ongoing performance using alert management tools.
    """
    return test_rule_impl(
        rule_text=rule_text,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
        hours_back=hours_back,
        max_results=max_results,
    )


@server.tool()
async def validate_rule(
    rule_text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Validate a YARA-L 2.0 detection rule syntax in Chronicle SIEM.

    Validates the syntax and structure of a YARA-L 2.0 detection rule without creating
    or testing it. This is useful for checking rule syntax during development and
    identifying compilation errors before rule deployment.



    **Workflow Integration:**
    - Use during rule development to quickly validate syntax without full testing.
    - Essential for catching syntax errors early in the rule development process.
    - Helpful for validating rule modifications before testing against historical data.
    - Enables rapid iteration on rule development with immediate syntax feedback.

    **Use Cases:**
    - Validate rule syntax during initial development or modification.
    - Check for compilation errors before committing rule changes.
    - Quickly verify that complex rule logic is syntactically correct.
    - Validate imported or shared rules before integration into your environment.
    - Educational tool for learning YARA-L 2.0 syntax and best practices.

    **Validation Capabilities:**
    - Syntax validation for YARA-L 2.0 language constructs
    - Field name validation against Chronicle's UDM schema
    - Function and operator usage validation
    - Rule structure and format validation
    - Metadata section validation

    Args:
        rule_text (str): Complete YARA-L 2.0 rule definition to validate.
        project_id (str): Google Cloud project ID (required).
        customer_id (str): Chronicle customer ID (required).
        region (str): Chronicle region (e.g., "us", "europe") (required).

    Returns:
        str: Validation results indicating success or specific syntax errors with location information.
             Returns error message if validation fails.

    Example Usage:
        rule_text = '''
        rule example_validation_rule {
            meta:
                description = "Example rule for validation testing"
                author = "Security Team"
                severity = "Medium"
                yara_version = "YL2.0"
                rule_version = "1.0"
            events:
                $e.metadata.event_type = "NETWORK_CONNECTION"
                $e.target.ip != ""
                $e.principal.hostname != ""
            condition:
                $e
        }
        '''

        validate_rule(
            rule_text=rule_text,
            project_id="my-project",
            customer_id="my-customer",
            region="us"
        )

    Next Steps (using MCP-enabled tools):
        - If validation passes, proceed with rule testing using `test_rule`.
        - If validation fails, review and correct the identified syntax errors.
        - Use the validation feedback to refine rule logic and structure.
        - Once validated and tested, create the rule using `create_rule`.
        - Enable the rule using `enable_rule` to start generating alerts.
    """
    return validate_rule_impl(
        rule_text=rule_text,
        project_id=project_id,
        customer_id=customer_id,
        region=region,
    )
