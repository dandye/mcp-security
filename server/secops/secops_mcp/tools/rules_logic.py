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
"""Shared logic for security rules tools."""

import logging
from typing import Any, Dict, Optional

from secops_mcp.server import get_chronicle_client

# Configure logging
logger = logging.getLogger("secops-mcp")

def list_rules_impl(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    page_size: int = 100,
    page_token: str | None = None,
) -> Dict[str, Any]:
    """
    Core implementation for listing security rules.
    Used by both MCP tool and Function Calling implementation.
    """
    try:
        if page_size > 1000:
            logger.warning("page_size cannot exceed 1000. Setting to 1000.")
            page_size = 1000

        chronicle = get_chronicle_client(project_id, customer_id, region)
        rules_response = chronicle.list_rules(
            page_size=page_size, page_token=page_token
        )
        return rules_response
    except Exception as e:
        logger.error(f"Error listing security rules: {str(e)}", exc_info=True)
        return {"error": str(e), "rules": []}

def search_security_rules_impl(
    query: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for searching security rules."""
    try:
        chronicle = get_chronicle_client(project_id, customer_id, region)
        rules_response = chronicle.search_rules(query)
        return rules_response
    except Exception as e:
        logger.error(f"Error searching security rules: {str(e)}", exc_info=True)
        return {"error": str(e), "rules": []}

def get_detection_rule_impl(
    rule_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for retrieving a detection rule."""
    try:
        logger.info(f"Retrieving detection rule: {rule_id}")

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Get the rule using the client
        rule_response = chronicle.get_rule(rule_id)

        logger.info(f"Successfully retrieved rule: {rule_id}")
        return rule_response

    except Exception as e:
        logger.error(
            f"Error retrieving detection rule {rule_id}: {str(e)}",
            exc_info=True,
        )
        return {
            "error": f"Error retrieving detection rule: {str(e)}",
            "rule": {},
        }

def get_rule_detections_impl(
    rule_id: str,
    alert_state: Optional[str] = None,
    page_size: Optional[int] = None,
    page_token: Optional[str] = None,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for retrieving rule detections."""
    try:
        chronicle = get_chronicle_client(project_id, customer_id, region)

        if (
            not hasattr(chronicle, "base_url")
            or not hasattr(chronicle, "instance_id")
            or not hasattr(chronicle, "session")
        ):
            logger.error(
                "Chronicle client from get_chronicle_client is missing expected attributes (base_url, instance_id, session)."
            )
            return {
                "error": "Chronicle client misconfigured for direct session access.",
                "detections": [],
            }

        valid_alert_states = ["UNSPECIFIED", "NOT_ALERTING", "ALERTING"]
        if alert_state:
            if alert_state not in valid_alert_states:
                logger.error(
                    f"Invalid alert_state: {alert_state}. Must be one of {valid_alert_states}"
                )
                raise ValueError(
                    f"alert_state must be one of {valid_alert_states}, got {alert_state}"
                )

        detections_response = chronicle.list_detections(
            rule_id, alert_state, page_size, page_token
        )

        return detections_response
    except (
        ValueError
    ) as ve:  # Catch specific ValueError from alert_state validation
        logger.error(
            f"Validation error getting rule detections for rule {rule_id}: {str(ve)}",
            exc_info=True,
        )
        return {"error": str(ve), "detections": []}
    except Exception as e:
        logger.error(
            f"Unexpected error getting rule detections for rule {rule_id}: {str(e)}",
            exc_info=True,
        )
        return {"error": f"Unexpected error: {str(e)}", "detections": []}

def list_rule_errors_impl(
    rule_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for listing rule errors."""
    try:
        chronicle = get_chronicle_client(project_id, customer_id, region)

        if (
            not hasattr(chronicle, "base_url")
            or not hasattr(chronicle, "instance_id")
            or not hasattr(chronicle, "session")
        ):
            logger.error(
                "Chronicle client from get_chronicle_client is missing expected attributes (base_url, instance_id, session)."
            )
            return {
                "error": "Chronicle client misconfigured for direct session access.",
                "errors": [],
            }

        logger.info(f"Requesting errors for rule_id: {rule_id}")
        response = chronicle.list_errors(rule_id)

        return response

    except Exception as e:
        logger.error(
            f"Unexpected error listing rule errors for {rule_id}: {str(e)}",
            exc_info=True,
        )
        return {"error": f"Unexpected error: {str(e)}", "errors": []}

def create_rule_impl(
    rule_text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Core implementation for creating a rule."""
    try:
        logger.info("Creating new detection rule")

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Create the rule
        rule = chronicle.create_rule(rule_text)

        # Extract rule ID from the response
        rule_id = rule.get("name", "").split("/")[-1]

        result = f"Successfully created detection rule.\n"
        result += f"Rule ID: {rule_id}\n"

        # Extract rule name from the text if possible
        lines = rule_text.strip().split("\n")
        for line in lines:
            if line.strip().startswith("rule "):
                rule_name = (
                    line.strip().replace("rule ", "").replace(" {", "").strip()
                )
                result += f"Rule Name: {rule_name}\n"
                break

        result += "Rule created successfully. Use test_rule to validate before enabling."

        return result

    except Exception as e:
        logger.error(f"Error creating rule: {str(e)}", exc_info=True)
        return f"Error creating rule: {str(e)}"

def test_rule_impl(
    rule_text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    hours_back: int = 168,  # 7 days default
    max_results: int = 100,
) -> str:
    """Core implementation for testing a rule."""
    try:
        logger.info(
            f"Testing detection rule against {hours_back} hours of historical data"
        )

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Define time range for testing
        from datetime import datetime, timedelta, timezone

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        logger.info(f"Rule test time range: {start_time} to {end_time}")

        # Test the rule
        test_results = chronicle.run_rule_test(
            rule_text=rule_text,
            start_time=start_time,
            end_time=end_time,
            max_results=max_results,
        )

        # Process streaming results
        detection_count = 0
        progress_updates = []
        detections = []
        errors = []

        for result in test_results:
            result_type = result.get("type")

            if result_type == "progress":
                # Progress update
                percent_done = result.get("percentDone", 0)
                progress_updates.append(f"Progress: {percent_done}%")

            elif result_type == "detection":
                # Detection result
                detection_count += 1
                detection = result.get("detection", {})
                detections.append(detection)

            elif result_type == "error":
                # Error information
                error_msg = result.get("message", "Unknown error")
                errors.append(error_msg)

        # Format response
        response = f"Rule Test Results:\n\n"
        response += f'Test Period: {hours_back} hours ({start_time.strftime("%Y-%m-%d %H:%M:%S")} to {end_time.strftime("%Y-%m-%d %H:%M:%S")})\n'
        response += f"Total Detections: {detection_count}\n"
        response += f"Max Results Limit: {max_results}\n\n"

        if errors:
            response += f"Errors Encountered:\n"
            for error in errors:
                response += f"  - {error}\n"
            response += "\n"

        if detection_count > 0:
            response += f"Detection Analysis:\n"
            response += (
                f"  - Rule successfully detected {detection_count} event(s)\n"
            )
            if detection_count >= max_results:
                response += f"  - Results limited to {max_results} detections (may have more)\n"

            # Show sample detection details
            if detections:
                response += f"\nSample Detection Details:\n"
                sample_detection = detections[0]

                if "rule_id" in sample_detection:
                    response += f'  Rule ID: {sample_detection["rule_id"]}\n'

                if "detection_time" in sample_detection:
                    response += f'  Detection Time: {sample_detection["detection_time"]}\n'

                # Show event details if available
                result_events = sample_detection.get("resultEvents", {})
                if result_events:
                    for var_name, var_data in result_events.items():
                        event_samples = var_data.get("eventSamples", [])
                        if event_samples:
                            sample_event = event_samples[0].get("event", {})
                            metadata = sample_event.get("metadata", {})
                            event_type = metadata.get("eventType", "Unknown")
                            response += f"  Event Type: {event_type}\n"
                            break

            response += f"\nRecommendation: Review detections to ensure they align with your detection objectives."
        else:
            response += f"No detections found in the test period.\n"
            response += f"Consider:\n"
            response += f"  - Expanding the test time range (currently {hours_back} hours)\n"
            response += f"  - Reviewing rule conditions for accuracy\n"
            response += (
                f"  - Checking if the required event types exist in your data\n"
            )

        return response

    except Exception as e:
        logger.error(f"Error testing rule: {str(e)}", exc_info=True)
        return f"Error testing rule: {str(e)}"

def validate_rule_impl(
    rule_text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Core implementation for validating a rule."""
    try:
        logger.info("Validating detection rule syntax")

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Validate the rule
        validation_result = chronicle.validate_rule(rule_text)

        # Format response based on validation result
        response = f"Rule Validation Results:\n\n"

        if hasattr(validation_result, "success") and validation_result.success:
            response += "✅ Rule validation PASSED\n"
            response += "The rule syntax is correct and ready for testing or deployment.\n"

            # Include suggested fields if available
            if (
                hasattr(validation_result, "suggested_fields")
                and validation_result.suggested_fields
            ):
                response += f'\nSuggested Fields: {", ".join(validation_result.suggested_fields)}'

        elif (
            hasattr(validation_result, "success")
            and not validation_result.success
        ):
            response += "❌ Rule validation FAILED\n"
            response += f"Error: {validation_result.message}\n"

            # Include position information if available
            if (
                hasattr(validation_result, "position")
                and validation_result.position
            ):
                position = validation_result.position
                if "startLine" in position and "startColumn" in position:
                    response += f'Location: Line {position["startLine"]}, Column {position["startColumn"]}\n'

            response += "\nPlease review and correct the syntax errors before proceeding."

        else:
            # Handle different response format
            response += f"Validation result: {validation_result}\n"

            # Try to determine if validation passed based on common response patterns
            if isinstance(validation_result, dict):
                is_valid = validation_result.get("isValid", False)
                if is_valid:
                    response += (
                        "✅ Rule appears to be valid based on API response.\n"
                    )
                else:
                    response += "❌ Rule validation may have failed based on API response.\n"

                # Include query type if available
                query_type = validation_result.get("queryType", "")
                if query_type:
                    response += f"Query Type: {query_type}\n"

                # Include suggested fields if available
                suggested_fields = validation_result.get("suggestedFields", [])
                if suggested_fields:
                    response += (
                        f'Suggested Fields: {", ".join(suggested_fields)}\n'
                    )

        return response

    except Exception as e:
        logger.error(f"Error validating rule: {str(e)}", exc_info=True)
        return f"Error validating rule: {str(e)}"
