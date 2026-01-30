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
"""
This module provides a standalone implementation of the security alerts functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.alerts_logic import (
    do_update_security_alert_impl,
    get_security_alert_by_id_impl,
    get_security_alerts_impl,
)

# 1. The Function Definitions (JSON Schema)

GET_ALERTS_SCHEMA = {
    "type": "function",
    "name": "get_security_alerts",
    "description": "Get security alerts directly from Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "project_id": {
                "type": "string",
                "description": "Google Cloud project ID. Optional if configured in environment.",
            },
            "customer_id": {
                "type": "string",
                "description": "Chronicle customer ID. Optional if configured in environment.",
            },
            "hours_back": {
                "type": "integer",
                "description": "How many hours to look back for alerts. Defaults to 24.",
                "default": 24,
            },
            "max_alerts": {
                "type": "integer",
                "description": "Maximum number of alerts to return. Defaults to 10.",
                "default": 10,
            },
            "status_filter": {
                "type": "string",
                "description": "Query string to filter alerts by status. Defaults to 'feedback_summary.status != \"CLOSED\"'.",
                "default": 'feedback_summary.status != "CLOSED"',
            },
            "region": {
                "type": "string",
                "description": "Chronicle region (e.g., 'us', 'europe'). Optional if configured in environment.",
            },
        },
        "required": [],
        "additionalProperties": False,
    },
}

GET_ALERT_BY_ID_SCHEMA = {
    "type": "function",
    "name": "get_security_alert_by_id",
    "description": "Get security alert by ID directly from Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "project_id": {
                "type": "string",
                "description": "Google Cloud project ID. Optional if configured in environment.",
            },
            "customer_id": {
                "type": "string",
                "description": "Chronicle customer ID. Optional if configured in environment.",
            },
            "region": {
                "type": "string",
                "description": "Chronicle region (e.g., 'us', 'europe'). Optional if configured in environment.",
            },
            "alert_id": {
                "type": "string",
                "description": "The unique identifier of the alert to retrieve.",
            },
            "include_detections": {
                "type": "boolean",
                "description": "Whether to include detection details in the response. Defaults to True.",
                "default": True,
            },
        },
        "required": ["alert_id"],
        "additionalProperties": False,
    },
}

UPDATE_ALERT_SCHEMA = {
    "type": "function",
    "name": "do_update_security_alert",
    "description": "Update security alert attributes directly in Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "alert_id": {
                "type": "string",
                "description": "The unique ID of the Chronicle security alert to update.",
            },
            "reason": {
                "type": "string",
                "description": "Reason for closing an alert. e.g., 'REASON_NOT_MALICIOUS'.",
            },
            "priority": {
                "type": "string",
                "description": "Alert priority. e.g., 'PRIORITY_HIGH'.",
            },
            "status": {
                "type": "string",
                "description": "Alert status. e.g., 'CLOSED'.",
            },
            "verdict": {
                "type": "string",
                "description": "Verdict on the alert. e.g., 'TRUE_POSITIVE'.",
            },
            "severity": {
                "type": "integer",
                "description": "Severity score [0-100] of the alert.",
            },
            "comment": {
                "type": "string",
                "description": "Analyst comment.",
            },
            "root_cause": {
                "type": "string",
                "description": "Alert root cause.",
            },
            "project_id": {
                "type": "string",
                "description": "Google Cloud project ID. Optional if configured in environment.",
            },
            "customer_id": {
                "type": "string",
                "description": "Chronicle customer ID. Optional if configured in environment.",
            },
            "region": {
                "type": "string",
                "description": "Chronicle region (e.g., 'us', 'europe'). Optional if configured in environment.",
            },
        },
        "required": ["alert_id"],
        "additionalProperties": False,
    },
}

# 2. The Tool Execution Logic

async def execute_get_alerts_tool(arguments: Dict[str, Any]) -> str:
    return get_security_alerts_impl(
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        hours_back=arguments.get("hours_back", 24),
        max_alerts=arguments.get("max_alerts", 10),
        status_filter=arguments.get("status_filter", 'feedback_summary.status != "CLOSED"'),
        region=arguments.get("region"),
    )

async def execute_get_alert_by_id_tool(arguments: Dict[str, Any]) -> str:
    return get_security_alert_by_id_impl(
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        alert_id=arguments.get("alert_id"),
        include_detections=arguments.get("include_detections", True),
    )

async def execute_update_alert_tool(arguments: Dict[str, Any]) -> str:
    return do_update_security_alert_impl(
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        alert_id=arguments.get("alert_id"),
        reason=arguments.get("reason"),
        priority=arguments.get("priority"),
        status=arguments.get("status"),
        verdict=arguments.get("verdict"),
        severity=arguments.get("severity"),
        comment=arguments.get("comment"),
        root_cause=arguments.get("root_cause"),
    )
