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
This module provides a standalone implementation of the security events search functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.security_events_logic import search_security_events_impl

# 1. The Function Definition (JSON Schema)

SEARCH_SECURITY_EVENTS_SCHEMA = {
    "type": "function",
    "name": "search_security_events",
    "description": "Search for security events in Chronicle SIEM using natural language.",
    "parameters": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "Natural language description of the events you want to find.",
            },
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
                "description": "How many hours back from the current time to search. Used if start_time is not provided.",
                "default": 24,
            },
            "start_time": {
                "type": "string",
                "description": "Start time in ISO 8601 format (e.g. '2023-01-01T00:00:00Z'). Overrides hours_back.",
            },
            "end_time": {
                "type": "string",
                "description": "End time in ISO 8601 format. Defaults to current time if not provided.",
            },
            "max_events": {
                "type": "integer",
                "description": "Maximum number of event records to return. Defaults to 100.",
                "default": 100,
            },
            "region": {
                "type": "string",
                "description": "Chronicle region (e.g., 'us', 'europe'). Optional if configured in environment.",
            },
        },
        "required": ["text"],
        "additionalProperties": False,
    },
}

# 2. The Tool Execution Logic

async def execute_search_security_events_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return search_security_events_impl(
        text=arguments.get("text"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        hours_back=arguments.get("hours_back", 24),
        start_time=arguments.get("start_time"),
        end_time=arguments.get("end_time"),
        max_events=arguments.get("max_events", 100),
        region=arguments.get("region"),
    )
