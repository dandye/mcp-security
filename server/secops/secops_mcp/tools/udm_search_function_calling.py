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
This module provides a standalone implementation of the UDM search and export functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.udm_search_logic import (
    export_udm_search_csv_impl,
    find_udm_field_values_impl,
)

# 1. The Function Definition (JSON Schema)

EXPORT_UDM_SEARCH_CSV_SCHEMA = {
    "type": "function",
    "name": "export_udm_search_csv",
    "description": "Export UDM search results to CSV format for analysis and reporting.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "UDM query to search for events. Use Chronicle query syntax.",
            },
            "fields": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of UDM fields to include in the CSV export.",
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
            "case_insensitive": {
                "type": "boolean",
                "description": "Whether to perform case-insensitive search. Defaults to True.",
                "default": True,
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
        "required": ["query", "fields"],
        "additionalProperties": False,
    },
}

FIND_UDM_FIELD_VALUES_SCHEMA = {
    "type": "function",
    "name": "find_udm_field_values",
    "description": "Find and autocomplete UDM field values in Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The partial UDM field value to search for.",
            },
            "page_size": {
                "type": "integer",
                "description": "Maximum number of matching values to return.",
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
        "required": ["query"],
        "additionalProperties": False,
    },
}

# 2. The Tool Execution Logic

async def execute_export_udm_search_csv_tool(arguments: Dict[str, Any]) -> str:
    return export_udm_search_csv_impl(
        query=arguments.get("query"),
        fields=arguments.get("fields"),
        hours_back=arguments.get("hours_back", 24),
        start_time=arguments.get("start_time"),
        end_time=arguments.get("end_time"),
        case_insensitive=arguments.get("case_insensitive", True),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_find_udm_field_values_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return find_udm_field_values_impl(
        query=arguments.get("query"),
        page_size=arguments.get("page_size"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )
