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
This module provides a standalone implementation of the reference list management functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.reference_list_logic import (
    create_reference_list_impl,
    get_reference_list_impl,
    update_reference_list_impl,
)

# 1. The Function Definition (JSON Schema)

CREATE_REFERENCE_LIST_SCHEMA = {
    "type": "function",
    "name": "create_reference_list",
    "description": "Create a new reference list in Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Unique name for the reference list.",
            },
            "description": {
                "type": "string",
                "description": "Description of the reference list's purpose and contents.",
            },
            "entries": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of values to include in the reference list.",
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
            "syntax_type": {
                "type": "string",
                "description": "Type of matching to use. Valid values: 'STRING', 'CIDR', 'REGEX'. Defaults to 'STRING'.",
                "default": "STRING",
            },
        },
        "required": ["name", "description", "entries"],
        "additionalProperties": False,
    },
}

GET_REFERENCE_LIST_SCHEMA = {
    "type": "function",
    "name": "get_reference_list",
    "description": "Get details and contents of a reference list in Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Name of the reference list to retrieve.",
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
            "include_entries": {
                "type": "boolean",
                "description": "Whether to include the full list of entries. Defaults to True.",
                "default": True,
            },
        },
        "required": ["name"],
        "additionalProperties": False,
    },
}

UPDATE_REFERENCE_LIST_SCHEMA = {
    "type": "function",
    "name": "update_reference_list",
    "description": "Update an existing reference list in Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Name of the existing reference list to update.",
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
            "entries": {
                "type": "array",
                "items": {"type": "string"},
                "description": "New list of entries to replace existing ones. If provided, completely replaces current entries.",
            },
            "description": {
                "type": "string",
                "description": "New description for the reference list.",
            },
        },
        "required": ["name"],
        "additionalProperties": False,
    },
}

# 2. The Tool Execution Logic

async def execute_create_reference_list_tool(arguments: Dict[str, Any]) -> str:
    return create_reference_list_impl(
        name=arguments.get("name"),
        description=arguments.get("description"),
        entries=arguments.get("entries"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        syntax_type=arguments.get("syntax_type", "STRING"),
    )

async def execute_get_reference_list_tool(arguments: Dict[str, Any]) -> str:
    return get_reference_list_impl(
        name=arguments.get("name"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        include_entries=arguments.get("include_entries", True),
    )

async def execute_update_reference_list_tool(arguments: Dict[str, Any]) -> str:
    return update_reference_list_impl(
        name=arguments.get("name"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        entries=arguments.get("entries"),
        description=arguments.get("description"),
    )
