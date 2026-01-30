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
This module provides a standalone implementation of the data table management functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.data_table_logic import (
    add_rows_to_data_table_impl,
    create_data_table_impl,
    delete_data_table_rows_impl,
    list_data_table_rows_impl,
)

# 1. The Function Definition (JSON Schema)

CREATE_DATA_TABLE_SCHEMA = {
    "type": "function",
    "name": "create_data_table",
    "description": "Create a new data table in Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Unique name for the data table.",
            },
            "description": {
                "type": "string",
                "description": "Description of the data table's purpose and contents.",
            },
            "header": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Column definitions mapping column names to their data types.",
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
            "rows": {
                "type": "array",
                "items": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "description": "Initial rows to populate the table.",
            },
        },
        "required": ["name", "description", "header"],
        "additionalProperties": False,
    },
}

ADD_ROWS_TO_DATA_TABLE_SCHEMA = {
    "type": "function",
    "name": "add_rows_to_data_table",
    "description": "Add rows to an existing data table in Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "table_name": {
                "type": "string",
                "description": "Name of the existing data table to add rows to.",
            },
            "rows": {
                "type": "array",
                "items": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "description": "List of rows to add.",
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
        "required": ["table_name", "rows"],
        "additionalProperties": False,
    },
}

LIST_DATA_TABLE_ROWS_SCHEMA = {
    "type": "function",
    "name": "list_data_table_rows",
    "description": "List rows in a data table in Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "table_name": {
                "type": "string",
                "description": "Name of the data table to list rows from.",
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
            "max_rows": {
                "type": "integer",
                "description": "Maximum number of rows to return. Defaults to 50.",
                "default": 50,
            },
        },
        "required": ["table_name"],
        "additionalProperties": False,
    },
}

DELETE_DATA_TABLE_ROWS_SCHEMA = {
    "type": "function",
    "name": "delete_data_table_rows",
    "description": "Delete specific rows from a data table in Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "table_name": {
                "type": "string",
                "description": "Name of the data table to delete rows from.",
            },
            "row_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of row IDs to delete.",
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
        "required": ["table_name", "row_ids"],
        "additionalProperties": False,
    },
}

# 2. The Tool Execution Logic

async def execute_create_data_table_tool(arguments: Dict[str, Any]) -> str:
    return create_data_table_impl(
        name=arguments.get("name"),
        description=arguments.get("description"),
        header=arguments.get("header"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        rows=arguments.get("rows"),
    )

async def execute_add_rows_to_data_table_tool(arguments: Dict[str, Any]) -> str:
    return add_rows_to_data_table_impl(
        table_name=arguments.get("table_name"),
        rows=arguments.get("rows"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_list_data_table_rows_tool(arguments: Dict[str, Any]) -> str:
    return list_data_table_rows_impl(
        table_name=arguments.get("table_name"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        max_rows=arguments.get("max_rows", 50),
    )

async def execute_delete_data_table_rows_tool(arguments: Dict[str, Any]) -> str:
    return delete_data_table_rows_impl(
        table_name=arguments.get("table_name"),
        row_ids=arguments.get("row_ids"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )
