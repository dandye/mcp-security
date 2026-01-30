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
This module provides a standalone implementation of the parser management functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.parser_logic import (
    activate_parser_impl,
    create_parser_impl,
    deactivate_parser_impl,
    get_parser_impl,
    run_parser_against_sample_logs_impl,
)

# 1. The Function Definition (JSON Schema)

CREATE_PARSER_SCHEMA = {
    "type": "function",
    "name": "create_parser",
    "description": "Create a new parser for a specific log type in Chronicle.",
    "parameters": {
        "type": "object",
        "properties": {
            "log_type": {
                "type": "string",
                "description": "Chronicle log type identifier for this parser.",
            },
            "parser_code": {
                "type": "string",
                "description": "Parser configuration code using Chronicle's parser DSL.",
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
            "validated_on_empty_logs": {
                "type": "boolean",
                "description": "Whether to validate the parser even on empty log samples. Defaults to True.",
                "default": True,
            },
        },
        "required": ["log_type", "parser_code"],
        "additionalProperties": False,
    },
}

GET_PARSER_SCHEMA = {
    "type": "function",
    "name": "get_parser",
    "description": "Get details of a specific parser in Chronicle.",
    "parameters": {
        "type": "object",
        "properties": {
            "log_type": {
                "type": "string",
                "description": "Chronicle log type identifier for the parser.",
            },
            "parser_id": {
                "type": "string",
                "description": "Unique identifier of the parser to retrieve.",
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
        "required": ["log_type", "parser_id"],
        "additionalProperties": False,
    },
}

ACTIVATE_PARSER_SCHEMA = {
    "type": "function",
    "name": "activate_parser",
    "description": "Activate a parser for a specific log type in Chronicle.",
    "parameters": {
        "type": "object",
        "properties": {
            "log_type": {
                "type": "string",
                "description": "Chronicle log type identifier for the parser.",
            },
            "parser_id": {
                "type": "string",
                "description": "Unique identifier of the parser to activate.",
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
        "required": ["log_type", "parser_id"],
        "additionalProperties": False,
    },
}

DEACTIVATE_PARSER_SCHEMA = {
    "type": "function",
    "name": "deactivate_parser",
    "description": "Deactivate a parser for a specific log type in Chronicle.",
    "parameters": {
        "type": "object",
        "properties": {
            "log_type": {
                "type": "string",
                "description": "Chronicle log type identifier for the parser.",
            },
            "parser_id": {
                "type": "string",
                "description": "Unique identifier of the parser to deactivate.",
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
        "required": ["log_type", "parser_id"],
        "additionalProperties": False,
    },
}

RUN_PARSER_AGAINST_SAMPLE_LOGS_SCHEMA = {
    "type": "function",
    "name": "run_parser_against_sample_logs",
    "description": "Run a parser against sample logs to test parsing logic.",
    "parameters": {
        "type": "object",
        "properties": {
            "log_type": {
                "type": "string",
                "description": "Chronicle log type identifier for the parser.",
            },
            "parser_code": {
                "type": "string",
                "description": "Parser configuration code to test.",
            },
            "sample_logs": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of sample log entries to test against.",
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
            "parser_extension_code": {
                "type": "string",
                "description": "Additional parser extension code if needed.",
            },
            "statedump_allowed": {
                "type": "boolean",
                "description": "Whether to allow statedump filters in the parser. Defaults to False.",
                "default": False,
            },
        },
        "required": ["log_type", "parser_code", "sample_logs"],
        "additionalProperties": False,
    },
}

# 2. The Tool Execution Logic

async def execute_create_parser_tool(arguments: Dict[str, Any]) -> str:
    return create_parser_impl(
        log_type=arguments.get("log_type"),
        parser_code=arguments.get("parser_code"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        validated_on_empty_logs=arguments.get("validated_on_empty_logs", True),
    )

async def execute_get_parser_tool(arguments: Dict[str, Any]) -> str:
    return get_parser_impl(
        log_type=arguments.get("log_type"),
        parser_id=arguments.get("parser_id"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_activate_parser_tool(arguments: Dict[str, Any]) -> str:
    return activate_parser_impl(
        log_type=arguments.get("log_type"),
        parser_id=arguments.get("parser_id"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_deactivate_parser_tool(arguments: Dict[str, Any]) -> str:
    return deactivate_parser_impl(
        log_type=arguments.get("log_type"),
        parser_id=arguments.get("parser_id"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_run_parser_against_sample_logs_tool(arguments: Dict[str, Any]) -> str:
    return run_parser_against_sample_logs_impl(
        log_type=arguments.get("log_type"),
        parser_code=arguments.get("parser_code"),
        sample_logs=arguments.get("sample_logs"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        parser_extension_code=arguments.get("parser_extension_code"),
        statedump_allowed=arguments.get("statedump_allowed", False),
    )
