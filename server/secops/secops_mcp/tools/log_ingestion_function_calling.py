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
This module provides a standalone implementation of the log ingestion functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.log_ingestion_logic import (
    get_available_log_types_impl,
    ingest_raw_log_impl,
    ingest_udm_events_impl,
)

# 1. The Function Definition (JSON Schema)

INGEST_RAW_LOG_SCHEMA = {
    "type": "function",
    "name": "ingest_raw_log",
    "description": "Ingest raw logs directly into Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "log_type": {
                "type": "string",
                "description": "Chronicle log type identifier (e.g., 'OKTA', 'WINEVTLOG_XML').",
            },
            "log_message": {
                "type": ["string", "array"],
                "items": {"type": "string"},
                "description": "Log content as string or list of strings for batch ingestion.",
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
            "forwarder_id": {
                "type": "string",
                "description": "Custom forwarder ID for log routing.",
            },
            "labels": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Custom labels to attach to ingested logs.",
            },
            "log_entry_time": {
                "type": "string",
                "description": "ISO 8601 timestamp when the log was originally generated.",
            },
            "collection_time": {
                "type": "string",
                "description": "ISO 8601 timestamp when the log was collected.",
            },
        },
        "required": ["log_type", "log_message"],
        "additionalProperties": False,
    },
}

INGEST_UDM_EVENTS_SCHEMA = {
    "type": "function",
    "name": "ingest_udm_events",
    "description": "Ingest UDM events directly into Chronicle SIEM.",
    "parameters": {
        "type": "object",
        "properties": {
            "udm_events": {
                "type": ["object", "array"],
                "description": "Single UDM event or list of UDM events.",
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
        "required": ["udm_events"],
        "additionalProperties": False,
    },
}

GET_AVAILABLE_LOG_TYPES_SCHEMA = {
    "type": "function",
    "name": "get_available_log_types",
    "description": "Get available log types supported by Chronicle for ingestion.",
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
            "search_term": {
                "type": "string",
                "description": "Filter log types by name or description containing this term.",
            },
        },
        "required": [],
        "additionalProperties": False,
    },
}

# 2. The Tool Execution Logic

async def execute_ingest_raw_log_tool(arguments: Dict[str, Any]) -> str:
    return ingest_raw_log_impl(
        log_type=arguments.get("log_type"),
        log_message=arguments.get("log_message"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        forwarder_id=arguments.get("forwarder_id"),
        labels=arguments.get("labels"),
        log_entry_time=arguments.get("log_entry_time"),
        collection_time=arguments.get("collection_time"),
    )

async def execute_ingest_udm_events_tool(arguments: Dict[str, Any]) -> str:
    return ingest_udm_events_impl(
        udm_events=arguments.get("udm_events"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_get_available_log_types_tool(arguments: Dict[str, Any]) -> str:
    return get_available_log_types_impl(
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
        search_term=arguments.get("search_term"),
    )
