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
This module provides a standalone implementation of the feed management functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.feed_logic import (
    create_feed_impl,
    delete_feed_impl,
    disable_feed_impl,
    enable_feed_impl,
    generate_feed_secret_impl,
    get_feed_impl,
    list_feeds_impl,
    update_feed_impl,
)

# 1. The Function Definition (JSON Schema)

LIST_FEEDS_SCHEMA = {
    "type": "function",
    "name": "list_feeds",
    "description": "List all feeds configured in Chronicle.",
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
        },
        "required": [],
        "additionalProperties": False,
    },
}

GET_FEED_SCHEMA = {
    "type": "function",
    "name": "get_feed",
    "description": "Get detailed information about a specific feed.",
    "parameters": {
        "type": "object",
        "properties": {
            "feed_id": {
                "type": "string",
                "description": "The ingestion feed identifier to retrieve details for.",
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
        "required": ["feed_id"],
        "additionalProperties": False,
    },
}

CREATE_FEED_SCHEMA = {
    "type": "function",
    "name": "create_feed",
    "description": "Create a new feed in Chronicle.",
    "parameters": {
        "type": "object",
        "properties": {
            "display_name": {
                "type": "string",
                "description": "User-friendly name for the feed.",
            },
            "feed_details": {
                "type": "object",
                "description": "Dictionary containing feed configuration details.",
                "additionalProperties": True,
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
        "required": ["display_name", "feed_details"],
        "additionalProperties": False,
    },
}

UPDATE_FEED_SCHEMA = {
    "type": "function",
    "name": "update_feed",
    "description": "Update an existing feed in Chronicle.",
    "parameters": {
        "type": "object",
        "properties": {
            "feed_id": {
                "type": "string",
                "description": "The ID of the feed to update.",
            },
            "display_name": {
                "type": "string",
                "description": "New display name for the feed.",
            },
            "feed_details": {
                "type": "object",
                "description": "Dictionary containing updated feed configuration details.",
                "additionalProperties": True,
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
        "required": ["feed_id"],
        "additionalProperties": False,
    },
}

ENABLE_FEED_SCHEMA = {
    "type": "function",
    "name": "enable_feed",
    "description": "Enable a inactive feed in Chronicle.",
    "parameters": {
        "type": "object",
        "properties": {
            "feed_id": {
                "type": "string",
                "description": "The feed identifier which is to be enabled.",
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
        "required": ["feed_id"],
        "additionalProperties": False,
    },
}

DISABLE_FEED_SCHEMA = {
    "type": "function",
    "name": "disable_feed",
    "description": "Disable an active feed in Chronicle.",
    "parameters": {
        "type": "object",
        "properties": {
            "feed_id": {
                "type": "string",
                "description": "The ID of the feed to disable.",
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
        "required": ["feed_id"],
        "additionalProperties": False,
    },
}

DELETE_FEED_SCHEMA = {
    "type": "function",
    "name": "delete_feed",
    "description": "Delete a feed from Chronicle.",
    "parameters": {
        "type": "object",
        "properties": {
            "feed_id": {
                "type": "string",
                "description": "The ID of the feed to delete.",
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
        "required": ["feed_id"],
        "additionalProperties": False,
    },
}

GENERATE_FEED_SECRET_SCHEMA = {
    "type": "function",
    "name": "generate_feed_secret",
    "description": "Generate authentication secret for a feed.",
    "parameters": {
        "type": "object",
        "properties": {
            "feed_id": {
                "type": "string",
                "description": "The ID of the feed to generate a secret for.",
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
        "required": ["feed_id"],
        "additionalProperties": False,
    },
}

# 2. The Tool Execution Logic

async def execute_list_feeds_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return list_feeds_impl(
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_get_feed_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return get_feed_impl(
        feed_id=arguments.get("feed_id"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_create_feed_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return create_feed_impl(
        display_name=arguments.get("display_name"),
        feed_details=arguments.get("feed_details"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_update_feed_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return update_feed_impl(
        feed_id=arguments.get("feed_id"),
        display_name=arguments.get("display_name"),
        feed_details=arguments.get("feed_details"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_enable_feed_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return enable_feed_impl(
        feed_id=arguments.get("feed_id"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_disable_feed_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return disable_feed_impl(
        feed_id=arguments.get("feed_id"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_delete_feed_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return delete_feed_impl(
        feed_id=arguments.get("feed_id"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )

async def execute_generate_feed_secret_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    return generate_feed_secret_impl(
        feed_id=arguments.get("feed_id"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )
