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
This module provides a standalone implementation of the entity lookup functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.entity_logic import lookup_entity_impl

# 1. The Function Definition (JSON Schema)

LOOKUP_ENTITY_SCHEMA = {
    "type": "function",
    "name": "lookup_entity",
    "description": "Look up an entity (IP, domain, hash, user, etc.) in Chronicle SIEM for enrichment.",
    "parameters": {
        "type": "object",
        "properties": {
            "entity_value": {
                "type": "string",
                "description": "Value to look up (e.g., IP address, domain name, file hash, username).",
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
                "description": "How many hours of historical data to consider for the summary. Defaults to 24.",
                "default": 24,
            },
            "region": {
                "type": "string",
                "description": "Chronicle region (e.g., 'us', 'europe'). Optional if configured in environment.",
            },
        },
        "required": ["entity_value"],
        "additionalProperties": False,
    },
}

# 2. The Tool Execution Logic

async def execute_lookup_entity_tool(arguments: Dict[str, Any]) -> str:
    return lookup_entity_impl(
        entity_value=arguments.get("entity_value"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        hours_back=arguments.get("hours_back", 24),
        region=arguments.get("region"),
    )
