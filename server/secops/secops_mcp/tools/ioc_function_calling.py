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
This module provides a standalone implementation of the IoC matches functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.ioc_logic import get_ioc_matches_impl

# 1. The Function Definition (JSON Schema)

GET_IOC_MATCHES_SCHEMA = {
    "type": "function",
    "name": "get_ioc_matches",
    "description": "Get Indicators of Compromise (IoCs) matches from Chronicle SIEM.",
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
                "description": "How many hours back to look for IoC matches. Defaults to 24.",
                "default": 24,
            },
            "max_matches": {
                "type": "integer",
                "description": "Maximum number of IoC matches to return. Defaults to 20.",
                "default": 20,
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

# 2. The Tool Execution Logic

async def execute_get_ioc_matches_tool(arguments: Dict[str, Any]) -> str:
    return get_ioc_matches_impl(
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        hours_back=arguments.get("hours_back", 24),
        max_matches=arguments.get("max_matches", 20),
        region=arguments.get("region"),
    )
