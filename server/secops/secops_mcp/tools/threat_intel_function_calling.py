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
This module provides a standalone implementation of the threat intelligence functionality
using the OpenAI Function Calling format.
"""

from typing import Any, Dict

from secops_mcp.tools.threat_intel_logic import get_threat_intel_impl

# 1. The Function Definition (JSON Schema)

GET_THREAT_INTEL_SCHEMA = {
    "type": "function",
    "name": "get_threat_intel",
    "description": "Get answers to security questions using Chronicle's integrated Gemini model.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The security or threat intelligence question to ask Gemini.",
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

async def execute_get_threat_intel_tool(arguments: Dict[str, Any]) -> str:
    return get_threat_intel_impl(
        query=arguments.get("query"),
        project_id=arguments.get("project_id"),
        customer_id=arguments.get("customer_id"),
        region=arguments.get("region"),
    )
