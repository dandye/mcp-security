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
This module provides a standalone implementation of the 'list_security_rules' functionality
using the OpenAI Function Calling format.

Function Calling vs MCP Tool:
-----------------------------
1.  **Format**:
    -   **MCP Tool**: Uses the Model Context Protocol (MCP) decorator `@server.tool()`. This registers
        the function with the MCP server, which automatically handles schema generation and
        communication with MCP clients (like Claude Desktop or IDE extensions).
    -   **Function Calling**: Manually defines a JSON schema (`LIST_RULES_SCHEMA`) compatible with
        OpenAI's Chat Completions API. This schema must be passed to the `tools` parameter in
        an OpenAI API request. The execution logic (`execute_list_rules_tool`) is separate and
        must be invoked by the "caller" (your application code) when the model requests it.

2.  **Use Cases**:
    -   Use **MCP** when building tools for an ecosystem of MCP-compliant clients. It's plug-and-play
        for end-users using those clients.
    -   Use **Function Calling** when building a custom application (e.g., a chatbot or agent)
        that consumes the OpenAI API directly. It gives you full control over the conversation loop,
        state management, and how tools are executed.

3.  **Implementation**:
    -   The logic below reuses the same underlying Chronicle client but exposes it via a
        dictionary-based interface typical of function calling handlers.
"""

import logging
from typing import Any, Dict, Optional

from secops_mcp.server import get_chronicle_client

# Configure logging
logger = logging.getLogger("secops-mcp-fc")


# 1. The Function Definition (JSON Schema)
# This is what you pass to the OpenAI API in the `tools` list.
LIST_RULES_SCHEMA = {
    "type": "function",
    "name": "list_security_rules",
    "description": "List security detection rules configured in Chronicle SIEM, with support for pagination.",
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
            "page_size": {
                "type": "integer",
                "description": "Maximum number of rules to return. Defaults to 100. Max is 1000.",
                "default": 100,
            },
            "page_token": {
                "type": "string",
                "description": "Page token for pagination.",
            },
        },
        "required": [],  # All parameters are optional if env vars are set, but usually project/customer are needed.
        "additionalProperties": False,
    },
    # "strict": True # Strict mode requires all properties in `required` and no optional params without null type.
    # For flexibility here, we are not enforcing strict mode in this example schema,
    # but it is recommended for production.
}


# 2. The Tool Execution Logic
# This is the function you call when the model tells you to call "list_security_rules".
async def execute_list_rules_tool(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes the list_security_rules tool based on the arguments provided by the LLM.

    Args:
        arguments: A dictionary of arguments extracted from the LLM's tool call.

    Returns:
        A dictionary containing the results from the Chronicle API or an error message.
    """
    project_id = arguments.get("project_id")
    customer_id = arguments.get("customer_id")
    region = arguments.get("region")
    page_size = arguments.get("page_size", 100)
    page_token = arguments.get("page_token")

    # Basic validation
    if page_size > 1000:
        logger.warning("page_size cannot exceed 1000. Setting to 1000.")
        page_size = 1000

    try:
        # Initialize the Chronicle client
        # This reuses the same helper from the main server module
        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Call the API
        rules_response = chronicle.list_rules(
            page_size=page_size, page_token=page_token
        )
        return rules_response
    except Exception as e:
        logger.error(f"Error listing security rules (Function Calling): {str(e)}", exc_info=True)
        return {"error": str(e), "rules": []}
