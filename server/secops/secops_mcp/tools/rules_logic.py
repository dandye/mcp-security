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
"""Shared logic for security rules tools."""

import logging
from typing import Any, Dict, Optional

from secops_mcp.server import get_chronicle_client

# Configure logging
logger = logging.getLogger("secops-mcp")

def list_rules_impl(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    page_size: int = 100,
    page_token: str | None = None,
) -> Dict[str, Any]:
    """
    Core implementation for listing security rules.
    Used by both MCP tool and Function Calling implementation.
    """
    try:
        if page_size > 1000:
            logger.warning("page_size cannot exceed 1000. Setting to 1000.")
            page_size = 1000

        chronicle = get_chronicle_client(project_id, customer_id, region)
        rules_response = chronicle.list_rules(
            page_size=page_size, page_token=page_token
        )
        return rules_response
    except Exception as e:
        logger.error(f"Error listing security rules: {str(e)}", exc_info=True)
        return {"error": str(e), "rules": []}
