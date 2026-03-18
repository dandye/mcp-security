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
"""Google Security Operations MCP server.

This module implements the Security Operations MCP server to perform
security operations tasks using Chronicle, including natural language search.
"""

import json
import logging
import os
from typing import Any, Optional

from google.oauth2.credentials import Credentials
from mcp.server.fastmcp import FastMCP
from secops import SecOpsClient

# Initialize FastMCP server with a descriptive name
server = FastMCP('Google Security Operations MCP server', log_level="ERROR")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('secops-mcp')

# Constants
USER_AGENT = 'secops-app/0.7.0'

# Default Chronicle configuration from environment variables
DEFAULT_PROJECT_ID = os.environ.get('CHRONICLE_PROJECT_ID', '725716774503')
DEFAULT_CUSTOMER_ID = os.environ.get(
    'CHRONICLE_CUSTOMER_ID', 'c3c6260c1c9340dcbbb802603bbf9636'
)
DEFAULT_REGION = os.environ.get('CHRONICLE_REGION', 'us')

SECOPS_CONFIG_MAP = {}
SECOPS_CONFIG_PATH = os.environ.get('SECOPS_CONFIG_PATH')
if SECOPS_CONFIG_PATH and os.path.exists(SECOPS_CONFIG_PATH):
    try:
        with open(SECOPS_CONFIG_PATH, 'r') as f:
            SECOPS_CONFIG_MAP = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load SECOPS_CONFIG_PATH from {SECOPS_CONFIG_PATH}: {e}")


def get_chronicle_client(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    access_token: Optional[str] = None,
    service_account_file: Optional[str] = None
) -> Any:
    """Initialize and return a Chronicle client.

    Args:
        project_id: Google Cloud project ID (defaults to extracted SA project_id or CHRONICLE_PROJECT_ID)
        customer_id: Chronicle customer ID (defaults to config map or CHRONICLE_CUSTOMER_ID)
        region: Chronicle region (defaults to config map or CHRONICLE_REGION env var or "us")
        access_token: OAuth access token for ADK authentication delegation.
        service_account_file: Path to a specific service account JSON file.

    Returns:
        Any: Initialized Chronicle client
    """
    # Attempt to extract project_id if service_account_file is provided and project_id is empty
    if service_account_file and not project_id:
        try:
            with open(service_account_file, 'r') as f:
                sa_data = json.load(f)
                project_id = sa_data.get('project_id')
        except Exception as e:
            logger.debug(f"Could not parse project_id from SA file: {e}")

    # Use config map to find customer_id and region if project_id is known
    mapped_config = SECOPS_CONFIG_MAP.get(project_id, {}) if project_id else {}
    mapped_customer_id = mapped_config.get('customer_id')
    mapped_region = mapped_config.get('region')

    # Use provided values or defaults from environment variables or config map
    project_id = project_id or DEFAULT_PROJECT_ID
    customer_id = customer_id or mapped_customer_id or DEFAULT_CUSTOMER_ID
    region = region or mapped_region or DEFAULT_REGION

    if not project_id or not customer_id:
        raise ValueError(
            'Chronicle project_id and customer_id must be provided either '
            'as parameters, config map, or through environment variables '
            '(CHRONICLE_PROJECT_ID, CHRONICLE_CUSTOMER_ID)'
        )

    service_account_path = service_account_file or os.getenv("SECOPS_SA_PATH")
    
    if access_token:
        credentials = Credentials(token=access_token)
        client = SecOpsClient(credentials=credentials)
    elif service_account_path:
        client = SecOpsClient(service_account_path=service_account_path)
    else:
        client = SecOpsClient()

    chronicle = client.chronicle(
        customer_id=customer_id, project_id=project_id, region=region
    )
    return chronicle


# Import all tools
from secops_mcp.tools import *


def main() -> None:
    """Run the MCP server for SecOps tools.

    This function initializes and starts the MCP server with all the defined
    tools.
    """
    # Initialize and run the server
    server.run(transport='stdio')


if __name__ == '__main__':
    main()