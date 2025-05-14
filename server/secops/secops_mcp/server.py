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

import logging
import os
from pathlib import Path
from typing import Any, Optional

#from fastmcp import Context
from mcp.server.fastmcp.resources import FileResource
from mcp.server.fastmcp import FastMCP
from secops import SecOpsClient

# Initialize FastMCP server with a descriptive name
server = FastMCP('Google Security Operations MCP server', log_level="DEBUG")

ACTIVE_PERSONA = None


# Helper function and formatters for resource registration
def format_persona_name(file_path: Path, _: Path) -> str:
    file_stem = file_path.stem
    persona_name_parts = file_stem.split('_')
    formatted_persona_name = " ".join(part.capitalize() for part in persona_name_parts)
    return f"{formatted_persona_name} Persona File"

def format_persona_description(file_path: Path, _: Path) -> str:
    file_stem = file_path.stem
    persona_name_parts = file_stem.split('_')
    formatted_persona_name = " ".join(part.capitalize() for part in persona_name_parts)
    return f"The Persona File for {formatted_persona_name}"

def format_runbook_name(file_path: Path, relative_to_dir: Path) -> str:
    path_parts_for_name = file_path.relative_to(relative_to_dir).parent.parts
    formatted_name_components = [part.replace("_", " ").capitalize() for part in path_parts_for_name]
    file_stem_capitalized = file_path.stem.replace("_", " ").capitalize()

    full_name_parts = formatted_name_components + [file_stem_capitalized]
    # Filter out empty strings from parts (e.g. if a part was just '.')
    # and ensure proper joining for cases with/without subdirs.
    valid_parts = [part for part in full_name_parts if part and part != '.']
    if not valid_parts: # Should not happen if file_stem_capitalized is always present
        formatted_runbook_name = file_stem_capitalized
    else:
        formatted_runbook_name = " - ".join(valid_parts)
    return f"{formatted_runbook_name} Runbook"

def format_runbook_description(file_path: Path, relative_to_dir: Path) -> str:
    path_parts_for_name = file_path.relative_to(relative_to_dir).parent.parts
    formatted_name_components = [part.replace("_", " ").capitalize() for part in path_parts_for_name]
    file_stem_capitalized = file_path.stem.replace("_", " ").capitalize()

    valid_parts = [part for part in (formatted_name_components + [file_stem_capitalized]) if part and part != '.']
    if not valid_parts:
        core_name = file_stem_capitalized
    else:
        core_name = " - ".join(valid_parts)
    return f"The Runbook for {core_name}"

def format_report_name(file_path: Path, _: Path) -> str:
    return f"Report: {file_path.name}"

def format_report_description(file_path: Path, _: Path) -> str:
    return f"Report file {file_path.name}"

def _register_resources_from_directory(
    server_instance: FastMCP,
    directory_path: Path,
    base_tag: str,
    file_glob_pattern: str,
    name_formatter,
    description_formatter,
    default_mime_type: str,
    skip_file_names: Optional[list[str]] = None
):
    if not directory_path.is_dir():
        logger.warning(f"Directory not found or not a directory: {directory_path}")
        return

    for file_path in directory_path.rglob(file_glob_pattern):
        if skip_file_names and file_path.name in skip_file_names:
            continue

        resolved_path = file_path.resolve()
        if not resolved_path.exists() or not resolved_path.is_file():
            logger.warning(f"File not found or not a file: {resolved_path}")
            continue

        relative_subdirs = file_path.relative_to(directory_path).parent.parts
        tags = [base_tag] + [part for part in relative_subdirs if part and part != '.']

        resource_name = name_formatter(file_path, directory_path)
        resource_description = description_formatter(file_path, directory_path)

        # Ensure tags are strings and unique
        final_tags = set(str(tag) for tag in tags)

        resource = FileResource(
            uri=f"file://{resolved_path.as_posix()}",
            path=resolved_path,
            name=resource_name,
            description=resource_description,
            mime_type=default_mime_type,
            tags=final_tags
        )
        server_instance.add_resource(resource)
        logger.debug(f"Registered resource: {resource_name} with tags {final_tags} from {resolved_path}")

@server.resource("resource://greeting")
def get_greeting() -> str:
    """Provides a simple greeting message."""
    return "Hello from FastMCP Resources!"

@server.resource("resource://persona-active-get")
async def persona_active_get() -> dict:
    """Provides active persona information."""
    if ACTIVE_PERSONA:
        return {
            "persona": ACTIVE_PERSONA,
        }
    else:
        return {
            "persona": "soc_analyst_tier1",
        }

#@server.resource("resource://persona-active-set")
#async def persona_active_set(persona: str) -> dict:
#    """Sets the active persona."""
#    global ACTIVE_PERSONA
#    ACTIVE_PERSONA = persona
#    return {
#        "persona": ACTIVE_PERSONA,
#    }

@server.resource("resource://personas-available-list")
async def personas_available_list() -> dict:
    """Provides available persona list information."""
    return {
        "personas": [
            "soc_analyst_tier1",
            "soc_analyst_tier2",
            "soc_analyst_tier3",
            "ciso",
        ]
    }

# 1. Exposing a static file directly
readme_path = Path("../README.md").resolve()
if readme_path.exists():
    # Use a file:// URI scheme
    readme_resource = FileResource(
        uri=f"file://{readme_path.as_posix()}",
        path=readme_path, # Path to the actual file
        name="README File",
        description="The project's README.",
        mime_type="text/markdown",
        tags={"documentation"}
    )
    server.add_resource(readme_resource)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    filename='secops_mcp.log',
    filemode='a',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('secops-mcp')
# Ensure this logger also respects the DEBUG level set for the basicConfig
logger.setLevel(logging.DEBUG)

# Base path for clinerules-bank and reports
agentic_runbooks_base_path = Path("/Users/dandye/Projects/agentic_runbooks/")

# Register Persona Files
personas_dir = agentic_runbooks_base_path / "clinerules-bank" / "personas"
_register_resources_from_directory(
    server_instance=server,
    directory_path=personas_dir,
    base_tag="persona",
    file_glob_pattern="*.md",
    name_formatter=format_persona_name,
    description_formatter=format_persona_description,
    default_mime_type="text/markdown",
    skip_file_names=["personas.md"]
)

# Register Runbook Files
runbooks_dir = agentic_runbooks_base_path / "clinerules-bank" / "run_books"
_register_resources_from_directory(
    server_instance=server,
    directory_path=runbooks_dir,
    base_tag="runbook",
    file_glob_pattern="*.md",
    name_formatter=format_runbook_name,
    description_formatter=format_runbook_description,
    default_mime_type="text/markdown"
)

# Register Report Files
reports_dir = agentic_runbooks_base_path / "reports"
_register_resources_from_directory(
    server_instance=server,
    directory_path=reports_dir,
    base_tag="report",
    file_glob_pattern="*.*", # All files
    name_formatter=format_report_name,
    description_formatter=format_report_description,
    default_mime_type="application/octet-stream" # Generic, can be improved with mimetypes lib if needed
)

# Constants
USER_AGENT = 'secops-app/1.0'

# Default Chronicle configuration from environment variables
DEFAULT_PROJECT_ID = os.environ.get('CHRONICLE_PROJECT_ID', '725716774503')
DEFAULT_CUSTOMER_ID = os.environ.get(
    'CHRONICLE_CUSTOMER_ID', 'c3c6260c1c9340dcbbb802603bbf9636'
)
DEFAULT_REGION = os.environ.get('CHRONICLE_REGION', 'us')


def get_chronicle_client(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None
) -> Any:
    """Initialize and return a Chronicle client.

    Args:
        project_id: Google Cloud project ID (defaults to CHRONICLE_PROJECT_ID env var)
        customer_id: Chronicle customer ID (defaults to CHRONICLE_CUSTOMER_ID env var)
        region: Chronicle region (defaults to CHRONICLE_REGION env var or "us")

    Returns:
        Any: Initialized Chronicle client
    """
    # Use provided values or defaults from environment variables
    project_id = project_id or DEFAULT_PROJECT_ID
    customer_id = customer_id or DEFAULT_CUSTOMER_ID
    region = region or DEFAULT_REGION

    if not project_id or not customer_id:
        raise ValueError(
            'Chronicle project_id and customer_id must be provided either '
            'as parameters or through environment variables '
            '(CHRONICLE_PROJECT_ID, CHRONICLE_CUSTOMER_ID)'
        )

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
