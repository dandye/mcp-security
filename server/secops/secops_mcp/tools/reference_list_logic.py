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
"""Shared logic for reference list management tools."""

import logging
from typing import Any, Dict, List, Optional

from secops.chronicle import ReferenceListView
from secops_mcp.server import get_chronicle_client

# Configure logging
logger = logging.getLogger('secops-mcp')

def create_reference_list_impl(
    name: str,
    description: str,
    entries: List[str],
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    syntax_type: str = "STRING",
) -> str:
    """Core implementation for creating a reference list."""
    try:
        logger.info(f'Creating reference list: {name} with {len(entries)} entries')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Create the reference list
        reference_list = chronicle.create_reference_list(
            name=name,
            description=description,
            entries=entries,
            syntax_type=syntax_type
        )

        # Extract list details from the response
        list_name = reference_list.get("name", "").split("/")[-1]
        create_time = reference_list.get("createTime", "Unknown")
        entry_count = len(reference_list.get("entries", []))

        result = f'Successfully created reference list: {name}\n'
        result += f'List ID: {list_name}\n'
        result += f'Description: {description}\n'
        result += f'Syntax Type: {syntax_type}\n'
        result += f'Created: {create_time}\n'
        result += f'Entries: {entry_count}\n'

        # Show sample entries
        if entries:
            result += '\nSample entries:\n'
            for i, entry in enumerate(entries[:5]):  # Show first 5 entries
                result += f'  - {entry}\n'

            if len(entries) > 5:
                result += f'  ... and {len(entries) - 5} more entries\n'

        result += f'\nThe list can now be referenced in detection rules as: reference_list.{name}'

        return result

    except Exception as e:
        logger.error(f'Error creating reference list {name}: {str(e)}', exc_info=True)
        return f'Error creating reference list {name}: {str(e)}'

def get_reference_list_impl(
    name: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    include_entries: bool = True,
) -> str:
    """Core implementation for getting a reference list."""
    try:
        logger.info(f'Getting reference list: {name}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Determine view based on include_entries parameter
        view = (
            ReferenceListView.FULL
            if include_entries
            else ReferenceListView.BASIC
        )

        # Get the reference list
        reference_list = chronicle.get_reference_list(name, view=view)

        if not reference_list:
            return f'Reference list "{name}" was not found.'

        # Extract list details
        list_name = reference_list.get("name", "").split("/")[-1]
        description = reference_list.get("description", "No description")
        create_time = reference_list.get("createTime", "Unknown")
        syntax_type = reference_list.get("syntaxType", "Unknown")

        result = f'Reference List: {name}\n'
        result += f'List ID: {list_name}\n'
        result += f'Description: {description}\n'
        result += f'Syntax Type: {syntax_type}\n'
        result += f'Created: {create_time}\n'

        # Show entries if requested
        if include_entries:
            entries = reference_list.get("entries", [])
            entry_count = len(entries)
            result += f'Total entries: {entry_count}\n\n'

            if entries:
                result += 'Entries:\n'
                for i, entry in enumerate(entries):
                    if isinstance(entry, str):
                        entry_value = entry
                    elif isinstance(entry, dict):
                        entry_value = entry.get("value", "Unknown")
                    elif hasattr(entry, "value"):
                        entry_value = entry.value
                    else:
                        entry_value = str(entry)
                    result += f'  {i+1}. {entry_value}\n'

                    # Limit display for very large lists
                    if i >= 49:  # Show first 50 entries
                        remaining = entry_count - 50
                        if remaining > 0:
                            result += f'  ... and {remaining} more entries\n'
                        break
            else:
                result += 'No entries found in this reference list.\n'
        else:
            # Just show count if entries are not included
            entries = reference_list.get("entries", [])
            result += f'Total entries: {len(entries)} (entries not displayed)\n'

        return result

    except Exception as e:
        logger.error(f'Error getting reference list {name}: {str(e)}', exc_info=True)
        return f'Error getting reference list {name}: {str(e)}'

def update_reference_list_impl(
    name: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    entries: Optional[List[str]] = None,
    description: Optional[str] = None,
) -> str:
    """Core implementation for updating a reference list."""
    try:
        # Validate that at least one update parameter is provided
        if entries is None and description is None:
            return "Error: Either entries or description must be provided for update."

        logger.info(f'Updating reference list: {name}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Prepare update parameters
        update_params = {"name": name}
        if entries is not None:
            update_params["entries"] = entries
        if description is not None:
            update_params["description"] = description

        # Update the reference list
        updated_list = chronicle.update_reference_list(**update_params)

        result = f'Successfully updated reference list: {name}\n'

        # Show what was updated
        if entries is not None:
            result += f'Entries updated: {len(entries)} total entries\n'

            # Show sample of new entries
            if entries:
                result += '\nSample of updated entries:\n'
                for i, entry in enumerate(entries[:5]):  # Show first 5 entries
                    result += f'  - {entry}\n'

                if len(entries) > 5:
                    result += f'  ... and {len(entries) - 5} more entries\n'

        if description is not None:
            result += f'Description updated: {description}\n'

        result += f'\nThe updated list can be used in detection rules as: reference_list.{name}'

        return result

    except Exception as e:
        logger.error(f'Error updating reference list {name}: {str(e)}', exc_info=True)
        return f'Error updating reference list {name}: {str(e)}'
