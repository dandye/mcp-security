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
"""Shared logic for data table management tools."""

import logging
from typing import Any, Dict, List, Optional

from secops_mcp.server import get_chronicle_client

# Configure logging
logger = logging.getLogger('secops-mcp')

def create_data_table_impl(
    name: str,
    description: str,
    header: Dict[str, str],
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    rows: Optional[List[List[str]]] = None,
) -> str:
    """Core implementation for creating a data table."""
    try:
        logger.info(f'Creating data table: {name}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Create the data table
        data_table = chronicle.create_data_table(
            name=name,
            description=description,
            header=header,
            rows=rows or []
        )

        # Extract table details from the response
        table_name = data_table.get("name", "").split("/")[-1]
        create_time = data_table.get("createTime", "Unknown")
        column_count = len(data_table.get("columnInfo", []))

        result = f'Successfully created data table: {name}\n'
        result += f'Table ID: {table_name}\n'
        result += f'Description: {description}\n'
        result += f'Created: {create_time}\n'
        result += f'Columns: {column_count}\n'

        # Show column details
        column_info = data_table.get("columnInfo", [])
        if column_info:
            result += '\nColumn Details:\n'
            for col in column_info:
                col_name = col.get("name", "Unknown")
                col_type = col.get("type", "Unknown")
                result += f'  - {col_name}: {col_type}\n'

        # Show initial row count if rows were provided
        if rows:
            result += f'\nInitial rows added: {len(rows)}'

        result += f'\nThe table can now be referenced in detection rules as: data_table.{name}'

        return result

    except Exception as e:
        logger.error(f'Error creating data table {name}: {str(e)}', exc_info=True)
        return f'Error creating data table {name}: {str(e)}'

def add_rows_to_data_table_impl(
    table_name: str,
    rows: List[List[str]],
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Core implementation for adding rows to a data table."""
    try:
        logger.info(f'Adding {len(rows)} rows to data table: {table_name}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Add rows to the data table
        result_response = chronicle.create_data_table_rows(table_name, rows)

        result = f'Successfully added rows to data table: {table_name}\n'
        result += f'Rows added: {len(rows)}\n'

        # Show sample of added data
        if rows:
            result += '\nSample of added data:\n'
            for i, row in enumerate(rows[:3]):  # Show first 3 rows
                result += f'  Row {i+1}: {row}\n'

            if len(rows) > 3:
                result += f'  ... and {len(rows) - 3} more rows\n'

        result += f'\nThe updated table can be used in detection rules as: data_table.{table_name}'

        return result

    except Exception as e:
        logger.error(f'Error adding rows to data table {table_name}: {str(e)}', exc_info=True)
        return f'Error adding rows to data table {table_name}: {str(e)}'

def list_data_table_rows_impl(
    table_name: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    max_rows: int = 50,
) -> str:
    """Core implementation for listing rows in a data table."""
    try:
        logger.info(f'Listing rows in data table: {table_name}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # List rows in the data table
        rows = chronicle.list_data_table_rows(table_name)

        if not rows:
            return f'Data table "{table_name}" has no rows or was not found.'

        result = f'Data Table: {table_name}\n'
        result += f'Total rows found: {len(rows)}\n'

        # Limit rows displayed
        displayed_rows = rows[:max_rows]
        result += f'Displaying: {len(displayed_rows)} row(s)\n\n'

        # Show rows with their IDs and values
        for i, row in enumerate(displayed_rows):
            row_id = row.get("name", "").split("/")[-1]
            values = row.get("values", [])

            result += f'Row {i+1} (ID: {row_id}):\n'
            result += f'  Values: {values}\n\n'

        if len(rows) > max_rows:
            result += f'Note: Showing first {max_rows} rows out of {len(rows)} total rows.\n'
            result += f'Increase max_rows parameter to see more rows.'

        return result

    except Exception as e:
        logger.error(f'Error listing rows in data table {table_name}: {str(e)}', exc_info=True)
        return f'Error listing rows in data table {table_name}: {str(e)}'

def delete_data_table_rows_impl(
    table_name: str,
    row_ids: List[str],
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Core implementation for deleting rows from a data table."""
    try:
        logger.info(f'Deleting {len(row_ids)} rows from data table: {table_name}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Delete rows from the data table
        chronicle.delete_data_table_rows(table_name, row_ids)

        result = f'Successfully deleted rows from data table: {table_name}\n'
        result += f'Rows deleted: {len(row_ids)}\n'

        # Show the deleted row IDs
        result += '\nDeleted row IDs:\n'
        for row_id in row_ids:
            result += f'  - {row_id}\n'

        result += f'\nWarning: This operation cannot be undone. '
        result += f'Verify the table contents using list_data_table_rows if needed.'

        return result

    except Exception as e:
        logger.error(f'Error deleting rows from data table {table_name}: {str(e)}', exc_info=True)
        return f'Error deleting rows from data table {table_name}: {str(e)}'
