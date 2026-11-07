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
"""Security Operations MCP tools for UDM search."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from mcp.types import ToolAnnotations as _ToolAnnotations
from secops_mcp.server import get_chronicle_client, server
from secops_mcp.utils import parse_time_range, tool_error_result as _tool_error_result


# Configure logging
logger = logging.getLogger('secops-mcp')


@server.tool(
    title='Search Chronicle UDM Events',
    annotations=_ToolAnnotations(
        title='Search Chronicle UDM Events',
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def search_udm(
    query: str,
    hours_back: int = 24,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events: Optional[int] = None,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> dict[str, Any]:
    """Search UDM events using UDM query in Chronicle.

    Args:
        query (str): UDM query to search for events.
        hours_back (int): How many hours back from the current time to search. Used if start_time is not provided.
        start_time (Optional[str]): Start time in ISO 8601 format (e.g. "2023-01-01T00:00:00Z"). Overrides hours_back.
        end_time (Optional[str]): End time in ISO 8601 format. Defaults to current time if not provided.
        max_events (Optional[int]): Maximum number of events to return.
        project_id (Optional[str]): Google Cloud project ID.
        customer_id (Optional[str]): Chronicle customer ID.
        region (Optional[str]): Chronicle region (e.g., "us", "europe").

    Returns:
        Dict containing the search results with events.
    """
    try:
        try:
            start_dt, end_dt = parse_time_range(start_time, end_time, hours_back)
        except ValueError as e:
            logger.error('Error parsing date format: %s', e, exc_info=True)
            return _tool_error_result(
                f'Error parsing date format: {e}. Use ISO 8601 format (e.g., 2023-01-01T12:00:00Z)',
                events=[],
            )

        logger.info(
            'Searching UDM events - Query: %s, Effective Time Range: %s to %s',
            query,
            start_dt,
            end_dt,
        )

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Call the search_udm method on the chronicle client
        search_results = chronicle.search_udm(
            query=query,
            start_time=start_dt,
            end_time=end_dt,
            max_events=max_events,
        )

        logger.info('Successfully found %s events.', search_results.get('total_events', 0))

        return search_results

    except Exception as e:
        logger.error('Error searching UDM events: %s', e, exc_info=True)
        return _tool_error_result(str(e), events=[])
