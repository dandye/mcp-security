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
from typing import Any, Dict, Optional

from secops_mcp.server import get_chronicle_client, server


# Configure logging
logger = logging.getLogger('secops-mcp')

@server.tool()
async def search_udm(
    query: str,
    project_id: str = None,
    customer_id: str = None,
    start_time: str = None,
    end_time: str = None,
    hours_back: int = 24,
    max_events: Optional[int] = None,
    region: str = None,
) -> Dict[str, Any]:
    """Search UDM events using UDM query in Chronicle.

    Args:
        query (str): UDM query to search for events.
        project_id (Optional[str]): Google Cloud project ID.
        customer_id (Optional[str]): Chronicle customer ID.
        start_time (Optional[str]): Start time in ISO 8601 format (e.g., "2023-01-01T00:00:00Z").
        end_time (Optional[str]): End time in ISO 8601 format. Defaults to now if start_time is set.
        hours_back (int): How many hours back from the current time to search. Defaults to 24.
        max_events (Optional[int]): Maximum number of events to return.
        region (Optional[str]): Chronicle region (e.g., "us", "europe").

    Returns:
        Dict containing the search results with events.
    """
    try:
        logger.info(
            f'Searching UDM events - Query: {query}, '
            f'start={start_time}, end={end_time}, hours_back={hours_back}'
        )

        chronicle = get_chronicle_client(project_id, customer_id, region)

        if start_time:
            # Parse ISO strings
            # Handle 'Z' manually for broader python compatibility
            s_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            if end_time:
                e_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            else:
                e_time = datetime.now(timezone.utc)
        else:
            e_time = datetime.now(timezone.utc)
            s_time = e_time - timedelta(hours=hours_back)

        logger.info(f'Search time range: {s_time} to {e_time}')

        # Call the search_udm method on the chronicle client
        search_results = chronicle.search_udm(
            query=query,
            start_time=s_time,
            end_time=e_time,
            max_events=max_events,
        )

        logger.info(f'Successfully found {search_results.get("total_events", 0)} events.')

        return search_results

    except Exception as e:
        logger.error(f'Error searching UDM events: {str(e)}', exc_info=True)
        return {'error': str(e), 'events': []}


@server.tool()
async def search_udm_8601(
    query: str,
    project_id: str = None,
    customer_id: str = None,
    start_time: str = None,
    end_time: str = None,
    hours_back: int = 24,
    max_events: Optional[int] = None,
    region: str = None,
) -> Dict[str, Any]:
    """Search UDM events using UDM query in Chronicle with explicit time ranges.

    This is an enhanced version of search_udm that supports explicit
    start_time and end_time parameters for precise historical searching.

    Args:
        query (str): UDM query to search for events.
        project_id (Optional[str]): Google Cloud project ID.
        customer_id (Optional[str]): Chronicle customer ID.
        start_time (Optional[str]): Start time in ISO 8601 format (e.g., "2023-01-01T00:00:00Z").
        end_time (Optional[str]): End time in ISO 8601 format. Defaults to now if start_time is set.
        hours_back (int): Fallback hours back if start_time is not provided. Defaults to 24.
        max_events (Optional[int]): Maximum number of events to return.
        region (Optional[str]): Chronicle region (e.g., "us", "europe").

    Returns:
        Dict containing the search results with events.
    """
    try:
        logger.info(
            f'Searching UDM events (v2) - Query: {query}, '
            f'start={start_time}, end={end_time}, hours_back={hours_back}'
        )

        chronicle = get_chronicle_client(project_id, customer_id, region)

        if start_time:
            # Parse ISO strings
            # Handle 'Z' manually for broader python compatibility
            s_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            if end_time:
                e_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            else:
                e_time = datetime.now(timezone.utc)
        else:
            e_time = datetime.now(timezone.utc)
            s_time = e_time - timedelta(hours=hours_back)

        logger.info(f'Search time range: {s_time} to {e_time}')

        # Call the search_udm method on the chronicle client
        search_results = chronicle.search_udm(
            query=query,
            start_time=s_time,
            end_time=e_time,
            max_events=max_events,
        )

        logger.info(f'Successfully found {search_results.get("total_events", 0)} events.')

        return search_results

    except Exception as e:
        logger.error(f'Error searching UDM events: {str(e)}', exc_info=True)
        return {'error': str(e), 'events': []}

