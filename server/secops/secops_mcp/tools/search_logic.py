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
"""Shared logic for UDM search tools."""

import logging
from typing import Any, Dict, Optional

from secops_mcp.server import get_chronicle_client
from secops_mcp.utils import parse_time_range

# Configure logging
logger = logging.getLogger('secops-mcp')

def search_udm_impl(
    query: str,
    hours_back: int = 24,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events: Optional[int] = None,
    project_id: str = None,
    customer_id: str = None,
    region: str = None,
) -> Dict[str, Any]:
    """Core implementation for searching UDM events."""
    try:
        try:
            start_dt, end_dt = parse_time_range(start_time, end_time, hours_back)
        except ValueError as e:
            logger.error(f'Error parsing date format: {str(e)}', exc_info=True)
            return {'error': f"Error parsing date format: {str(e)}. Use ISO 8601 format (e.g., 2023-01-01T12:00:00Z)", 'events': []}

        logger.info(
            f'Searching UDM events - Query: {query}, Effective Time Range: {start_dt} to {end_dt}'
        )

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Call the search_udm method on the chronicle client
        search_results = chronicle.search_udm(
            query=query,
            start_time=start_dt,
            end_time=end_dt,
            max_events=max_events,
        )

        logger.info(f'Successfully found {search_results.get("total_events", 0)} events.')

        return search_results

    except Exception as e:
        logger.error(f'Error searching UDM events: {str(e)}', exc_info=True)
        return {'error': str(e), 'events': []}
