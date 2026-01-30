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
"""Shared logic for security events tools."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from secops_mcp.server import get_chronicle_client
from secops_mcp.utils import parse_time_range

# Configure logging
logger = logging.getLogger('secops-mcp')

def search_security_events_impl(
    text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    hours_back: int = 24,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events: int = 100,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for searching security events using natural language."""
    try:
        try:
            start_dt, end_dt = parse_time_range(start_time, end_time, hours_back)
        except ValueError as e:
            logger.error(f'Error parsing date format: {str(e)}', exc_info=True)
            return {
                'udm_query': None,
                'events': {'error': f"Error parsing date format: {str(e)}. Use ISO 8601 format (e.g., 2023-01-01T12:00:00Z)", 'events': [], 'total_events': 0},
            }

        logger.info(
            f'Searching security events - Query: {text}, Effective Time Range: {start_dt} to {end_dt}'
        )

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Use the new natural language search method
        udm_query = chronicle.translate_nl_to_udm(text)
        logger.info(f'YL2 UDM Query: {udm_query}')

        events = chronicle.search_udm(
            query=udm_query,
            start_time=start_dt,
            end_time=end_dt,
            max_events=max_events,
        )

        # For compatibility with old format, check if we need to transform response
        if isinstance(events, dict) and 'events' in events:
            total_events = events.get('total_events', 0)
            event_list = events.get('events', [])
        else:
            # This might be the case with the standard library format
            event_list = events if isinstance(events, list) else []
            total_events = len(event_list)
            events = {'events': event_list, 'total_events': total_events}

        logger.info(
            f'Search results: {total_events} total events,'
            f' {len(event_list)} returned'
        )

        # Return a new dictionary with UDM query first, then events data
        return {'udm_query': udm_query, 'events': events}

    except Exception as e:
        logger.error(f'Error searching security events: {str(e)}', exc_info=True)
        # Return an error object that can be processed by the model
        return {
            'udm_query': None,
            'events': {'error': str(e), 'events': [], 'total_events': 0},
        }
