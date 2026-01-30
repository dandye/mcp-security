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
"""Shared logic for log ingestion tools."""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from secops_mcp.server import get_chronicle_client

# Configure logging
logger = logging.getLogger('secops-mcp')

def ingest_raw_log_impl(
    log_type: str,
    log_message: Union[str, List[str]],
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    forwarder_id: Optional[str] = None,
    labels: Optional[Dict[str, str]] = None,
    log_entry_time: Optional[str] = None,
    collection_time: Optional[str] = None,
) -> str:
    """Core implementation for ingesting raw logs."""
    try:
        logger.info(f'Ingesting raw log of type: {log_type}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Prepare ingestion parameters
        ingestion_params = {
            'log_type': log_type,
            'log_message': log_message
        }

        if forwarder_id:
            ingestion_params['forwarder_id'] = forwarder_id
        if labels:
            ingestion_params['labels'] = labels
        if log_entry_time:
            ingestion_params['log_entry_time'] = datetime.fromisoformat(log_entry_time.replace('Z', '+00:00'))
        if collection_time:
            ingestion_params['collection_time'] = datetime.fromisoformat(collection_time.replace('Z', '+00:00'))

        # Ingest the log(s)
        result = chronicle.ingest_log(**ingestion_params)

        # Format response
        operation = result.get('operation', 'Unknown operation')
        log_count = len(log_message) if isinstance(log_message, list) else 1

        response = f'Successfully ingested {log_count} log(s) of type {log_type}.\n'
        response += f'Operation: {operation}'

        if labels:
            response += f'\nLabels applied: {labels}'

        return response

    except Exception as e:
        logger.error(f'Error ingesting raw log: {str(e)}', exc_info=True)
        return f'Error ingesting raw log: {str(e)}'

def ingest_udm_events_impl(
    udm_events: Union[Dict[str, Any], List[Dict[str, Any]]],
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Core implementation for ingesting UDM events."""
    try:
        logger.info('Ingesting UDM events')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Auto-generate IDs for events that don't have them
        events_to_ingest = udm_events if isinstance(udm_events, list) else [udm_events]

        for event in events_to_ingest:
            if 'metadata' in event and 'id' not in event['metadata']:
                event['metadata']['id'] = str(uuid.uuid4())

        # Ingest the UDM events
        result = chronicle.ingest_udm(udm_events=udm_events)

        # Format response
        event_count = len(events_to_ingest)
        response = f'Successfully ingested {event_count} UDM event(s).\n'

        # Add event IDs if available
        event_ids = []
        for event in events_to_ingest:
            if 'metadata' in event and 'id' in event['metadata']:
                event_ids.append(event['metadata']['id'])

        if event_ids:
            response += f'Event IDs: {", ".join(event_ids[:5])}'  # Show first 5 IDs
            if len(event_ids) > 5:
                response += f' (and {len(event_ids) - 5} more)'

        return response

    except Exception as e:
        logger.error(f'Error ingesting UDM events: {str(e)}', exc_info=True)
        return f'Error ingesting UDM events: {str(e)}'

def get_available_log_types_impl(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    search_term: Optional[str] = None,
) -> str:
    """Core implementation for getting available log types."""
    try:
        logger.info(f'Getting available log types, search term: {search_term}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        if search_term:
            # Search for specific log types
            log_types = chronicle.search_log_types(search_term)
        else:
            # Get all log types (limit to first 50 to avoid overwhelming output)
            log_types = chronicle.get_all_log_types()[:50]

        if not log_types:
            return f'No log types found{" matching search term: " + search_term if search_term else ""}.'

        result = f'Found {len(log_types)} log type(s):\n\n'

        for log_type in log_types:
            log_id = getattr(log_type, 'id', 'Unknown ID')
            description = getattr(log_type, 'description', 'No description available')
            result += f'ID: {log_id}\n'
            result += f'Description: {description}\n\n'

        if len(log_types) == 50 and not search_term:
            result += '\nNote: Only showing first 50 log types. Use search_term to filter results.'

        return result

    except Exception as e:
        logger.error(f'Error getting available log types: {str(e)}', exc_info=True)
        return f'Error getting available log types: {str(e)}'
