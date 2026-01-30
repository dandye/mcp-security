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
"""Shared logic for parser management tools."""

import base64
import logging
from typing import List, Optional

from secops_mcp.server import get_chronicle_client

# Configure logging
logger = logging.getLogger('secops-mcp')

def create_parser_impl(
    log_type: str,
    parser_code: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    validated_on_empty_logs: bool = True,
) -> str:
    """Core implementation for creating a parser."""
    try:
        logger.info(f'Creating parser for log type: {log_type}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Create the parser
        parser = chronicle.create_parser(
            log_type=log_type,
            parser_code=parser_code,
            validated_on_empty_logs=validated_on_empty_logs
        )

        # Extract parser ID from the response
        parser_id = parser.get("name", "").split("/")[-1]
        state = parser.get("state", "Unknown")

        result = f'Successfully created parser for log type: {log_type}\n'
        result += f'Parser ID: {parser_id}\n'
        result += f'State: {state}\n'

        if validated_on_empty_logs:
            result += 'Parser was validated on empty logs during creation.'

        return result

    except Exception as e:
        logger.error(f'Error creating parser for log type {log_type}: {str(e)}', exc_info=True)
        return f'Error creating parser for log type {log_type}: {str(e)}'

def get_parser_impl(
    log_type: str,
    parser_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Core implementation for getting parser details."""
    try:
        logger.info(f'Getting parser {parser_id} for log type: {log_type}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Get the parser
        parser = chronicle.get_parser(log_type=log_type, id=parser_id)

        parser_name = parser.get("name", "").split("/")[-1]
        state = parser.get("state", "Unknown")
        create_time = parser.get("createTime", "Unknown")

        result = f'Parser Details:\n\n'
        result += f'Parser ID: {parser_name}\n'
        result += f'Log Type: {log_type}\n'
        result += f'State: {state}\n'
        result += f'Created: {create_time}\n\n'

        # Extract and decode parser code if available
        parser_code = parser.get("text", "")
        if not parser_code and "cbn" in parser:
            # Decode base64 encoded parser code
            try:
                parser_code = base64.b64decode(parser["cbn"]).decode('utf-8')
            except Exception as decode_error:
                logger.warning(f"Failed to decode parser code: {decode_error}")
                parser_code = "Could not decode parser code"

        if parser_code:
            result += f'Parser Code:\n{parser_code}\n'
        else:
            result += 'Parser code not available in response.\n'

        return result

    except Exception as e:
        logger.error(f'Error getting parser {parser_id} for log type {log_type}: {str(e)}', exc_info=True)
        return f'Error getting parser {parser_id} for log type {log_type}: {str(e)}'

def activate_parser_impl(
    log_type: str,
    parser_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Core implementation for activating a parser."""
    try:
        logger.info(f'Activating parser {parser_id} for log type: {log_type}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Activate the parser
        chronicle.activate_parser(log_type=log_type, id=parser_id)

        result = f'Successfully activated parser for log type: {log_type}\n'
        result += f'Parser ID: {parser_id}\n'
        result += 'The parser is now active and will process incoming logs of this type.'

        return result

    except Exception as e:
        logger.error(f'Error activating parser {parser_id} for log type {log_type}: {str(e)}', exc_info=True)
        return f'Error activating parser {parser_id} for log type {log_type}: {str(e)}'

def deactivate_parser_impl(
    log_type: str,
    parser_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> str:
    """Core implementation for deactivating a parser."""
    try:
        logger.info(f'Deactivating parser {parser_id} for log type: {log_type}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Deactivate the parser
        chronicle.deactivate_parser(log_type=log_type, id=parser_id)

        result = f'Successfully deactivated parser for log type: {log_type}\n'
        result += f'Parser ID: {parser_id}\n'
        result += 'WARNING: Incoming logs of this type will not be parsed until a parser is activated.'

        return result

    except Exception as e:
        logger.error(f'Error deactivating parser {parser_id} for log type {log_type}: {str(e)}', exc_info=True)
        return f'Error deactivating parser {parser_id} for log type {log_type}: {str(e)}'

def run_parser_against_sample_logs_impl(
    log_type: str,
    parser_code: str,
    sample_logs: List[str],
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
    parser_extension_code: Optional[str] = None,
    statedump_allowed: bool = False,
) -> str:
    """Core implementation for running a parser against sample logs."""
    try:
        logger.info(f'Running parser test for log type: {log_type} with {len(sample_logs)} sample logs')

        # Validate input constraints
        if len(sample_logs) > 1000:
            return "Error: Maximum of 1000 sample logs allowed per test."

        total_size = sum(len(log.encode('utf-8')) for log in sample_logs)
        if total_size > 50 * 1024 * 1024:  # 50MB
            return "Error: Total sample logs size exceeds 50MB limit."

        for i, log in enumerate(sample_logs):
            if len(log.encode('utf-8')) > 10 * 1024 * 1024:  # 10MB
                return f"Error: Sample log {i+1} exceeds 10MB size limit."

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Run the parser
        result = chronicle.run_parser(
            log_type=log_type,
            parser_code=parser_code,
            parser_extension_code=parser_extension_code,
            logs=sample_logs,
            statedump_allowed=statedump_allowed
        )

        # Process and format the results
        response = f'Parser test results for log type: {log_type}\n'
        response += f'Tested {len(sample_logs)} sample log(s)\n\n'

        if "runParserResults" in result:
            for i, parser_result in enumerate(result["runParserResults"]):
                response += f'Log {i+1} Results:\n'

                # Check for parsed events
                if "parsedEvents" in parser_result and parser_result["parsedEvents"]:
                    parsed_events = parser_result["parsedEvents"]
                    if isinstance(parsed_events, dict) and "events" in parsed_events:
                        events = parsed_events["events"]
                        response += f'  Successfully parsed {len(events)} UDM event(s)\n'

                        # Show first event details
                        if events:
                            first_event = events[0]
                            if "event" in first_event:
                                event_data = first_event["event"]
                                if "metadata" in event_data:
                                    metadata = event_data["metadata"]
                                    event_type = metadata.get("eventType", "Unknown")
                                    response += f'  Event Type: {event_type}\n'
                                    if "description" in metadata:
                                        response += f'  Description: {metadata["description"]}\n'
                    else:
                        response += f'  Parsed events: {parsed_events}\n'
                else:
                    response += '  No parsed events generated\n'

                # Check for errors
                if "errors" in parser_result and parser_result["errors"]:
                    errors = parser_result["errors"]
                    response += f'  Parsing errors: {errors}\n'

                response += '\n'
        else:
            response += f'Unexpected result format: {result}'

        return response

    except Exception as e:
        logger.error(f'Error running parser test for log type {log_type}: {str(e)}', exc_info=True)
        return f'Error running parser test for log type {log_type}: {str(e)}'
