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
"""Shared logic for UDM search and export tools."""

import json
import logging
from typing import Any, Dict, List, Optional

from secops_mcp.server import get_chronicle_client
from secops_mcp.utils import parse_time_range

# Configure logging
logger = logging.getLogger("secops-mcp")

def export_udm_search_csv_impl(
    query: str,
    fields: List[str],
    hours_back: int = 24,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    case_insensitive: bool = True,
    project_id: str = None,
    customer_id: str = None,
    region: str = None,
) -> str:
    """Core implementation for exporting UDM search results to CSV."""
    try:
        try:
            start_dt, end_dt = parse_time_range(start_time, end_time, hours_back)
        except ValueError as e:
            logger.error(f'Error parsing date format: {str(e)}', exc_info=True)
            return f"Error parsing date format: {str(e)}. Use ISO 8601 format (e.g., 2023-01-01T12:00:00Z)"

        logger.info(
            f"Exporting UDM search results to CSV - Query: {query}, "
            f"Fields: {fields}, Effective Time Range: {start_dt} to {end_dt}"
        )

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Call the fetch_udm_search_csv method on the chronicle client
        csv_results = chronicle.fetch_udm_search_csv(
            query=query,
            start_time=start_dt,
            end_time=end_dt,
            fields=fields,
            case_insensitive=case_insensitive,
        )

        # SDK/Wrapper is returning JSON string directly instead of CSV
        if isinstance(csv_results, str):
            try:
                csv_results = json.loads(csv_results)
            except json.JSONDecodeError:
                return csv_results

        if isinstance(csv_results, list):
            csv_results = csv_results[0]

        if (
            csv_results.get("queryValidationErrors")
            or csv_results.get("runtimeErrors")
            or csv_results.get("failureCsvFieldValidations")
        ):

            export_errors = (
                csv_results.get("queryValidationErrors")
                or csv_results.get("runtimeErrors")
                or csv_results.get("failureCsvFieldValidations")
            )

            logger.error(
                f"Error exporting UDM search to CSV: {export_errors}",
                exc_info=True,
            )
            return f"Error exporting UDM search results: {export_errors}"

        row_count = 0
        if (
            "csv" in csv_results
            and csv_results["csv"]
            and csv_results["csv"].get("row")
        ):
            row_count = len(csv_results["csv"]["row"])
            logger.info(f"Successfully exported {row_count} rows to CSV format")
            # Returning CSV as a string
            return "\n".join(csv_results["csv"]["row"])

        # Return raw response as default
        return "No results found"

    except Exception as e:
        logger.error(
            f"Error exporting UDM search to CSV: {str(e)}", exc_info=True
        )
        return f"Error exporting UDM search results: {str(e)}"

def find_udm_field_values_impl(
    query: str,
    page_size: Optional[int] = None,
    project_id: str = None,
    customer_id: str = None,
    region: str = None,
) -> Dict[str, Any]:
    """Core implementation for finding UDM field values."""
    try:
        logger.info(f"Finding UDM field values matching: {query}")

        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Call the aliased library function
        results = chronicle.find_udm_field_values(
            query=query, page_size=page_size
        )

        # Log success
        if isinstance(results, dict):
            # Try to extract count information if available
            if "values" in results:
                count = len(results["values"])
            elif "fieldValues" in results:
                count = len(results["fieldValues"])
            else:
                count = "unknown number of"
            logger.info(f"Found {count} matching field values")
        else:
            logger.info("Field value search completed")

        return results

    except Exception as e:
        logger.error(f"Error finding UDM field values: {str(e)}", exc_info=True)
        return {"error": str(e), "values": []}
