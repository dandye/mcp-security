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
"""Shared logic for feed management tools."""

import logging
from typing import Any, Dict, Optional

from secops_mcp.server import get_chronicle_client

# Configure logging
logger = logging.getLogger("secops-mcp")

def list_feeds_impl(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for listing feeds."""
    try:
        logger.info("Listing feeds")
        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Get all feeds
        feeds = chronicle.list_feeds()

        # Process feeds into a structured response
        result = {
            "feeds": [],
            "total_feeds": len(feeds),
            "active_feeds": 0,
            "disabled_feeds": 0,
        }

        # Count active and disabled feeds
        for feed in feeds:
            feed_state = feed.get("state", "UNKNOWN")
            if feed_state == "ACTIVE":
                result["active_feeds"] += 1
            elif feed_state == "INACTIVE":
                result["disabled_feeds"] += 1

            # Add feed details to result
            result["feeds"].append(feed)

        return result
    except Exception as e:
        logger.error(f"Error listing feeds: {e}", exc_info=True)
        return {"error": f"Error listing feeds: {e}"}

def get_feed_impl(
    feed_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for getting feed details."""
    try:
        logger.info(f"Getting details for feed with ID: {feed_id}")
        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Get feed details
        feed = chronicle.get_feed(feed_id)

        if not feed:
            return {"error": f"Feed with ID {feed_id} not found"}

        return feed
    except Exception as e:
        logger.error(f"Error getting feed: {e}", exc_info=True)
        return {"error": f"Error getting feed: {e}"}

def create_feed_impl(
    display_name: str,
    feed_details: Dict[str, Any],
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for creating a feed."""
    try:
        logger.info(f"Creating new feed: {display_name}")
        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Create the feed
        return chronicle.create_feed(
            display_name=display_name, details=feed_details
        )

    except Exception as e:
        logger.error(f"Error creating feed: {e}", exc_info=True)
        return {"error": f"Error creating feed: {e}"}

def update_feed_impl(
    feed_id: str,
    display_name: Optional[str] = None,
    feed_details: Dict[str, Any] = None,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for updating a feed."""
    try:
        logger.info(f"Updating feed with ID: {feed_id}")
        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Update the feed
        return chronicle.update_feed(
            feed_id=feed_id,
            display_name=display_name,
            details=feed_details or {},
        )
    except Exception as e:
        logger.error(f"Error updating feed: {e}", exc_info=True)
        return {"error": f"Error updating feed: {e}"}

def enable_feed_impl(
    feed_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for enabling a feed."""
    try:
        logger.info(f"Enabling feed with ID: {feed_id}")
        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Enable the feed
        enabled_feed = chronicle.enable_feed(feed_id)

        # Format the response
        result = {
            "id": feed_id,
            "state": enabled_feed.get("state", "UNKNOWN"),
            "message": "Feed enabled successfully",
        }

        return result
    except Exception as e:
        logger.error(f"Error enabling feed: {e}", exc_info=True)
        return {"error": f"Error enabling feed: {e}"}

def disable_feed_impl(
    feed_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for disabling a feed."""
    try:
        logger.info(f"Disabling feed with ID: {feed_id}")
        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Disable the feed
        disabled_feed = chronicle.disable_feed(feed_id)

        # Format the response
        result = {
            "id": feed_id,
            "state": disabled_feed.get("state", "UNKNOWN"),
            "message": "Feed disabled successfully",
        }

        return result
    except Exception as e:
        logger.error(f"Error disabling feed: {e}", exc_info=True)
        return {"error": f"Error disabling feed: {e}"}

def delete_feed_impl(
    feed_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for deleting a feed."""
    try:
        logger.info(f"Deleting feed with ID: {feed_id}")
        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Delete the feed
        chronicle.delete_feed(feed_id)

        # Format the response
        result = {"id": feed_id, "message": "Feed deleted successfully"}

        return result
    except Exception as e:
        logger.error(f"Error deleting feed: {e}", exc_info=True)
        return {"error": f"Error deleting feed: {e}"}

def generate_feed_secret_impl(
    feed_id: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Core implementation for generating a feed secret."""
    try:
        logger.info(f"Generating secret for feed with ID: {feed_id}")
        chronicle = get_chronicle_client(project_id, customer_id, region)

        # Generate the secret
        secret_result = chronicle.generate_secret(feed_id)

        # Format the response
        result = {"id": feed_id, "message": "Secret generated successfully"}

        # Add secret to response if returned by the API
        if secret_result and "secret" in secret_result:
            result["secret"] = secret_result["secret"]

        return result
    except Exception as e:
        logger.error(f"Error generating feed secret: {e}", exc_info=True)
        return {"error": f"Error generating feed secret: {e}"}
