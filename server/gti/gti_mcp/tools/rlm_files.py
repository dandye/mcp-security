# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""DSPy 3.4+ RLM-powered file and sandbox behavior tools for GTI MCP."""

from __future__ import annotations

import asyncio
import json
import logging
import typing
from typing import Any, Optional

from mcp.server.fastmcp import Context

from .. import rlm_engine
from .. import utils
from ..server import server, vt_client
from .files import FILE_KEY_RELATIONSHIPS, FILE_RELATIONSHIPS

logger = logging.getLogger(__name__)

FILE_BEHAVIOUR_KEY_RELATIONSHIPS = [
    "contacted_domains",
    "contacted_ips",
    "contacted_urls",
    "dropped_files",
    "embedded_domains",
    "embedded_ips",
    "embedded_urls",
    "associations",
]


async def _fetch_behaviour_summary_raw(
    client: Any, file_hash: str
) -> dict[str, Any]:
  """Fetches /files/{hash}/behaviour_summary and returns data or an error dict."""
  try:
    res = await client.get_async(f"/files/{file_hash}/behaviour_summary")
    res_json = await res.json_async()
  except Exception as exc:
    logger.warning(
        "Failed to fetch behaviour_summary for %s: %s", file_hash, exc
    )
    return {"error": f"Failed to fetch behaviour_summary for {file_hash}: {exc}"}

  if not isinstance(res_json, dict) or "data" not in res_json:
    if isinstance(res_json, dict) and "error" in res_json:
      logger.warning("VirusTotal API Error: %s", res_json["error"])
      return {"error": f"VirusTotal API Error: {res_json['error']}"}
    logger.warning(
        "Unexpected response format from VirusTotal API: %s", res_json
    )
    return {
        "error": f"Unexpected response format from VirusTotal API: {res_json}"
    }
  return utils.sanitize_response(res_json["data"])


async def _safe_fetch_object_relationships(
    client: Any,
    resource_collection_type: str,
    resource_id: str,
    relationship_name: str,
    *,
    descriptors_only: bool = False,
    limit: int = 10,
) -> Any:
  """Wraps utils.fetch_object_relationships to catch TaskGroup / API exceptions cleanly."""
  try:
    res = await utils.fetch_object_relationships(
        client,
        resource_collection_type,
        resource_id,
        relationships=[relationship_name],
        descriptors_only=descriptors_only,
        limit=limit,
    )
  except (asyncio.CancelledError, KeyboardInterrupt):
    raise
  except BaseException as exc:
    logger.warning(
        "Failed to fetch relationship %s for %s: %s",
        relationship_name,
        resource_id,
        exc,
    )
    return {
        "error": (
            f"Failed to fetch relationship '{relationship_name}' "
            f"for {resource_id}: {exc}"
        )
    }
  return utils.sanitize_response(res.get(relationship_name, []))


@server.tool()
async def rlm_get_file_report(
    hash: str,
    ctx: Context,
    query: Optional[str] = None,
) -> dict[str, Any]:
  """Get a high-signal DSPy RLM-distilled file analysis report (1 VT API call).

  Fetches the full VirusTotal/GTI file report (including vendor analysis results,
  PE/ELF/Mach-O headers, YARA/Sigma/IDS matches, Code Insights, and key
  relationships) into a sandboxed Python REPL and distills it using `dspy.RLM`
  while preserving 100% verbatim cryptographic digests.

  Args:
    hash (required): The MD5, SHA-1, or SHA-256 hash of the file to analyze.
    query (optional): Specific question or focus area to answer from the report.

  Returns:
    Structured dictionary with `verbatim_anchors`, `verdict_and_summary`,
    `answer`, `key_findings`, `high_signal_iocs`, `attributions`,
    `mitre_techniques`, `filtered_noise_summary`, and `compression_metrics`.
  """
  async with vt_client(ctx) as client:
    raw_res = await utils.fetch_object(
        client,
        "files",
        "file",
        hash,
        relationships=FILE_KEY_RELATIONSHIPS,
    )
  sanitized = utils.sanitize_response(raw_res)
  if isinstance(sanitized, dict) and "error" in sanitized:
    return sanitized

  endpoint = f"/files/{hash}"
  tracker = rlm_engine.APICallTracker(
      max_api_calls=1,
      initial_endpoint=endpoint,
      initial_bytes=len(json.dumps(sanitized, default=str).encode("utf-8")),
  )
  return await rlm_engine.distill_gti_payload_async(
      sanitized,
      entity_id=hash,
      tool_name="rlm_get_file_report",
      query=query,
      default_objective=(
          "Summarize vendor detection consensus, GTI assessment, Code Insights, "
          "malware family/threat actor attributions, YARA/Sigma/IDS hits, and "
          "contacted/dropped IOCs while omitting raw vendor-by-vendor and PE import noise."
      ),
      tracker=tracker,
  )


@server.tool()
async def rlm_get_file_behavior_summary(
    hash: str,
    ctx: Context,
    query: Optional[str] = None,
) -> dict[str, Any]:
  """Get a high-signal DSPy RLM-distilled summary of all sandbox behaviors (1 VT API call).

  Loads the full `/files/{hash}/behaviour_summary` payload into a sandboxed
  Python REPL, filters out benign OS/sandbox clutter (`SyncRootManager`,
  `MSIExecute`, Fonts/Adobe/NLS reads), and extracts malicious execution trees,
  command lines, persistence, network C2 traffic, and MITRE ATT&CK techniques.

  Args:
    hash (required): MD5, SHA-1, or SHA-256 hash that identifies the file.
    query (optional): Specific behavioral question to answer.

  Returns:
    Structured dictionary with `verbatim_anchors`, distilled behavioral IOCs,
    MITRE techniques, and `compression_metrics`.
  """
  async with vt_client(ctx) as client:
    sanitized = await _fetch_behaviour_summary_raw(client, hash)
  if isinstance(sanitized, dict) and "error" in sanitized:
    return sanitized

  endpoint = f"/files/{hash}/behaviour_summary"
  tracker = rlm_engine.APICallTracker(
      max_api_calls=1,
      initial_endpoint=endpoint,
      initial_bytes=len(json.dumps(sanitized, default=str).encode("utf-8")),
  )
  return await rlm_engine.distill_gti_payload_async(
      sanitized,
      entity_id=hash,
      tool_name="rlm_get_file_behavior_summary",
      query=query,
      default_objective=(
          "Extract malicious process execution trees, command lines, persistence "
          "registry modifications, non-noisy mutexes, dropped files, network C2 "
          "conversations, sandbox signatures, and MITRE ATT&CK techniques."
      ),
      tracker=tracker,
  )


@server.tool()
async def rlm_get_file_behavior_report(
    file_behaviour_id: str,
    ctx: Context,
    query: Optional[str] = None,
) -> dict[str, Any]:
  """Get a high-signal DSPy RLM-distilled sandbox behavior report by ID (1 VT API call).

  The `file_behaviour_id` follows the pattern `"{file_hash}_{sandbox_name}"`.

  Args:
    file_behaviour_id (required): File behaviour identifier.
    query (optional): Specific sandbox execution question to answer.

  Returns:
    Structured dictionary with `verbatim_anchors`, distilled sandbox behavior,
    and `compression_metrics`.
  """
  async with vt_client(ctx) as client:
    raw_res = await utils.fetch_object(
        client,
        "file_behaviours",
        "file_behaviour",
        file_behaviour_id,
        relationships=FILE_BEHAVIOUR_KEY_RELATIONSHIPS,
    )
  sanitized = utils.sanitize_response(raw_res)
  if isinstance(sanitized, dict) and "error" in sanitized:
    return sanitized

  endpoint = f"/file_behaviours/{file_behaviour_id}"
  tracker = rlm_engine.APICallTracker(
      max_api_calls=1,
      initial_endpoint=endpoint,
      initial_bytes=len(json.dumps(sanitized, default=str).encode("utf-8")),
  )
  return await rlm_engine.distill_gti_payload_async(
      sanitized,
      entity_id=file_behaviour_id,
      tool_name="rlm_get_file_behavior_report",
      query=query,
      default_objective=(
          "Distill this sandbox execution report: process tree, command lines, "
          "persistence, network connections, dropped files, and sandbox signatures."
      ),
      tracker=tracker,
  )


@server.tool()
async def rlm_get_entities_related_to_a_file(
    hash: str,
    relationship_name: str,
    ctx: Context,
    descriptors_only: bool = False,
    limit: int = 10,
    query: Optional[str] = None,
) -> dict[str, Any]:
  """Retrieve and distill entities related to a file hash via DSPy RLM (1 VT API call).

  Args:
    hash (required): MD5, SHA-1, or SHA-256 hash that identifies the file.
    relationship_name (required): Relationship name from `FILE_RELATIONSHIPS`.
    descriptors_only (optional): If False (default), fetches full related objects
      and compresses them in the RLM REPL. Set to True for descriptor IDs only.
    limit (optional): Maximum number of related entities to retrieve (default 10).
    query (optional): Specific question about the related entities.

  Returns:
    Structured dictionary with distilled related entities, IOCs, attributions,
    and `compression_metrics`, or an error dict if `relationship_name` is invalid.
  """
  if relationship_name not in FILE_RELATIONSHIPS:
    return {
        "error": (
            f"Relationship {relationship_name} does not exist. "
            f"Available relationships are: {','.join(FILE_RELATIONSHIPS)}"
        )
    }

  async with vt_client(ctx) as client:
    related_items = await _safe_fetch_object_relationships(
        client,
        "files",
        hash,
        relationship_name,
        descriptors_only=descriptors_only,
        limit=limit,
    )
  if isinstance(related_items, dict) and "error" in related_items:
    return related_items
  endpoint = f"/files/{hash}/{relationship_name}"
  tracker = rlm_engine.APICallTracker(
      max_api_calls=1,
      initial_endpoint=endpoint,
      initial_bytes=len(json.dumps(related_items, default=str).encode("utf-8")),
  )
  return await rlm_engine.distill_gti_payload_async(
      related_items,
      entity_id=hash,
      tool_name="rlm_get_entities_related_to_a_file",
      query=query,
      default_objective=(
          f"Summarize the '{relationship_name}' entities related to file {hash}, "
          "highlighting malicious indicators, threat actor/family attributions, "
          "and notable attributes."
      ),
      tracker=tracker,
  )


@server.tool()
async def rlm_investigate_file(
    hash: str,
    ctx: Context,
    investigation_goal: Optional[str] = None,
    max_api_calls: int = 4,
) -> dict[str, Any]:
  """Autonomously investigate a file across multiple GTI endpoints inside a DSPy RLM REPL.

  Unlike the 1-API-call `rlm_get_*` tools, `rlm_investigate_file` seeds the
  `dspy.RLM` Python REPL with `GET /files/{hash}` (call 1) and binds four
  budget-tracked GTI lookup tools inside the REPL so the RLM can selectively
  pivot into sandbox behavior summaries, specific sandbox reports, file
  relationships, and threat actor/malware family collections up to `max_api_calls`:
    - `fetch_behavior_summary()`
    - `fetch_sandbox_report(file_behaviour_id)`
    - `fetch_related_entities(relationship_name, descriptors_only=False, limit=10)`
    - `fetch_collection_summary(collection_id)`

  Args:
    hash (required): MD5, SHA-1, or SHA-256 hash of the file to investigate.
    investigation_goal (optional): Specific investigation question or hypothesis.
    max_api_calls (optional): Maximum total VT API calls allowed across the
      investigation (clamped between 1 and 10; default 4).

  Returns:
    Structured intelligence dictionary combining static analysis, dynamic sandbox
    behavior, and threat attribution with full `compression_metrics`.
  """
  capped_calls = max(1, min(int(max_api_calls), 10))
  loop = asyncio.get_running_loop()

  async with vt_client(ctx) as client:
    initial_raw = await utils.fetch_object(
        client,
        "files",
        "file",
        hash,
        relationships=FILE_KEY_RELATIONSHIPS,
    )
    sanitized_initial = utils.sanitize_response(initial_raw)
    if isinstance(sanitized_initial, dict) and "error" in sanitized_initial:
      return sanitized_initial

    initial_bytes = len(
        json.dumps(sanitized_initial, default=str).encode("utf-8")
    )
    tracker = rlm_engine.APICallTracker(
        max_api_calls=capped_calls,
        initial_endpoint=f"/files/{hash}",
        initial_bytes=initial_bytes,
    )

    def fetch_behavior_summary() -> dict[str, Any]:
      """Fetch `/files/{hash}/behaviour_summary` for the current file hash."""
      endpoint = f"/files/{hash}/behaviour_summary"

      def _do_fetch() -> dict[str, Any]:
        fut = asyncio.run_coroutine_threadsafe(
            _fetch_behaviour_summary_raw(client, hash), loop
        )
        return fut.result(timeout=30.0)

      return tracker.call(endpoint, None, _do_fetch)

    def fetch_sandbox_report(file_behaviour_id: str) -> dict[str, Any]:
      """Fetch a specific sandbox behavior report `/file_behaviours/{file_behaviour_id}`."""
      endpoint = f"/file_behaviours/{file_behaviour_id}"

      def _do_fetch() -> dict[str, Any]:
        coro = utils.fetch_object(
            client,
            "file_behaviours",
            "file_behaviour",
            file_behaviour_id,
            relationships=FILE_BEHAVIOUR_KEY_RELATIONSHIPS,
        )
        fut = asyncio.run_coroutine_threadsafe(coro, loop)
        return utils.sanitize_response(fut.result(timeout=30.0))

      return tracker.call(endpoint, None, _do_fetch)

    def fetch_related_entities(
        relationship_name: str,
        descriptors_only: bool = False,
        limit: int = 10,
    ) -> Any:
      """Fetch `/files/{hash}/{relationship_name}` related entities."""
      if relationship_name not in FILE_RELATIONSHIPS:
        return {
            "error": (
                f"Invalid relationship '{relationship_name}'. "
                f"Valid: {','.join(FILE_RELATIONSHIPS)}"
            )
        }
      endpoint = f"/files/{hash}/{relationship_name}"
      params = {"descriptors_only": descriptors_only, "limit": limit}

      def _do_fetch() -> Any:
        coro = _safe_fetch_object_relationships(
            client,
            "files",
            hash,
            relationship_name,
            descriptors_only=descriptors_only,
            limit=limit,
        )
        fut = asyncio.run_coroutine_threadsafe(coro, loop)
        return fut.result(timeout=30.0)

      return tracker.call(endpoint, params, _do_fetch)

    def fetch_collection_summary(collection_id: str) -> dict[str, Any]:
      """Fetch `/collections/{collection_id}` report for a threat actor, malware family, or campaign."""
      endpoint = f"/collections/{collection_id}"

      def _do_fetch() -> dict[str, Any]:
        coro = utils.fetch_object(
            client,
            "collections",
            "collection",
            collection_id,
            relationships=["associations"],
            params={"exclude_attributes": "aggregations"},
        )
        fut = asyncio.run_coroutine_threadsafe(coro, loop)
        return utils.sanitize_response(fut.result(timeout=30.0))

      return tracker.call(endpoint, None, _do_fetch)

    bound_tools = [
        fetch_behavior_summary,
        fetch_sandbox_report,
        fetch_related_entities,
        fetch_collection_summary,
    ]

    return await rlm_engine.distill_gti_payload_async(
        sanitized_initial,
        entity_id=hash,
        tool_name="rlm_investigate_file",
        query=investigation_goal,
        default_objective=(
            "Perform a comprehensive file triage and attribution investigation: "
            "inspect the static file report first, then use `fetch_behavior_summary()`, "
            "`fetch_related_entities()`, or `fetch_collection_summary()` inside the "
            "REPL within the API call budget to correlate static detections, dynamic "
            "execution behavior, C2 infrastructure, and threat actor attribution."
        ),
        extra_tools=bound_tools,
        tracker=tracker,
    )
