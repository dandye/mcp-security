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
"""DSPy RLM-compacted security event search and entity timeline tools for Chronicle SIEM."""

import logging
import re
from typing import Any, Dict, Optional

from secops_mcp import rlm_engine
from secops_mcp.server import get_chronicle_client, server
from secops_mcp.utils import parse_time_range

logger = logging.getLogger("secops-mcp")

_RAW_UDM_SYNTAX_RE = re.compile(
    r"\b(?:metadata|principal|target|src|observer|network|security_result|about)\.[a-zA-Z0-9_.]+\s*(?:=|!=|in\b)",
    re.IGNORECASE,
)


def _looks_like_raw_udm(text: str) -> bool:
  """Returns True if `text` already uses explicit Chronicle UDM field syntax."""
  return bool(_RAW_UDM_SYNTAX_RE.search(text or ""))


def _normalize_search_udm_response(events: Any) -> dict[str, Any]:
  """Normalizes `chronicle.search_udm` output into `{'events': [...], 'total_events': int}`."""
  if isinstance(events, dict) and "events" in events:
    event_list = events.get("events") or []
    total_events = int(events.get("total_events") or len(event_list))
    return {"events": event_list, "total_events": total_events}
  event_list = events if isinstance(events, list) else []
  return {"events": event_list, "total_events": len(event_list)}


@server.tool()
async def rlm_search_security_events(
    text: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    hours_back: int = 24,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events: int = 100,
    region: Optional[str] = None,
    is_raw_udm: bool = False,
    query: Optional[str] = None,
) -> Dict[str, Any]:
  """Search Chronicle SIEM security events and distill the UDM payload via DSPy RLM (>95% compaction).

  Translates a natural-language query into UDM (or executes a raw UDM query when
  `is_raw_udm=True` or UDM field syntax is detected), retrieves up to `max_events`
  raw UDM records (typically 390 KB - 1.35 MB for 50-200 Windows/Sysmon/EDR events),
  and compacts them inside `SecOpsSandboxedInterpreter`:
  - Deterministically preserves 100% of verbatim `hostnames`, `ip_addresses`,
    `users`, cryptographic `file_hashes` (`md5`, `sha1`, `sha256` with `full_path`),
    and `command_lines` under `verbatim_anchors`.
  - Collapses repetitive background OS processes (`svchost.exe`, `conhost.exe`,
    `MpCmdRun.exe`) and deduplicates identical process/file/network events into
    counted chronological timeline groups.

  Args:
      text: Natural-language description of the events to find, or a raw UDM query.
      project_id: Google Cloud project ID (defaults to environment configuration).
      customer_id: Chronicle customer ID (defaults to environment configuration).
      hours_back: Hours back from current time when `start_time` is not provided.
      start_time: ISO 8601 start timestamp (e.g. "2026-10-31T14:18:00Z").
      end_time: ISO 8601 end timestamp (e.g. "2026-10-31T14:27:00Z").
      max_events: Maximum raw UDM events to fetch for RLM compaction (default 100).
      region: Chronicle region (e.g. "us", "europe").
      is_raw_udm: Set True when `text` is already a UDM query string.
      query: Optional specific analytical question for the RLM synthesis.
  """
  try:
    try:
      start_dt, end_dt = parse_time_range(start_time, end_time, hours_back)
    except ValueError as exc:
      logger.error("Error parsing date format: %s", exc, exc_info=True)
      return {
          "udm_query": None,
          "error": (
              f"Error parsing date format: {exc}. Use ISO 8601 format "
              "(e.g., 2026-10-31T14:18:00Z)"
          ),
      }

    chronicle = get_chronicle_client(project_id, customer_id, region)

    if is_raw_udm or _looks_like_raw_udm(text):
      udm_query = text
    else:
      udm_query = chronicle.translate_nl_to_udm(text)

    logger.info(
        "Executing rlm_search_security_events - UDM Query: %s (%s to %s, max_events=%s)",
        udm_query,
        start_dt,
        end_dt,
        max_events,
    )

    raw_events_resp = chronicle.search_udm(
        query=udm_query,
        start_time=start_dt,
        end_time=end_dt,
        max_events=max_events,
    )
    normalized_resp = _normalize_search_udm_response(raw_events_resp)
    raw_envelope = {
        "udm_query": udm_query,
        "events": normalized_resp,
    }

    tracker = rlm_engine.APICallTracker(max_api_calls=1)
    tracker.record_initial("search_udm", raw_envelope)

    effective_query = query or (
        "Reconstruct the chronological attack timeline from these Chronicle UDM "
        "events, highlighting initial access, credential access, lateral movement, "
        "command lines, file hashes (MD5/SHA-256), hostnames, IPs, and users."
    )

    return await rlm_engine.distill_secops_udm_async(
        raw_payload=raw_envelope,
        entity_or_search_text=text,
        tool_name="rlm_search_security_events",
        query=effective_query,
        udm_query=udm_query,
        api_tracker=tracker,
    )
  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.error("Error in rlm_search_security_events: %s", exc, exc_info=True)
    return {
        "udm_query": None,
        "error": str(exc),
    }


@server.tool()
async def rlm_investigate_entity_timeline(
    entity_value: str,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    hours_back: int = 24,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_events: int = 100,
    region: Optional[str] = None,
    investigation_goal: Optional[str] = None,
    max_api_calls: int = 4,
) -> Dict[str, Any]:
  """Autonomously investigate an entity (hostname, IP, user, or hash) in Chronicle SIEM via DSPy RLM.

  Fetches initial UDM telemetry for `entity_value` and mounts sandboxed REPL pivot
  tools (`fetch_entity_summary`, `search_entity_udm_events`, `fetch_entity_alerts`)
  under a strict `max_api_calls` budget, returning a single >95%-compacted
  investigation report with verbatim cryptographic hashes, command lines, and alerts.
  """
  try:
    start_dt, end_dt = parse_time_range(start_time, end_time, hours_back)
    chronicle = get_chronicle_client(project_id, customer_id, region)

    val_clean = entity_value.strip()
    if re.match(r"^[0-9a-fA-F]{32}$", val_clean):
      initial_udm_query = (
          f'target.process.file.md5 = "{val_clean}" OR '
          f'target.file.md5 = "{val_clean}" OR '
          f'principal.process.file.md5 = "{val_clean}"'
      )
    elif re.match(r"^[0-9a-fA-F]{64}$", val_clean):
      initial_udm_query = (
          f'target.process.file.sha256 = "{val_clean}" OR '
          f'target.file.sha256 = "{val_clean}" OR '
          f'principal.process.file.sha256 = "{val_clean}"'
      )
    elif re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", val_clean):
      initial_udm_query = f'principal.ip = "{val_clean}" OR target.ip = "{val_clean}"'
    else:
      initial_udm_query = (
          f'principal.hostname = "{val_clean}" OR '
          f'target.hostname = "{val_clean}" OR '
          f'principal.user.userid = "{val_clean}" OR '
          f'target.user.userid = "{val_clean}"'
      )

    raw_events_resp = chronicle.search_udm(
        query=initial_udm_query,
        start_time=start_dt,
        end_time=end_dt,
        max_events=max_events,
    )
    normalized_resp = _normalize_search_udm_response(raw_events_resp)
    raw_envelope = {
        "udm_query": initial_udm_query,
        "events": normalized_resp,
    }

    tracker = rlm_engine.APICallTracker(max_api_calls=max_api_calls)
    tracker.record_initial(f"search_udm:{val_clean}", raw_envelope)

    def fetch_entity_summary(target_entity: str = val_clean) -> dict[str, Any]:
      """Fetches Chronicle entity summary (first/last seen, related entities, alert counts)."""
      ep = f"summarize_entity:{target_entity}"
      cached = tracker.get_cached(ep)
      if cached is not None:
        return cached
      if not tracker.try_acquire(ep):
        return {
            "budget_exhausted": True,
            "message": f"API call budget ({tracker.max_api_calls}) reached.",
        }
      summary_obj = chronicle.summarize_entity(
          value=target_entity,
          start_time=start_dt,
          end_time=end_dt,
      )
      primary = getattr(summary_obj, "primary_entity", None)
      entity_type = (
          getattr(getattr(primary, "metadata", None), "entity_type", "UNKNOWN")
          if primary
          else "UNKNOWN"
      )
      metric = getattr(primary, "metric", None) if primary else None
      alert_counts = [
          {
              "rule": getattr(a, "rule", "Unknown"),
              "count": getattr(a, "count", 0),
          }
          for a in (getattr(summary_obj, "alert_counts", None) or [])
      ]
      compact_summary = {
          "entity": target_entity,
          "entity_type": str(entity_type),
          "first_seen": str(getattr(metric, "first_seen", None)),
          "last_seen": str(getattr(metric, "last_seen", None)),
          "alert_counts": alert_counts,
      }
      tracker.store_response(ep, str(summary_obj), compact_summary)
      return compact_summary

    def search_entity_udm_events(
        additional_udm_query: str,
        limit: int = 50,
    ) -> dict[str, Any]:
      """Executes a follow-up Chronicle UDM search and returns deduplicated timeline groups."""
      capped_limit = max(1, min(int(limit), 100))
      ep = f"search_udm:{additional_udm_query}:{capped_limit}"
      cached = tracker.get_cached(ep)
      if cached is not None:
        return cached
      if not tracker.try_acquire(ep):
        return {
            "budget_exhausted": True,
            "message": f"API call budget ({tracker.max_api_calls}) reached.",
        }
      resp = chronicle.search_udm(
          query=additional_udm_query,
          start_time=start_dt,
          end_time=end_dt,
          max_events=capped_limit,
      )
      norm = _normalize_search_udm_response(resp)
      compacted = rlm_engine.deduplicate_and_compact_udm_events(norm)
      tracker.store_response(ep, norm, compacted)
      return compacted

    effective_goal = investigation_goal or (
        f"Investigate entity {val_clean} in Chronicle SIEM, correlate its entity "
        "summary and alert counts with the UDM process/file/network timeline, and "
        "extract all verbatim file hashes, command lines, users, and IPs."
    )

    return await rlm_engine.distill_secops_udm_async(
        raw_payload=raw_envelope,
        entity_or_search_text=val_clean,
        tool_name="rlm_investigate_entity_timeline",
        query=effective_goal,
        udm_query=initial_udm_query,
        tools=[fetch_entity_summary, search_entity_udm_events],
        api_tracker=tracker,
    )
  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.error(
        "Error in rlm_investigate_entity_timeline: %s", exc, exc_info=True
    )
    return {
        "query_or_entity": entity_value,
        "error": str(exc),
    }
