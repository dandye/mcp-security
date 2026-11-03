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
"""DSPy 3.4+ RLM-powered network infrastructure (IP, domain, URL) tools for GTI MCP."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
from typing import Any, Optional

from mcp.server.fastmcp import Context

from .. import rlm_engine
from .. import utils
from ..server import server, vt_client
from .netloc import DOMAIN_RELATIONSHIPS, IP_RELATIONSHIPS
from .rlm_files import _safe_fetch_object_relationships
from .urls import URL_RELATIONSHIPS, url_to_base64

logger = logging.getLogger(__name__)

NETWORK_IOC_INITIAL_RELATIONSHIPS = {
    "ip_addresses": [
        "associations",
        "resolutions",
        "communicating_files",
        "downloaded_files",
        "urls",
    ],
    "domains": [
        "associations",
        "resolutions",
        "communicating_files",
        "downloaded_files",
        "urls",
        "subdomains",
    ],
    "urls": [
        "associations",
        "downloaded_files",
        "communicating_files",
        "contacted_domains",
        "contacted_ips",
        "last_serving_ip_address",
        "redirects_to",
    ],
}

_SHA256_URL_ID_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def detect_network_ioc_type(ioc: str, ioc_type: str = "auto") -> str:
  """Resolves 'auto' into 'ip_address', 'domain', or 'url'."""
  normalized = (ioc_type or "auto").strip().lower().replace("-", "_")
  if normalized in ("ip", "ip_address", "ip_addresses", "ipv4", "ipv6"):
    return "ip_address"
  if normalized in ("domain", "domains", "fqdn", "hostname"):
    return "domain"
  if normalized in ("url", "urls", "uri"):
    return "url"

  candidate = ioc.strip()
  if "://" in candidate or "/" in candidate or "?" in candidate:
    return "url"
  try:
    ipaddress.ip_address(candidate)
    return "ip_address"
  except ValueError:
    return "domain"


def _resolve_url_identifier(url_or_id: str) -> str:
  """Returns the VT URL identifier (base64 without padding or 64-hex SHA-256)."""
  stripped = url_or_id.strip()
  if _SHA256_URL_ID_RE.match(stripped):
    return stripped
  return url_to_base64(stripped)


def _compact_related_network_entities(
    items: Any, *, max_items: int = 15
) -> Any:
  """Compacts full related file/URL/resolution objects for REPL inspection."""
  if not isinstance(items, list):
    return items
  compacted: list[dict[str, Any]] = []
  for item in items[:max_items]:
    if not isinstance(item, dict):
      continue
    attrs = (
        item.get("attributes")
        if isinstance(item.get("attributes"), dict)
        else {}
    )
    ctx_attrs = (
        item.get("context_attributes")
        if isinstance(item.get("context_attributes"), dict)
        else {}
    )
    item_type = str(item.get("type") or "")
    entry: dict[str, Any] = {
        "id": item.get("id"),
        "type": item_type,
    }
    if item_type == "file":
      entry.update({
          "sha256": attrs.get("sha256") or item.get("id"),
          "md5": attrs.get("md5"),
          "meaningful_name": attrs.get("meaningful_name") or attrs.get("name"),
          "type_description": attrs.get("type_description"),
          "first_submission_date": attrs.get("first_submission_date"),
          "first_seen_itw_date": attrs.get("first_seen_itw_date"),
          "last_analysis_stats": attrs.get("last_analysis_stats"),
          "popular_threat_classification": attrs.get(
              "popular_threat_classification"
          ),
          "gti_assessment": attrs.get("gti_assessment"),
      })
    elif item_type == "url":
      raw_u = str(ctx_attrs.get("url") or attrs.get("url") or item.get("id") or "")
      if len(raw_u) > 200:
        raw_u = f"{raw_u[:180]}...[+{len(raw_u) - 180} chars]"
      raw_final_u = str(attrs.get("final_url") or "")
      if len(raw_final_u) > 200:
        raw_final_u = f"{raw_final_u[:180]}...[+{len(raw_final_u) - 180} chars]"
      entry.update({
          "url": raw_u,
          "final_url": raw_final_u or None,
          "last_http_response_code": attrs.get("last_http_response_code"),
          "last_http_response_content_sha256": attrs.get(
              "last_http_response_content_sha256"
          ),
          "last_modification_date": attrs.get("last_modification_date"),
          "last_analysis_stats": attrs.get("last_analysis_stats"),
          "categories": attrs.get("categories"),
          "gti_assessment": attrs.get("gti_assessment"),
      })
    elif item_type == "resolution":
      entry.update({
          "host_name": attrs.get("host_name"),
          "ip_address": attrs.get("ip_address"),
          "date": attrs.get("date"),
      })
    else:
      entry["attributes"] = {
          k: v
          for k, v in attrs.items()
          if k
          in (
              "name",
              "collection_type",
              "asn",
              "as_owner",
              "country",
              "last_analysis_stats",
              "gti_assessment",
              "reputation",
          )
      }
    compacted.append({k: v for k, v in entry.items() if v is not None})
  return compacted


@server.tool()
async def rlm_get_domain_report(
    domain: str,
    ctx: Context,
    query: Optional[str] = None,
) -> dict[str, Any]:
  """Get a high-signal DSPy RLM-distilled domain report (1 VT API call).

  Fetches the full unstripped VirusTotal/GTI domain report (including all vendor
  `last_analysis_results`, WHOIS/RDAP, DNS records, HTTPS certificate chain,
  JARM, popularity ranks, and key relationships) into a sandboxed Python REPL
  and distills it via `dspy.RLM`.

  Args:
    domain (required): Domain name to analyze.
    query (optional): Specific question or focus area to answer from the report.

  Returns:
    Structured dictionary with `verbatim_anchors` (including
    `network_infrastructure`), `verdict_and_summary`, `answer`, `key_findings`,
    `high_signal_iocs`, `attributions`, `mitre_techniques`,
    `filtered_noise_summary`, and `compression_metrics`.
  """
  async with vt_client(ctx) as client:
    raw_res = await utils.fetch_object(
        client,
        "domains",
        "domain",
        domain,
        relationships=NETWORK_IOC_INITIAL_RELATIONSHIPS["domains"],
    )
  sanitized = utils.sanitize_response(raw_res)
  if isinstance(sanitized, dict) and "error" in sanitized:
    return sanitized

  endpoint = f"/domains/{domain}"
  tracker = rlm_engine.APICallTracker(
      max_api_calls=1,
      initial_endpoint=endpoint,
      initial_bytes=len(json.dumps(sanitized, default=str).encode("utf-8")),
  )
  return await rlm_engine.distill_gti_payload_async(
      sanitized,
      entity_id=domain,
      tool_name="rlm_get_domain_report",
      query=query,
      default_objective=(
          "Summarize domain reputation, GTI assessment, registrar/WHOIS creation, "
          "DNS records, passive DNS resolutions, TLS certificate details, "
          "communicating/downloaded malware hashes, and threat attributions."
      ),
      tracker=tracker,
  )


@server.tool()
async def rlm_get_ip_address_report(
    ip_address: str,
    ctx: Context,
    query: Optional[str] = None,
) -> dict[str, Any]:
  """Get a high-signal DSPy RLM-distilled IP address report (1 VT API call).

  Fetches the full unstripped VirusTotal/GTI IP address report (including all
  vendor `last_analysis_results`, ASN/AS owner, RDAP/WHOIS, JARM, HTTPS
  certificate chain, and key relationships) into a sandboxed Python REPL and
  distills it via `dspy.RLM`.

  Args:
    ip_address (required): IPv4 or IPv6 address to analyze.
    query (optional): Specific question or focus area to answer from the report.

  Returns:
    Structured dictionary with `verbatim_anchors` (including
    `network_infrastructure`), `verdict_and_summary`, `answer`, `key_findings`,
    `high_signal_iocs`, `attributions`, `mitre_techniques`,
    `filtered_noise_summary`, and `compression_metrics`.
  """
  async with vt_client(ctx) as client:
    raw_res = await utils.fetch_object(
        client,
        "ip_addresses",
        "ip",
        ip_address,
        relationships=NETWORK_IOC_INITIAL_RELATIONSHIPS["ip_addresses"],
    )
  sanitized = utils.sanitize_response(raw_res)
  if isinstance(sanitized, dict) and "error" in sanitized:
    return sanitized

  endpoint = f"/ip_addresses/{ip_address}"
  tracker = rlm_engine.APICallTracker(
      max_api_calls=1,
      initial_endpoint=endpoint,
      initial_bytes=len(json.dumps(sanitized, default=str).encode("utf-8")),
  )
  return await rlm_engine.distill_gti_payload_async(
      sanitized,
      entity_id=ip_address,
      tool_name="rlm_get_ip_address_report",
      query=query,
      default_objective=(
          "Summarize IP address ASN/network ownership, vendor detection consensus, "
          "GTI assessment, JARM/TLS certificates, passive DNS resolutions, "
          "communicating/downloaded files, associated URLs, and attributions."
      ),
      tracker=tracker,
  )


@server.tool()
async def rlm_get_url_report(
    url: str,
    ctx: Context,
    query: Optional[str] = None,
) -> dict[str, Any]:
  """Get a high-signal DSPy RLM-distilled URL analysis report (1 VT API call).

  Fetches the full unstripped VirusTotal/GTI URL report (including all vendor
  scanner verdicts, HTTP response status code, body SHA-256, redirect chain,
  serving IP, and downloaded/communicating files) into a sandboxed Python REPL
  and distills it via `dspy.RLM`.

  Args:
    url (required): URL (or 64-hex VT URL ID) to analyze.
    query (optional): Specific question or focus area to answer from the report.

  Returns:
    Structured dictionary with `verbatim_anchors` (including
    `network_infrastructure`), `verdict_and_summary`, `answer`, `key_findings`,
    `high_signal_iocs`, `attributions`, `mitre_techniques`,
    `filtered_noise_summary`, and `compression_metrics`.
  """
  url_id = _resolve_url_identifier(url)
  async with vt_client(ctx) as client:
    raw_res = await utils.fetch_object(
        client,
        "urls",
        "url",
        url_id,
        relationships=NETWORK_IOC_INITIAL_RELATIONSHIPS["urls"],
    )
  sanitized = utils.sanitize_response(raw_res)
  if isinstance(sanitized, dict) and "error" in sanitized:
    return sanitized

  endpoint = f"/urls/{url_id}"
  tracker = rlm_engine.APICallTracker(
      max_api_calls=1,
      initial_endpoint=endpoint,
      initial_bytes=len(json.dumps(sanitized, default=str).encode("utf-8")),
  )
  return await rlm_engine.distill_gti_payload_async(
      sanitized,
      entity_id=url,
      tool_name="rlm_get_url_report",
      query=query,
      default_objective=(
          "Summarize URL scanner verdicts, HTTP status code, final redirect destination, "
          "serving IP address, downloaded payload hashes, and threat attributions."
      ),
      tracker=tracker,
  )


@server.tool()
async def rlm_investigate_network_ioc(
    ioc: str,
    ctx: Context,
    ioc_type: str = "auto",
    investigation_goal: Optional[str] = None,
    max_api_calls: int = 4,
) -> dict[str, Any]:
  """Autonomously investigate an IP address, domain, or URL across GTI endpoints inside a DSPy RLM REPL.

  Seeds the `dspy.RLM` Python REPL with the full unstripped primary report
  (`GET /ip_addresses/{ip}`, `GET /domains/{domain}`, or `GET /urls/{id}`) and
  binds budget-tracked relationship pivot tools inside the REPL without the
  legacy `descriptors_only=True` restriction so the RLM can inspect full
  communicating/downloaded malware files, passive DNS resolutions, and URLs:
    - `fetch_resolutions(limit=15)`
    - `fetch_communicating_files(limit=10)`
    - `fetch_downloaded_files(limit=10)`
    - `fetch_referrer_files(limit=10)`
    - `fetch_related_urls(limit=10)`
    - `fetch_collection_summary(collection_id)`

  Args:
    ioc (required): The IPv4/IPv6 address, domain name, or URL to investigate.
    ioc_type (optional): One of `'auto'`, `'ip_address'`, `'domain'`, or `'url'`.
      Defaults to `'auto'`.
    investigation_goal (optional): Specific investigation hypothesis or question.
    max_api_calls (optional): Maximum total VT API calls allowed across the
      investigation (clamped between 1 and 10; default 4).

  Returns:
    Structured intelligence dictionary combining infrastructure ownership,
    passive DNS history, communicating/downloaded malware hashes, related URLs,
    and threat attribution with full `compression_metrics`.
  """
  capped_calls = max(1, min(int(max_api_calls), 10))
  resolved_type = detect_network_ioc_type(ioc, ioc_type)
  if resolved_type == "ip_address":
    collection_name = "ip_addresses"
    object_label = "ip"
    resource_id = ioc.strip()
    valid_relationships = IP_RELATIONSHIPS
  elif resolved_type == "url":
    collection_name = "urls"
    object_label = "url"
    resource_id = _resolve_url_identifier(ioc)
    valid_relationships = URL_RELATIONSHIPS
  else:
    collection_name = "domains"
    object_label = "domain"
    resource_id = ioc.strip()
    valid_relationships = DOMAIN_RELATIONSHIPS

  loop = asyncio.get_running_loop()

  async with vt_client(ctx) as client:
    initial_raw = await utils.fetch_object(
        client,
        collection_name,
        object_label,
        resource_id,
        relationships=NETWORK_IOC_INITIAL_RELATIONSHIPS[collection_name],
    )
    sanitized_initial = utils.sanitize_response(initial_raw)
    if isinstance(sanitized_initial, dict) and "error" in sanitized_initial:
      return sanitized_initial

    initial_bytes = len(
        json.dumps(sanitized_initial, default=str).encode("utf-8")
    )
    tracker = rlm_engine.APICallTracker(
        max_api_calls=capped_calls,
        initial_endpoint=f"/{collection_name}/{resource_id}",
        initial_bytes=initial_bytes,
    )

    def _fetch_rel_compacted(
        rel_name: str, *, limit: int = 10
    ) -> Any:
      if rel_name not in valid_relationships:
        return {
            "error": (
                f"Relationship '{rel_name}' is not supported for {collection_name}. "
                f"Valid: {','.join(valid_relationships)}"
            )
        }
      endpoint = f"/{collection_name}/{resource_id}/{rel_name}"
      params = {"descriptors_only": False, "limit": limit}

      def _do_fetch() -> Any:
        coro = _safe_fetch_object_relationships(
            client,
            collection_name,
            resource_id,
            rel_name,
            descriptors_only=False,
            limit=limit,
        )
        fut = asyncio.run_coroutine_threadsafe(coro, loop)
        raw_items = fut.result(timeout=30.0)
        raw_len = len(json.dumps(raw_items, default=str).encode("utf-8"))
        compacted = _compact_related_network_entities(
            raw_items, max_items=limit
        )
        compacted_len = len(json.dumps(compacted, default=str).encode("utf-8"))
        if raw_len > compacted_len:
          tracker.total_raw_bytes += raw_len - compacted_len
        return compacted

      return tracker.call(endpoint, params, _do_fetch)

    def fetch_resolutions(limit: int = 15) -> Any:
      """Fetch passive DNS resolutions (`host_name`, `ip_address`, `date`) for this IP/domain."""
      if resolved_type == "url":
        return _fetch_rel_compacted("network_location", limit=limit)
      return _fetch_rel_compacted("resolutions", limit=limit)

    def fetch_communicating_files(limit: int = 10) -> Any:
      """Fetch full file reports (`sha256`, `md5`, `meaningful_name`, `last_analysis_stats`, `first_submission_date`) for files communicating with this IOC."""
      return _fetch_rel_compacted("communicating_files", limit=limit)

    def fetch_downloaded_files(limit: int = 10) -> Any:
      """Fetch full file reports for malware payloads downloaded from this IOC."""
      return _fetch_rel_compacted("downloaded_files", limit=limit)

    def fetch_referrer_files(limit: int = 10) -> Any:
      """Fetch full file reports for files containing/referring to this IOC."""
      return _fetch_rel_compacted("referrer_files", limit=limit)

    def fetch_related_urls(limit: int = 10) -> Any:
      """Fetch full URL scan objects (`url`, `last_http_response_code`, `last_analysis_stats`) associated with this IOC."""
      rel_target = "redirects_to" if resolved_type == "url" else "urls"
      return _fetch_rel_compacted(rel_target, limit=limit)

    def fetch_collection_summary(collection_id: str) -> dict[str, Any]:
      """Fetch `/collections/{collection_id}` report for an associated threat actor, malware family, or campaign."""
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
        fetch_resolutions,
        fetch_communicating_files,
        fetch_downloaded_files,
        fetch_referrer_files,
        fetch_related_urls,
        fetch_collection_summary,
    ]

    return await rlm_engine.distill_gti_payload_async(
        sanitized_initial,
        entity_id=ioc,
        tool_name="rlm_investigate_network_ioc",
        query=investigation_goal,
        default_objective=(
            f"Perform a comprehensive network infrastructure investigation on {resolved_type} '{ioc}': "
            "inspect ASN/WHOIS ownership, vendor verdicts, and embedded relationship descriptors first, "
            "then call `fetch_downloaded_files()`, `fetch_communicating_files()`, `fetch_resolutions()`, "
            "or `fetch_related_urls()` inside the REPL within the API call budget to identify "
            "associated malware hashes, payload staging URLs, passive DNS history, and threat actor attributions."
        ),
        extra_tools=bound_tools,
        tracker=tracker,
    )
