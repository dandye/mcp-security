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
"""DSPy 3.4+ Recursive Language Model (RLM) distillation engine for Chronicle SIEM UDM telemetry.

Provides a dual-layer compaction architecture for Google SecOps (Chronicle SIEM):
1. Verbatim Anchor Extraction (`extract_udm_verbatim_anchors`):
   Deterministic, zero-LLM extraction of exact UDM queries, event timestamps,
   hostnames, IPv4/IPv6 addresses, user IDs, cryptographic file digests
   (MD5, SHA-1, SHA-256) with file paths, and process command lines.
2. Deduplicated Kill-Chain Timeline & Sandboxed `dspy.RLM` Synthesis:
   Collapses repetitive OS/service background events (`svchost.exe`, `conhost.exe`,
   `MpCmdRun.exe`, duplicate auth/network heartbeats) into counted timeline groups
   and explores the UDM event set inside `SecOpsSandboxedInterpreter` using
   `vertex_ai/gemini-3.8-flash` (root) and `vertex_ai/gemini-3.5-flash-lite` (sub-LM),
   reducing 400 KB - 1.35 MB raw UDM event payloads by >95%.
"""

import asyncio
import inspect
import json
import logging
import os
import re
import threading
import time
from typing import Any, Callable, Optional

import dspy
from dspy.primitives.local_interpreter import LocalInterpreter

logger = logging.getLogger("secops-mcp.rlm")

DEFAULT_ROOT_LM_MODEL = "vertex_ai/gemini-3.8-flash"
DEFAULT_SUB_LM_MODEL = "vertex_ai/gemini-3.5-flash-lite"
DEFAULT_VERTEX_LOCATION = "global"

# Known repetitive Windows OS / background service binaries that generate high-volume
# UDM PROCESS_LAUNCH / FILE_CREATION clutter when no suspicious command-line flags exist.
BENIGN_UDM_BACKGROUND_PROCESS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\\windows\\system32\\svchost\.exe$", re.IGNORECASE),
    re.compile(r"\\windows\\system32\\conhost\.exe$", re.IGNORECASE),
    re.compile(r"\\windows\\system32\\backgroundtaskhost\.exe$", re.IGNORECASE),
    re.compile(r"\\windows\\system32\\searchprotocolhost\.exe$", re.IGNORECASE),
    re.compile(r"\\windows\\system32\\searchfilterhost\.exe$", re.IGNORECASE),
    re.compile(r"\\windows\\system32\\taskhostw\.exe$", re.IGNORECASE),
    re.compile(r"\\windows\\system32\\runtimebroker\.exe$", re.IGNORECASE),
    re.compile(r"\\windows\\system32\\dllhost\.exe$", re.IGNORECASE),
    re.compile(r"\\windows\\system32\\wbem\\wmiprvse\.exe$", re.IGNORECASE),
    re.compile(r"\\programdata\\microsoft\\windows defender\\.*\\mpcmdrun\.exe$", re.IGNORECASE),
    re.compile(r"\\programdata\\microsoft\\windows defender\\.*\\msmpeng\.exe$", re.IGNORECASE),
    re.compile(r"\\program files\\google\\compute engine\\.*$", re.IGNORECASE),
    re.compile(r"\\monitoring agent\\agent\\monitoringhost\.exe$", re.IGNORECASE),
)

# High-signal suspicious keywords in command lines or file paths that must NEVER
# be classified as background noise, even if launched via a system host process.
HIGH_SIGNAL_UDM_KEYWORDS: tuple[str, ...] = (
    "mimikatz",
    "mimilib",
    "sekurlsa",
    "lsadump",
    "privilege::debug",
    "ntds.dit",
    "diskshadow",
    "vssadmin",
    "shadowcopy",
    "wmic",
    "krbtgt",
    "procdump",
    "lsass",
    "comsvcs.dll",
    "minidump",
    "psexec",
    "bloodhound",
    "sharphound",
    "rubeus",
    "certutil",
    "bitsadmin",
    "reg.exe save",
    "sam ",
    "system ",
    "security ",
    "-enc",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex(",
    "c:\\temp\\",
    "\\appdata\\local\\temp\\",
)


def _pick(d: Any, *keys: str, default: Any = None) -> Any:
  """Retrieves the first present non-None key from a dict (camelCase or snake_case)."""
  if not isinstance(d, dict):
    return default
  for k in keys:
    val = d.get(k)
    if val is not None:
      return val
  return default


def _unwrap_udm_events(raw_payload: Any) -> tuple[list[dict[str, Any]], int]:
  """Extracts the list of UDM event dicts from a Chronicle search response."""
  if isinstance(raw_payload, list):
    events_raw = raw_payload
    reported_total = len(events_raw)
  elif isinstance(raw_payload, dict):
    inner = raw_payload.get("events")
    if isinstance(inner, dict) and "events" in inner:
      events_raw = inner.get("events") or []
      reported_total = int(inner.get("total_events") or len(events_raw))
    elif isinstance(inner, list):
      events_raw = inner
      reported_total = int(raw_payload.get("total_events") or len(events_raw))
    else:
      events_raw = []
      reported_total = int(raw_payload.get("total_events") or 0)
  else:
    events_raw = []
    reported_total = 0

  udm_list: list[dict[str, Any]] = []
  for item in events_raw:
    if not isinstance(item, dict):
      continue
    if isinstance(item.get("udm"), dict):
      udm_list.append(item["udm"])
    else:
      udm_list.append(item)
  return udm_list, reported_total


def _extract_ips_from_node(node: Any, out: set[str]) -> None:
  """Collects IP strings from a UDM entity node (`principal`, `target`, `src`, etc.)."""
  if not isinstance(node, dict):
    return
  for key in ("ip", "nat_ip", "natIp"):
    val = node.get(key)
    if isinstance(val, str) and val.strip():
      out.add(val.strip())
    elif isinstance(val, list):
      for item in val:
        if isinstance(item, str) and item.strip():
          out.add(item.strip())
  asset = node.get("asset")
  if isinstance(asset, dict):
    _extract_ips_from_node(asset, out)


def _extract_file_hash_entry(
    file_node: Any,
    role: str,
    by_digest_key: dict[str, dict[str, Any]],
) -> None:
  """Extracts verbatim MD5, SHA-1, and SHA-256 digests and fullPath from a UDM file node."""
  if not isinstance(file_node, dict):
    return
  md5 = str(file_node.get("md5") or "").strip().lower()
  sha1 = str(file_node.get("sha1") or "").strip().lower()
  sha256 = str(file_node.get("sha256") or "").strip().lower()
  full_path = str(_pick(file_node, "fullPath", "full_path", default="") or "").strip()
  if not (md5 or sha1 or sha256):
    return
  digest_key = sha256 or md5 or sha1
  entry = by_digest_key.get(digest_key)
  if entry is None:
    entry = {
        "md5": md5 or None,
        "sha1": sha1 or None,
        "sha256": sha256 or None,
        "full_path": full_path or None,
        "roles": [role],
        "occurrence_count": 1,
    }
    by_digest_key[digest_key] = entry
  else:
    entry["occurrence_count"] = int(entry.get("occurrence_count", 1)) + 1
    if not entry.get("md5") and md5:
      entry["md5"] = md5
    if not entry.get("sha1") and sha1:
      entry["sha1"] = sha1
    if not entry.get("sha256") and sha256:
      entry["sha256"] = sha256
    if not entry.get("full_path") and full_path:
      entry["full_path"] = full_path
    if role not in entry["roles"]:
      entry["roles"].append(role)


def extract_udm_verbatim_anchors(
    raw_payload: Any,
    udm_query: Optional[str] = None,
) -> dict[str, Any]:
  """Deterministically extracts 100% verbatim forensic anchors from raw Chronicle UDM events.

  Guarantees that cryptographic hashes (MD5, SHA-1, SHA-256), hostnames, IP
  addresses, user accounts, process command lines, and event timestamps are
  never altered or hallucinated by an LLM.
  """
  udm_events, reported_total = _unwrap_udm_events(raw_payload)
  if udm_query is None and isinstance(raw_payload, dict):
    udm_query = raw_payload.get("udm_query")

  timestamps: list[str] = []
  event_type_counts: dict[str, int] = {}
  hostnames: set[str] = set()
  ip_addresses: set[str] = set()
  users: set[str] = set()
  command_lines: list[str] = []
  seen_cmdlines: set[str] = set()
  security_results: list[str] = []
  seen_sec_results: set[str] = set()
  sample_event_ids: list[str] = []
  hashes_by_key: dict[str, dict[str, Any]] = {}

  for udm in udm_events:
    meta = udm.get("metadata") or {}
    ev_id = str(meta.get("id") or "").strip()
    if ev_id and len(sample_event_ids) < 25 and ev_id not in sample_event_ids:
      sample_event_ids.append(ev_id)

    ts = str(_pick(meta, "eventTimestamp", "event_timestamp", default="") or "").strip()
    if ts:
      timestamps.append(ts)

    ev_type = str(_pick(meta, "eventType", "event_type", default="UNKNOWN") or "UNKNOWN")
    event_type_counts[ev_type] = event_type_counts.get(ev_type, 0) + 1

    for role_name in ("principal", "target", "src", "observer", "intermediary"):
      node = udm.get(role_name)
      if not isinstance(node, dict):
        continue
      hostname = str(
          node.get("hostname")
          or _pick(node.get("asset"), "hostname", default="")
          or ""
      ).strip()
      if hostname:
        hostnames.add(hostname)

      _extract_ips_from_node(node, ip_addresses)

      user_node = node.get("user")
      if isinstance(user_node, dict):
        uid = str(
            _pick(
                user_node,
                "userid",
                "userDisplayName",
                "user_display_name",
                default="",
            )
            or ""
        ).strip()
        if uid and not uid.endswith("$"):
          users.add(uid)

      proc_node = node.get("process")
      if isinstance(proc_node, dict):
        cmdline = str(_pick(proc_node, "commandLine", "command_line", default="") or "").strip()
        if cmdline and cmdline not in seen_cmdlines:
          seen_cmdlines.add(cmdline)
          command_lines.append(cmdline)
        _extract_file_hash_entry(
            proc_node.get("file"), f"{role_name}.process.file", hashes_by_key
        )
        parent_proc = _pick(proc_node, "parentProcess", "parent_process")
        if isinstance(parent_proc, dict):
          parent_cmd = str(
              _pick(parent_proc, "commandLine", "command_line", default="") or ""
          ).strip()
          if parent_cmd and parent_cmd not in seen_cmdlines:
            seen_cmdlines.add(parent_cmd)
            command_lines.append(parent_cmd)
          _extract_file_hash_entry(
              parent_proc.get("file"),
              f"{role_name}.process.parent_process.file",
              hashes_by_key,
          )

      _extract_file_hash_entry(
          node.get("file"), f"{role_name}.file", hashes_by_key
      )

    sec_res = _pick(udm, "securityResult", "security_result")
    sec_list = sec_res if isinstance(sec_res, list) else ([sec_res] if isinstance(sec_res, dict) else [])
    for sr in sec_list:
      if not isinstance(sr, dict):
        continue
      summary = str(
          _pick(sr, "summary", "ruleName", "rule_name", "description", default="") or ""
      ).strip()
      if summary and summary not in seen_sec_results:
        seen_sec_results.add(summary)
        security_results.append(summary)

  timestamps_sorted = sorted(timestamps)
  time_window = {
      "earliest_timestamp": timestamps_sorted[0] if timestamps_sorted else None,
      "latest_timestamp": timestamps_sorted[-1] if timestamps_sorted else None,
  }

  return {
      "udm_query": udm_query,
      "total_raw_events": len(udm_events),
      "reported_total_events": reported_total,
      "time_window": time_window,
      "event_type_counts": event_type_counts,
      "hostnames": sorted(hostnames),
      "ip_addresses": sorted(ip_addresses),
      "users": sorted(users),
      "file_hashes": list(hashes_by_key.values()),
      "command_lines": command_lines[:60],
      "security_results": security_results[:30],
      "sample_event_ids": sample_event_ids,
  }


def is_benign_udm_background_event(compact_ev: dict[str, Any]) -> bool:
  """Returns True if a UDM event is routine Windows OS background activity without suspicious indicators."""
  cmdline = (
      f"{compact_ev.get('target_cmdline') or ''} "
      f"{compact_ev.get('parent_cmdline') or ''} "
      f"{compact_ev.get('target_file_path') or ''}"
  ).lower()
  if any(kw in cmdline for kw in HIGH_SIGNAL_UDM_KEYWORDS):
    return False
  target_proc = str(compact_ev.get("target_process") or "")
  if any(p.search(target_proc) for p in BENIGN_UDM_BACKGROUND_PROCESS_PATTERNS):
    return True
  return False


def normalize_single_udm_event(udm: dict[str, Any]) -> dict[str, Any]:
  """Projects a deeply nested 8 KB Chronicle UDM event into a compact canonical record."""
  meta = udm.get("metadata") or {}
  principal = udm.get("principal") or {}
  target = udm.get("target") or {}
  network = udm.get("network") or {}

  p_proc = principal.get("process") or {}
  p_file = (p_proc.get("file") if isinstance(p_proc, dict) else None) or {}
  t_proc = target.get("process") or {}
  t_proc_file = (t_proc.get("file") if isinstance(t_proc, dict) else None) or {}
  t_file = target.get("file") or {}

  p_ips: set[str] = set()
  t_ips: set[str] = set()
  _extract_ips_from_node(principal, p_ips)
  _extract_ips_from_node(target, t_ips)

  user_id = (
      _pick(principal.get("user"), "userid", "userDisplayName", "user_display_name")
      or _pick(target.get("user"), "userid", "userDisplayName", "user_display_name")
  )

  sec_res = _pick(udm, "securityResult", "security_result")
  sec_summary = None
  if isinstance(sec_res, list) and sec_res and isinstance(sec_res[0], dict):
    sec_summary = _pick(sec_res[0], "summary", "ruleName", "rule_name")
  elif isinstance(sec_res, dict):
    sec_summary = _pick(sec_res, "summary", "ruleName", "rule_name")

  dns_q = None
  dns_node = network.get("dns") if isinstance(network, dict) else None
  if isinstance(dns_node, dict):
    questions = dns_node.get("questions")
    if isinstance(questions, list) and questions and isinstance(questions[0], dict):
      dns_q = questions[0].get("name")

  record: dict[str, Any] = {
      "event_id": meta.get("id"),
      "timestamp": _pick(meta, "eventTimestamp", "event_timestamp"),
      "event_type": _pick(meta, "eventType", "event_type"),
      "product_event_type": _pick(meta, "productEventType", "product_event_type"),
      "hostname": principal.get("hostname") or target.get("hostname"),
      "principal_ip": sorted(p_ips)[0] if p_ips else None,
      "target_ip": sorted(t_ips)[0] if t_ips else None,
      "user": user_id,
      "parent_process": _pick(p_file, "fullPath", "full_path"),
      "parent_cmdline": _pick(p_proc, "commandLine", "command_line"),
      "target_process": _pick(t_proc_file, "fullPath", "full_path"),
      "target_cmdline": _pick(t_proc, "commandLine", "command_line"),
      "target_process_md5": t_proc_file.get("md5"),
      "target_process_sha256": t_proc_file.get("sha256"),
      "target_file_path": _pick(t_file, "fullPath", "full_path"),
      "target_file_md5": t_file.get("md5"),
      "target_file_sha256": t_file.get("sha256"),
      "target_url": target.get("url"),
      "dns_question": dns_q,
      "security_summary": sec_summary,
  }
  return {k: v for k, v in record.items() if v is not None and v != ""}


def deduplicate_and_compact_udm_events(
    raw_payload: Any,
    max_unique_groups: int = 40,
) -> dict[str, Any]:
  """Deduplicates and compacts raw UDM events into high-signal timeline groups and noise counts."""
  udm_events, reported_total = _unwrap_udm_events(raw_payload)
  groups: dict[tuple[Any, ...], dict[str, Any]] = {}
  background_noise_counts: dict[str, int] = {}
  background_events_collapsed = 0

  for udm in udm_events:
    rec = normalize_single_udm_event(udm)
    if is_benign_udm_background_event(rec):
      background_events_collapsed += 1
      proc_label = str(rec.get("target_process") or rec.get("event_type") or "background")
      background_noise_counts[proc_label] = background_noise_counts.get(proc_label, 0) + 1
      continue

    group_key = (
        rec.get("event_type"),
        rec.get("product_event_type"),
        rec.get("hostname"),
        rec.get("user"),
        rec.get("parent_process"),
        rec.get("parent_cmdline"),
        rec.get("target_process"),
        rec.get("target_cmdline"),
        rec.get("target_process_md5"),
        rec.get("target_file_path"),
        rec.get("target_file_md5"),
        rec.get("principal_ip"),
        rec.get("target_ip"),
        rec.get("target_url"),
        rec.get("dns_question"),
        rec.get("security_summary"),
    )
    ts = str(rec.get("timestamp") or "")
    existing = groups.get(group_key)
    if existing is None:
      entry = dict(rec)
      ev_id = entry.pop("event_id", None)
      entry.pop("timestamp", None)
      entry["first_seen"] = ts or None
      entry["last_seen"] = ts or None
      entry["occurrence_count"] = 1
      if ev_id:
        entry["sample_event_id"] = ev_id
      groups[group_key] = entry
    else:
      existing["occurrence_count"] = int(existing.get("occurrence_count", 1)) + 1
      if ts:
        if not existing.get("first_seen") or ts < existing["first_seen"]:
          existing["first_seen"] = ts
        if not existing.get("last_seen") or ts > existing["last_seen"]:
          existing["last_seen"] = ts

  sorted_timeline = sorted(
      groups.values(),
      key=lambda item: str(item.get("first_seen") or ""),
  )

  return {
      "raw_event_count": len(udm_events),
      "reported_total_events": reported_total,
      "unique_signal_groups": len(sorted_timeline),
      "background_events_collapsed": background_events_collapsed,
      "background_noise_counts": background_noise_counts,
      "timeline": sorted_timeline[:max_unique_groups],
  }


def build_udm_payload_index(
    raw_payload: Any,
    udm_query: Optional[str] = None,
) -> dict[str, Any]:
  """Builds a structural index of a raw Chronicle UDM payload for the RLM REPL."""
  anchors = extract_udm_verbatim_anchors(raw_payload, udm_query=udm_query)
  compacted = deduplicate_and_compact_udm_events(raw_payload)
  return {
      "udm_query": anchors["udm_query"],
      "total_raw_events": anchors["total_raw_events"],
      "reported_total_events": anchors["reported_total_events"],
      "time_window": anchors["time_window"],
      "event_type_counts": anchors["event_type_counts"],
      "unique_signal_groups": compacted["unique_signal_groups"],
      "background_events_collapsed": compacted["background_events_collapsed"],
      "background_noise_counts": compacted["background_noise_counts"],
      "hostnames": anchors["hostnames"],
      "ip_addresses": anchors["ip_addresses"],
      "users": anchors["users"],
      "file_hashes_count": len(anchors["file_hashes"]),
      "command_lines_count": len(anchors["command_lines"]),
  }


class APICallTracker:
  """Thread-safe tracker enforcing a strict Chronicle API call budget inside RLM tools."""

  def __init__(self, max_api_calls: int = 4) -> None:
    self.max_api_calls = max(1, int(max_api_calls))
    self.calls_made = 0
    self.endpoints_called: list[str] = []
    self.raw_bytes_fetched = 0
    self._cache: dict[str, Any] = {}
    self._lock = threading.Lock()

  def record_initial(self, endpoint: str, payload: Any) -> None:
    with self._lock:
      self.calls_made += 1
      self.endpoints_called.append(endpoint)
      self.raw_bytes_fetched += len(json.dumps(payload, default=str).encode("utf-8"))
      self._cache[endpoint] = payload

  def get_cached(self, endpoint: str) -> Any:
    with self._lock:
      return self._cache.get(endpoint)

  def try_acquire(self, endpoint: str) -> bool:
    with self._lock:
      if endpoint in self._cache:
        return True
      if self.calls_made >= self.max_api_calls:
        return False
      self.calls_made += 1
      self.endpoints_called.append(endpoint)
      return True

  def store_response(self, endpoint: str, raw_payload: Any, compact_result: Any) -> None:
    with self._lock:
      self.raw_bytes_fetched += len(json.dumps(raw_payload, default=str).encode("utf-8"))
      self._cache[endpoint] = compact_result


class SecOpsSandboxedInterpreter(LocalInterpreter):
  """Sandboxed DSPy LocalInterpreter tailored for Chronicle SIEM UDM telemetry."""

  _LARGE_CACHEABLE_VARS = ("raw_events", "udm_index", "compact_timeline")

  def __init__(
      self,
      *args: Any,
      min_sub_lm_prompt_chars: int = 40,
      **kwargs: Any,
  ) -> None:
    super().__init__(*args, **kwargs)
    self.user_turn_count = 0
    self.min_sub_lm_prompt_chars = min_sub_lm_prompt_chars
    self._injected_large_vars: set[str] = set()

  def execute(
      self,
      code: str,
      variables: Optional[dict[str, Any]] = None,
  ) -> Any:
    if variables and "__dspy_host_token" in variables:
      return super().execute(code, variables)

    self.user_turn_count += 1
    if variables:
      filtered_vars: dict[str, Any] = {}
      for k, v in variables.items():
        if k in self._LARGE_CACHEABLE_VARS:
          if k not in self._injected_large_vars:
            filtered_vars[k] = v
            self._injected_large_vars.add(k)
        else:
          filtered_vars[k] = v
      variables = filtered_vars

    return super().execute(code, variables)

  def invoke_tool(
      self,
      name: str,
      args: tuple[Any, ...],
      kwargs: dict[str, Any],
  ) -> Any:
    if name in ("llm_query", "llm_query_batched") and self.min_sub_lm_prompt_chars > 0:
      prompts = self._extract_prompts(name, args, kwargs)
      for p in prompts:
        if len(str(p).strip()) < self.min_sub_lm_prompt_chars:
          raise ValueError(
              f"{name} requires a grounded UDM data slice (>= {self.min_sub_lm_prompt_chars} "
              "characters) embedded in the prompt because the sub-LM is stateless."
          )

    fn = self.tools.get(name)
    if fn is not None and args and hasattr(fn, "__wrapped__"):
      sig = getattr(fn, "__signature__", None) or inspect.signature(fn.__wrapped__)
      bound = sig.bind(*args, **kwargs)
      bound.apply_defaults()
      return super().invoke_tool(name, (), dict(bound.arguments))

    return super().invoke_tool(name, args, kwargs)

  @staticmethod
  def _extract_prompts(
      name: str,
      args: tuple[Any, ...],
      kwargs: dict[str, Any],
  ) -> list[str]:
    if name == "llm_query":
      prompt = args[0] if args else kwargs.get("prompt", "")
      return [str(prompt)]
    prompts = args[0] if args else kwargs.get("prompts", [])
    if isinstance(prompts, list):
      return [str(p) for p in prompts]
    return [str(prompts)]


class SecOpsUDMDistillSignature(dspy.Signature):
  """Explore Chronicle SIEM UDM telemetry in the Python REPL and distill high-signal attack timelines.

  Instructions for the Python REPL:
  1. `udm_index` and `compact_timeline` already contain the deduplicated UDM timeline groups, event type counts, hostnames, IPs, users, and collapsed background noise counts. Do NOT waste turns printing `udm_index` or `raw_events`.
  2. On Turn 0, write a single Python snippet that inspects `compact_timeline["timeline"]` (and calls bound pivot tools like `fetch_entity_summary` or `search_entity_udm_events` if needed) and calls `SUBMIT(...)` immediately on Turn 0 or Turn 1.
  3. Keep `kill_chain_timeline` concise (at most 8-12 key high-signal attack steps; omit benign OS background processes). Never fabricate or alter cryptographic hashes, hostnames, IP addresses, or command lines.
  """

  entity_or_search_text: str = dspy.InputField(
      desc="Natural-language search query, UDM query, or entity value being investigated."
  )
  tool_name: str = dspy.InputField(
      desc="Name of the SecOps MCP RLM tool (`rlm_search_security_events` or `rlm_investigate_entity_timeline`)."
  )
  query: str = dspy.InputField(
      desc="Specific analytical or threat-hunting question to answer from the UDM events."
  )
  udm_index: dict[str, Any] = dspy.InputField(
      desc="Pre-computed UDM event summary index (counts, hosts, IPs, users, noise stats)."
  )
  compact_timeline: dict[str, Any] = dspy.InputField(
      desc="Deduplicated high-signal UDM event groups ordered chronologically."
  )
  raw_events: list[dict[str, Any]] = dspy.InputField(
      desc="Normalized list of UDM event records for on-demand REPL slicing."
  )

  verdict_and_summary: str = dspy.OutputField(
      desc="Concise 1-3 sentence executive summary of the SIEM UDM activity and severity."
  )
  answer: str = dspy.OutputField(
      desc="Direct, evidence-backed answer to `query` citing exact timestamps, command lines, hosts, users, IPs, and hashes."
  )
  kill_chain_timeline: list[dict[str, Any]] = dspy.OutputField(
      desc="Chronological list of high-signal attack stages (`timestamp`, `stage`, `event_type`, `hostname`, `user`, `command_line_or_file`, `hashes`, `mitre_technique`)."
  )
  high_signal_iocs: dict[str, list[str]] = dspy.OutputField(
      desc="Categorized IOCs extracted from UDM telemetry with keys: `hostnames`, `ip_addresses`, `users`, `file_hashes`, `process_command_lines`, `files_created_or_modified`."
  )
  mitre_techniques: list[dict[str, str]] = dspy.OutputField(
      desc="List of observed MITRE ATT&CK techniques (`id`, `name`, `evidence`)."
  )
  filtered_noise_summary: str = dspy.OutputField(
      desc="Summary of repetitive or benign background UDM events collapsed during compaction."
  )


def configure_secops_rlm_lms(
    lm: Optional[dspy.LM] = None,
    sub_lm: Optional[dspy.LM] = None,
) -> tuple[Optional[dspy.LM], Optional[dspy.LM]]:
  """Configures the root and sub-LM instances on Vertex AI (`global`) for SecOps RLM."""
  if lm is not None and sub_lm is not None:
    return lm, sub_lm

  if os.getenv("SECOPS_RLM_DISABLE_LLM", "").lower() in ("1", "true", "yes"):
    return None, None

  root_model = (
      os.getenv("SECOPS_RLM_MODEL")
      or os.getenv("GTI_RLM_MODEL")
      or DEFAULT_ROOT_LM_MODEL
  )
  sub_model = (
      os.getenv("SECOPS_RLM_SUB_MODEL")
      or os.getenv("GTI_RLM_SUB_MODEL")
      or DEFAULT_SUB_LM_MODEL
  )
  vertex_location = (
      os.getenv("SECOPS_RLM_VERTEX_LOCATION")
      or os.getenv("GTI_RLM_VERTEX_LOCATION")
      or os.getenv("VERTEXAI_LOCATION")
      or DEFAULT_VERTEX_LOCATION
  )

  try:
    resolved_lm = lm or dspy.LM(
        root_model,
        vertex_location=vertex_location,
        max_tokens=16384,
        reasoning_effort="low",
        cache=False,
    )
    resolved_sub_lm = sub_lm or dspy.LM(
        sub_model,
        vertex_location=vertex_location,
        max_tokens=8192,
        reasoning_effort="low",
        cache=False,
    )
    return resolved_lm, resolved_sub_lm
  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.warning("Falling back to deterministic UDM distillation: %s", exc)
    return None, None


def _infer_mitre_techniques_from_udm(
    anchors: dict[str, Any],
    timeline: list[dict[str, Any]],
) -> list[dict[str, str]]:
  """Infers high-confidence MITRE ATT&CK techniques from UDM command lines and events."""
  techniques: list[dict[str, str]] = []
  seen_ids: set[str] = set()
  cmd_blob = "\n".join(anchors.get("command_lines") or [])
  cmd_lower = cmd_blob.lower()

  rules: list[tuple[str, str, tuple[str, ...]]] = [
      ("T1003.001", "OS Credential Dumping: LSASS Memory", ("sekurlsa", "mimikatz", "lsass", "comsvcs.dll")),
      ("T1003.003", "OS Credential Dumping: NTDS", ("ntds.dit", "diskshadow")),
      ("T1047", "Windows Management Instrumentation", ("wmic ", "wmic.exe")),
      ("T1490", "Inhibit System Recovery / Shadow Copy Access", ("vssadmin", "shadowcopy")),
      ("T1059.001", "Command and Scripting Interpreter: PowerShell", ("powershell", "-enc", "invoke-expression")),
      ("T1059.003", "Windows Command Shell", ("cmd /c", "cmd.exe /c")),
      ("T1110.001", "Brute Force: Password Guessing", ("repeatedauthfailure", "4625")),
  ]
  for tid, tname, needles in rules:
    for needle in needles:
      if needle in cmd_lower and tid not in seen_ids:
        seen_ids.add(tid)
        evidence_line = next(
            (c for c in (anchors.get("command_lines") or []) if needle in c.lower()),
            needle,
        )
        techniques.append({"id": tid, "name": tname, "evidence": evidence_line})
        break

  for item in timeline:
    ev_type = str(item.get("event_type") or "")
    if ev_type == "USER_LOGIN" and "T1078" not in seen_ids:
      seen_ids.add("T1078")
      techniques.append({
          "id": "T1078",
          "name": "Valid Accounts",
          "evidence": f"USER_LOGIN user={item.get('user')} src_ip={item.get('principal_ip')}",
      })
  return techniques


def deterministic_distill_udm(
    raw_payload: Any,
    entity_or_search_text: str,
    tool_name: str,
    query: str,
    udm_query: Optional[str] = None,
    extra_context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
  """Deterministically distills raw Chronicle UDM events into a compact forensic bundle."""
  raw_bytes = len(json.dumps(raw_payload, default=str).encode("utf-8"))
  anchors = extract_udm_verbatim_anchors(raw_payload, udm_query=udm_query)
  compacted = deduplicate_and_compact_udm_events(raw_payload)
  timeline = compacted["timeline"]
  mitre = _infer_mitre_techniques_from_udm(anchors, timeline)

  kill_chain_timeline: list[dict[str, Any]] = []
  for idx, ev in enumerate(timeline[:25], 1):
    hashes = [
        h
        for h in (
            ev.get("target_process_md5"),
            ev.get("target_process_sha256"),
            ev.get("target_file_md5"),
            ev.get("target_file_sha256"),
        )
        if h
    ]
    kill_chain_timeline.append({
        "step": idx,
        "first_seen": ev.get("first_seen"),
        "last_seen": ev.get("last_seen"),
        "occurrence_count": ev.get("occurrence_count", 1),
        "event_type": ev.get("event_type"),
        "product_event_type": ev.get("product_event_type"),
        "hostname": ev.get("hostname"),
        "user": ev.get("user"),
        "principal_ip": ev.get("principal_ip"),
        "target_ip": ev.get("target_ip"),
        "parent_process": ev.get("parent_process"),
        "parent_cmdline": ev.get("parent_cmdline"),
        "target_process": ev.get("target_process"),
        "target_cmdline": ev.get("target_cmdline"),
        "target_file_path": ev.get("target_file_path"),
        "hashes": hashes,
    })

  hash_strings = [
      f"{h.get('md5') or h.get('sha256')} ({h.get('full_path') or 'unknown'})"
      for h in anchors["file_hashes"]
  ]
  files_created = [
      str(ev.get("target_file_path"))
      for ev in timeline
      if ev.get("target_file_path")
  ]

  verdict_summary = (
      f"Distilled {anchors['total_raw_events']} raw Chronicle UDM events "
      f"({compacted['unique_signal_groups']} unique signal groups, "
      f"{compacted['background_events_collapsed']} background events collapsed) "
      f"across hosts {anchors['hostnames']} and users {anchors['users']}."
  )
  answer_lines = [
      f"UDM Query: {anchors['udm_query']}",
      f"Time Window: {anchors['time_window']['earliest_timestamp']} to {anchors['time_window']['latest_timestamp']}",
      f"Hosts: {', '.join(anchors['hostnames'])} | IPs: {', '.join(anchors['ip_addresses'])} | Users: {', '.join(anchors['users'])}",
      f"Observed {len(anchors['file_hashes'])} unique file hashes and {len(anchors['command_lines'])} distinct command lines.",
  ]
  for cmd in anchors["command_lines"][:10]:
    answer_lines.append(f"- Command: {cmd}")

  result: dict[str, Any] = {
      "query_or_entity": entity_or_search_text,
      "tool": tool_name,
      "query": query,
      "udm_query": anchors["udm_query"],
      "verdict_and_summary": verdict_summary,
      "answer": "\n".join(answer_lines),
      "verbatim_anchors": anchors,
      "kill_chain_timeline": kill_chain_timeline,
      "high_signal_iocs": {
          "hostnames": anchors["hostnames"],
          "ip_addresses": anchors["ip_addresses"],
          "users": anchors["users"],
          "file_hashes": hash_strings,
          "process_command_lines": anchors["command_lines"],
          "files_created_or_modified": sorted(set(files_created)),
      },
      "mitre_techniques": mitre,
      "filtered_noise_summary": (
          f"Collapsed {compacted['background_events_collapsed']} routine background "
          f"OS events and deduplicated {anchors['total_raw_events']} raw events into "
          f"{compacted['unique_signal_groups']} chronological timeline groups."
      ),
  }
  if extra_context:
    result["pivoted_context"] = extra_context

  distilled_bytes = len(json.dumps(result, default=str).encode("utf-8"))
  reduction_pct = (
      round((1.0 - (distilled_bytes / raw_bytes)) * 100.0, 2)
      if raw_bytes > 0
      else 0.0
  )
  result["compression_metrics"] = {
      "raw_bytes": raw_bytes,
      "distilled_bytes": distilled_bytes,
      "reduction_pct": reduction_pct,
      "raw_event_count": anchors["total_raw_events"],
      "deduplicated_group_count": compacted["unique_signal_groups"],
      "background_events_collapsed": compacted["background_events_collapsed"],
      "distillation_mode": "deterministic_fallback",
      "api_calls_made": 1,
      "endpoints_called": ["search_udm"],
  }
  return result


def distill_secops_udm(
    raw_payload: Any,
    entity_or_search_text: str,
    tool_name: str,
    query: str,
    udm_query: Optional[str] = None,
    tools: Optional[list[Callable[..., Any]]] = None,
    api_tracker: Optional[APICallTracker] = None,
    lm: Optional[dspy.LM] = None,
    sub_lm: Optional[dspy.LM] = None,
    max_iters: int = 2,
    max_llm_calls: int = 4,
) -> dict[str, Any]:
  """Runs `dspy.RLM` over Chronicle SIEM UDM telemetry and merges verbatim anchors."""
  t0 = time.monotonic()
  baseline = deterministic_distill_udm(
      raw_payload=raw_payload,
      entity_or_search_text=entity_or_search_text,
      tool_name=tool_name,
      query=query,
      udm_query=udm_query,
  )

  resolved_lm, resolved_sub_lm = configure_secops_rlm_lms(lm=lm, sub_lm=sub_lm)
  if resolved_lm is None:
    baseline["compression_metrics"]["elapsed_seconds"] = round(
        time.monotonic() - t0, 2
    )
    return baseline

  udm_index = build_udm_payload_index(raw_payload, udm_query=udm_query)
  compacted = deduplicate_and_compact_udm_events(raw_payload)
  udm_events_raw, _ = _unwrap_udm_events(raw_payload)
  normalized_events = [normalize_single_udm_event(e) for e in udm_events_raw[:150]]

  def filter_events_by_type(event_type: str) -> list[dict[str, Any]]:
    """Returns deduplicated UDM timeline entries matching `event_type` (case-insensitive)."""
    target = str(event_type).strip().upper()
    return [
        ev
        for ev in compacted["timeline"]
        if str(ev.get("event_type") or "").upper() == target
    ]

  def search_events_regex(pattern: str) -> list[dict[str, Any]]:
    """Searches deduplicated UDM timeline entries for a regex pattern across all fields."""
    rx = re.compile(pattern, re.IGNORECASE)
    return [
        ev
        for ev in compacted["timeline"]
        if rx.search(json.dumps(ev, default=str))
    ]

  def get_process_tree() -> list[dict[str, Any]]:
    """Returns chronological process launch events with parent/target command lines and hashes."""
    return [
        ev
        for ev in compacted["timeline"]
        if ev.get("target_process") or ev.get("target_cmdline")
    ]

  def get_file_artifacts() -> list[dict[str, Any]]:
    """Returns verbatim file hashes and file creation/modification paths from UDM events."""
    return baseline["verbatim_anchors"]["file_hashes"]

  all_tools: list[Callable[..., Any]] = [
      filter_events_by_type,
      search_events_regex,
      get_process_tree,
      get_file_artifacts,
  ]
  if tools:
    all_tools.extend(tools)

  try:
    rlm = dspy.RLM(
        SecOpsUDMDistillSignature,
        max_iters=max_iters,
        max_llm_calls=max_llm_calls,
        max_output_chars=12000,
        sub_lm=resolved_sub_lm,
        tools=all_tools,
        interpreter_factory=lambda: SecOpsSandboxedInterpreter(),
    )
    with dspy.context(lm=resolved_lm):
      pred = rlm(
          entity_or_search_text=entity_or_search_text,
          tool_name=tool_name,
          query=query,
          udm_index=udm_index,
          compact_timeline=compacted,
          raw_events=normalized_events,
      )

    verdict = str(getattr(pred, "verdict_and_summary", "") or "").strip()
    answer = str(getattr(pred, "answer", "") or "").strip()
    if verdict:
      baseline["verdict_and_summary"] = verdict
    if answer:
      baseline["answer"] = answer

    pred_timeline = getattr(pred, "kill_chain_timeline", None)
    if isinstance(pred_timeline, list) and pred_timeline:
      baseline["kill_chain_timeline"] = pred_timeline[:12]

    pred_mitre = getattr(pred, "mitre_techniques", None)
    if isinstance(pred_mitre, list) and pred_mitre:
      existing_ids = {m.get("id") for m in baseline["mitre_techniques"] if isinstance(m, dict)}
      for m in pred_mitre:
        if isinstance(m, dict) and m.get("id") not in existing_ids:
          baseline["mitre_techniques"].append(m)

    pred_noise = str(getattr(pred, "filtered_noise_summary", "") or "").strip()
    if pred_noise:
      baseline["filtered_noise_summary"] = pred_noise

    distillation_mode = "dspy_rlm"
  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.warning("dspy.RLM UDM execution failed; using deterministic distillation: %s", exc)
    distillation_mode = "deterministic_fallback"

  raw_bytes = (
      api_tracker.raw_bytes_fetched
      if api_tracker and api_tracker.raw_bytes_fetched > 0
      else baseline["compression_metrics"]["raw_bytes"]
  )
  distilled_bytes = len(json.dumps(baseline, default=str).encode("utf-8"))
  reduction_pct = (
      round((1.0 - (distilled_bytes / raw_bytes)) * 100.0, 2)
      if raw_bytes > 0
      else 0.0
  )
  baseline["compression_metrics"].update({
      "raw_bytes": raw_bytes,
      "distilled_bytes": distilled_bytes,
      "reduction_pct": reduction_pct,
      "distillation_mode": distillation_mode,
      "api_calls_made": api_tracker.calls_made if api_tracker else 1,
      "endpoints_called": (
          api_tracker.endpoints_called if api_tracker else ["search_udm"]
      ),
      "elapsed_seconds": round(time.monotonic() - t0, 2),
  })
  return baseline


async def distill_secops_udm_async(
    raw_payload: Any,
    entity_or_search_text: str,
    tool_name: str,
    query: str,
    udm_query: Optional[str] = None,
    tools: Optional[list[Callable[..., Any]]] = None,
    api_tracker: Optional[APICallTracker] = None,
    lm: Optional[dspy.LM] = None,
    sub_lm: Optional[dspy.LM] = None,
    max_iters: int = 2,
    max_llm_calls: int = 4,
) -> dict[str, Any]:
  """Async wrapper executing `distill_secops_udm` in a worker thread."""
  return await asyncio.to_thread(
      distill_secops_udm,
      raw_payload=raw_payload,
      entity_or_search_text=entity_or_search_text,
      tool_name=tool_name,
      query=query,
      udm_query=udm_query,
      tools=tools,
      api_tracker=api_tracker,
      lm=lm,
      sub_lm=sub_lm,
      max_iters=max_iters,
      max_llm_calls=max_llm_calls,
  )
