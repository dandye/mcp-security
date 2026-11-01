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
"""DSPy 3.4+ RLM distillation engine and sandboxed REPL interpreter for GTI MCP."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import re
import threading
import typing
from typing import Any, Callable, Optional

import dspy
from dspy.primitives.local_interpreter import LocalInterpreter

logger = logging.getLogger(__name__)

# Known benign OS/sandbox artifacts that pollute VirusTotal behaviour_summary
# and file_behaviour payloads (per GTI malware_analysis guidelines).
COMMON_BENIGN_NOISE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|\\)SyncRootManager$", re.IGNORECASE),
    re.compile(r"(?:^|\\)MSIExecute$", re.IGNORECASE),
    re.compile(r"WilStaging_\d+", re.IGNORECASE),
    re.compile(r"SM0:\d+:\d+:WilStaging", re.IGNORECASE),
    re.compile(
        r"\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts(?:\\|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\\Software\\Adobe\\Acrobat Reader\\DC\\Privileged(?:\\|$)",
        re.IGNORECASE,
    ),
    re.compile(r"\\Windows\\System32\\locale_.*\.nls$", re.IGNORECASE),
    re.compile(r"\\Windows\\Globalization\\Sorting\\", re.IGNORECASE),
    re.compile(r"\\Software\\Microsoft\\CTF\\TIP\\", re.IGNORECASE),
)


def is_benign_sandbox_noise(value: Any) -> bool:
  """Returns True if a mutex, registry key, or file path is known benign OS noise."""
  if not isinstance(value, str):
    if isinstance(value, dict):
      candidate = (
          value.get("key")
          or value.get("path")
          or value.get("name")
          or value.get("mutex")
          or ""
      )
      return is_benign_sandbox_noise(candidate) if candidate else False
    return False
  stripped = value.strip()
  if not stripped:
    return True
  return any(pattern.search(stripped) for pattern in COMMON_BENIGN_NOISE_PATTERNS)


def _extract_attributes(raw_data: Any) -> dict[str, Any]:
  """Extracts the primary attributes dict from a VT object or returns raw_data if flat."""
  if not isinstance(raw_data, dict):
    return {}
  if isinstance(raw_data.get("attributes"), dict):
    return raw_data["attributes"]
  if isinstance(raw_data.get("data"), dict):
    inner = raw_data["data"]
    if isinstance(inner.get("attributes"), dict):
      return inner["attributes"]
    return inner
  return raw_data


def _extract_relationships(raw_data: Any) -> dict[str, Any]:
  """Extracts the relationships dict from a VT object if present."""
  if not isinstance(raw_data, dict):
    return {}
  if isinstance(raw_data.get("relationships"), dict):
    return raw_data["relationships"]
  if isinstance(raw_data.get("data"), dict):
    inner = raw_data["data"]
    if isinstance(inner.get("relationships"), dict):
      return inner["relationships"]
  return {}


def extract_verbatim_anchors(raw_data: Any) -> dict[str, Any]:
  """Deterministically extracts exact cryptographic digests and core GTI scores."""
  attrs = _extract_attributes(raw_data)
  pe_info = attrs.get("pe_info") if isinstance(attrs.get("pe_info"), dict) else {}

  code_insights: Optional[str] = None
  ai_results = attrs.get("crowdsourced_ai_results")
  if isinstance(ai_results, list):
    snippets = []
    for item in ai_results:
      if isinstance(item, dict) and item.get("analysis"):
        snippets.append(str(item["analysis"]).strip())
    if snippets:
      code_insights = "\n".join(snippets)

  return {
      "sha256": attrs.get("sha256"),
      "sha1": attrs.get("sha1"),
      "md5": attrs.get("md5"),
      "imphash": pe_info.get("imphash") or attrs.get("imphash"),
      "ssdeep": attrs.get("ssdeep"),
      "tlsh": attrs.get("tlsh"),
      "meaningful_name": attrs.get("meaningful_name") or attrs.get("name"),
      "type_description": attrs.get("type_description") or attrs.get("collection_type"),
      "size": attrs.get("size"),
      "last_analysis_stats": (
          attrs.get("last_analysis_stats")
          if isinstance(attrs.get("last_analysis_stats"), dict)
          else {}
      ),
      "popular_threat_classification": (
          attrs.get("popular_threat_classification")
          if isinstance(attrs.get("popular_threat_classification"), dict)
          else {}
      ),
      "gti_assessment": (
          attrs.get("gti_assessment")
          if isinstance(attrs.get("gti_assessment"), dict)
          else {}
      ),
      "code_insights": code_insights,
  }


def build_payload_index(raw_data: Any) -> dict[str, Any]:
  """Builds a compact structural index of a VT response for turn-0 REPL inspection."""
  if isinstance(raw_data, list):
    return {
        "payload_type": "list",
        "item_count": len(raw_data),
        "sample_keys": (
            sorted(list(raw_data[0].keys()))[:20]
            if raw_data and isinstance(raw_data[0], dict)
            else []
        ),
        "collection_counts": {"items": len(raw_data)},
        "benign_noise_counts": {},
    }

  if not isinstance(raw_data, dict):
    return {
        "payload_type": type(raw_data).__name__,
        "collection_counts": {},
        "benign_noise_counts": {},
    }

  attrs = _extract_attributes(raw_data)
  rels = _extract_relationships(raw_data)
  collection_counts: dict[str, int] = {}
  benign_noise_counts: dict[str, int] = {}

  for key, val in attrs.items():
    if isinstance(val, (list, dict)):
      collection_counts[key] = len(val)
      if isinstance(val, list):
        noise_count = sum(1 for item in val if is_benign_sandbox_noise(item))
        if noise_count > 0:
          benign_noise_counts[key] = noise_count

  pe_info = attrs.get("pe_info")
  if isinstance(pe_info, dict):
    for sub_key, sub_val in pe_info.items():
      if isinstance(sub_val, (list, dict)):
        collection_counts[f"pe_info.{sub_key}"] = len(sub_val)

  relationship_counts = {
      rel_name: len(rel_items)
      for rel_name, rel_items in rels.items()
      if isinstance(rel_items, list)
  }

  return {
      "payload_type": "dict",
      "top_level_keys": sorted(list(raw_data.keys())),
      "attribute_keys": sorted(list(attrs.keys())),
      "collection_counts": collection_counts,
      "relationship_counts": relationship_counts,
      "benign_noise_counts": benign_noise_counts,
  }


def _flatten_process_tree(tree: list[Any], depth: int = 0) -> list[str]:
  """Flattens a nested VT processes_tree list into readable parent -> child chains."""
  lines: list[str] = []
  for node in tree:
    if not isinstance(node, dict):
      continue
    name = node.get("name") or node.get("process_id") or "unknown"
    pid = node.get("process_id")
    prefix = "  " * depth + ("-> " if depth > 0 else "")
    label = f"{prefix}{name} (pid={pid})" if pid else f"{prefix}{name}"
    if not is_benign_sandbox_noise(name):
      lines.append(label)
    children = node.get("children")
    if isinstance(children, list) and children:
      lines.extend(_flatten_process_tree(children, depth + 1))
  return lines


def deterministic_distill_payload(
    raw_data: Any,
    *,
    entity_id: str,
    tool_name: str,
    query: str,
    api_calls_made: int = 1,
    endpoints_called: Optional[list[str]] = None,
    rlm_iters: int = 0,
    rlm_mode: str = "deterministic_fallback",
) -> dict[str, Any]:
  """Deterministically distills a VT file/behavior/relationship payload into high-signal JSON."""
  raw_bytes = len(json.dumps(raw_data, default=str).encode("utf-8"))
  anchors = extract_verbatim_anchors(raw_data)
  attrs = _extract_attributes(raw_data)
  rels = _extract_relationships(raw_data)

  network_iocs: list[str] = []
  files_dropped: list[str] = []
  process_cmds: list[str] = []
  persistence_mutexes: list[str] = []
  yara_sigma_matches: list[str] = []
  attributions: list[dict[str, str]] = []
  mitre_techniques: list[dict[str, str]] = []
  key_findings: list[str] = []
  filtered_noise_total = 0

  # 1. Extract network IOCs from relationships and behaviour fields
  for rel_key in (
      "contacted_domains",
      "contacted_ips",
      "contacted_urls",
      "embedded_domains",
      "embedded_ips",
      "embedded_urls",
      "itw_domains",
      "itw_ips",
      "itw_urls",
  ):
    items = rels.get(rel_key) or attrs.get(rel_key)
    if isinstance(items, list):
      for item in items[:25]:
        ioc_val = item.get("id") or item.get("url") if isinstance(item, dict) else str(item)
        if ioc_val and ioc_val not in network_iocs:
          network_iocs.append(str(ioc_val))

  for traffic in attrs.get("ip_traffic", []) if isinstance(attrs.get("ip_traffic"), list) else []:
    if isinstance(traffic, dict) and traffic.get("destination_ip"):
      port = traffic.get("destination_port")
      entry = (
          f"{traffic['destination_ip']}:{port}"
          if port
          else str(traffic["destination_ip"])
      )
      if entry not in network_iocs:
        network_iocs.append(entry)
      if str(traffic["destination_ip"]) not in network_iocs:
        network_iocs.append(str(traffic["destination_ip"]))

  for dns in attrs.get("dns_lookups", []) if isinstance(attrs.get("dns_lookups"), list) else []:
    if isinstance(dns, dict) and dns.get("hostname"):
      host = str(dns["hostname"])
      if host not in network_iocs:
        network_iocs.append(host)

  for http in (
      attrs.get("http_conversations", [])
      if isinstance(attrs.get("http_conversations"), list)
      else []
  ):
    if isinstance(http, dict) and http.get("url"):
      url_val = str(http["url"])
      if url_val not in network_iocs:
        network_iocs.append(url_val)

  # 2. Extract dropped/modified files
  for drop_source in (rels.get("dropped_files"), attrs.get("files_dropped"), attrs.get("files_written")):
    if isinstance(drop_source, list):
      for item in drop_source:
        if is_benign_sandbox_noise(item):
          filtered_noise_total += 1
          continue
        if isinstance(item, dict):
          path = item.get("path") or ""
          sha = item.get("sha256") or item.get("id") or ""
          desc = f"{path} (sha256={sha})" if path and sha else (path or sha)
        else:
          desc = str(item)
        if desc and desc not in files_dropped:
          files_dropped.append(desc)

  # 3. Extract processes and command executions
  if isinstance(attrs.get("processes_tree"), list):
    for proc_line in _flatten_process_tree(attrs["processes_tree"]):
      if proc_line not in process_cmds:
        process_cmds.append(proc_line)

  for cmd_field in ("command_executions", "processes_created", "processes_injected"):
    cmds = attrs.get(cmd_field)
    if isinstance(cmds, list):
      for cmd in cmds:
        if is_benign_sandbox_noise(cmd):
          filtered_noise_total += 1
          continue
        cmd_str = str(cmd).strip()
        if cmd_str and cmd_str not in process_cmds:
          process_cmds.append(cmd_str)

  # 4. Extract persistence (registry keys set, non-noisy mutexes)
  for mutex_field in ("mutexes_created", "mutexes_opened"):
    mutexes = attrs.get(mutex_field)
    if isinstance(mutexes, list):
      for mutex in mutexes:
        if is_benign_sandbox_noise(mutex):
          filtered_noise_total += 1
          continue
        m_str = str(mutex).strip()
        if m_str and m_str not in persistence_mutexes:
          persistence_mutexes.append(m_str)

  for reg_field in ("registry_keys_set", "registry_keys_deleted"):
    regs = attrs.get(reg_field)
    if isinstance(regs, list):
      for reg in regs:
        if is_benign_sandbox_noise(reg):
          filtered_noise_total += 1
          continue
        if isinstance(reg, dict):
          k = reg.get("key") or ""
          v = reg.get("value")
          reg_str = f"{k} = {v}" if v is not None else k
        else:
          reg_str = str(reg)
        if reg_str and reg_str not in persistence_mutexes:
          persistence_mutexes.append(reg_str)

  # Count filtered noisy read-only arrays
  for noisy_read_field in ("registry_keys_opened", "files_opened", "modules_loaded"):
    arr = attrs.get(noisy_read_field)
    if isinstance(arr, list):
      filtered_noise_total += sum(1 for item in arr if is_benign_sandbox_noise(item))

  # 5. Extract YARA, Sigma, IDS, and sandbox signature matches
  for yara in (
      attrs.get("crowdsourced_yara_results", [])
      if isinstance(attrs.get("crowdsourced_yara_results"), list)
      else []
  ):
    if isinstance(yara, dict) and yara.get("rule_name"):
      entry = f"YARA:{yara['rule_name']}"
      if yara.get("ruleset_name"):
        entry += f" ({yara['ruleset_name']})"
      if entry not in yara_sigma_matches:
        yara_sigma_matches.append(entry)

  for sigma in (
      attrs.get("sigma_analysis_results", [])
      if isinstance(attrs.get("sigma_analysis_results"), list)
      else []
  ):
    if isinstance(sigma, dict) and sigma.get("rule_title"):
      lvl = sigma.get("rule_level", "unknown")
      entry = f"Sigma:{sigma['rule_title']} [{lvl}]"
      if entry not in yara_sigma_matches:
        yara_sigma_matches.append(entry)

  for ids_hit in (
      attrs.get("crowdsourced_ids_results", [])
      if isinstance(attrs.get("crowdsourced_ids_results"), list)
      else []
  ):
    if isinstance(ids_hit, dict) and ids_hit.get("rule_msg"):
      entry = f"IDS:{ids_hit['rule_msg']}"
      if entry not in yara_sigma_matches:
        yara_sigma_matches.append(entry)

  for sig in (
      attrs.get("signature_matches", [])
      if isinstance(attrs.get("signature_matches"), list)
      else []
  ):
    if isinstance(sig, dict) and sig.get("description"):
      sev = sig.get("severity", "")
      entry = f"SandboxSig:{sig['description']}" + (f" [{sev}]" if sev else "")
      if entry not in yara_sigma_matches:
        yara_sigma_matches.append(entry)

  # 6. Extract attributions / associations
  assoc_items: list[Any] = []
  if isinstance(rels.get("associations"), list):
    assoc_items.extend(rels["associations"])
  if isinstance(raw_data, list):
    assoc_items.extend(raw_data)
  for assoc in assoc_items:
    if isinstance(assoc, dict):
      a_id = str(assoc.get("id") or "")
      a_attrs = assoc.get("attributes") if isinstance(assoc.get("attributes"), dict) else {}
      a_name = str(a_attrs.get("name") or a_id)
      a_type = str(
          a_attrs.get("collection_type") or assoc.get("type") or "collection"
      )
      if a_id:
        attributions.append(
            {"id": a_id, "name": a_name, "collection_type": a_type}
        )

  # 7. Extract MITRE ATT&CK techniques
  raw_techniques = attrs.get("attack_techniques") or rels.get("attack_techniques")
  if isinstance(raw_techniques, list):
    for tech in raw_techniques:
      if isinstance(tech, str):
        mitre_techniques.append({"id": tech, "name": tech, "evidence": "behaviour_summary"})
      elif isinstance(tech, dict):
        t_id = str(tech.get("id") or "")
        t_attrs = tech.get("attributes") if isinstance(tech.get("attributes"), dict) else {}
        t_name = str(t_attrs.get("name") or tech.get("name") or t_id)
        if t_id:
          mitre_techniques.append({"id": t_id, "name": t_name, "evidence": "relationship"})
  elif isinstance(raw_techniques, dict):
    for t_id, details in raw_techniques.items():
      t_name = t_id
      if isinstance(details, list) and details and isinstance(details[0], dict):
        t_name = str(details[0].get("description") or t_id)
      mitre_techniques.append({"id": str(t_id), "name": t_name, "evidence": "behaviour"})

  # 8. Build key findings and verdict summary
  stats = anchors.get("last_analysis_stats") or {}
  malicious_count = stats.get("malicious", 0)
  suspicious_count = stats.get("suspicious", 0)
  threat_label = (
      anchors.get("popular_threat_classification", {}).get("suggested_threat_label")
      or ""
  )
  gti_verdict = (
      anchors.get("gti_assessment", {}).get("verdict", {}).get("value")
      if isinstance(anchors.get("gti_assessment", {}).get("verdict"), dict)
      else None
  )

  if malicious_count or gti_verdict:
    key_findings.append(
        f"Detections: {malicious_count} malicious, {suspicious_count} suspicious"
        + (f"; label={threat_label}" if threat_label else "")
        + (f"; gti_verdict={gti_verdict}" if gti_verdict else "")
    )
  if anchors.get("code_insights"):
    key_findings.append(f"Code Insights: {anchors['code_insights']}")
  if yara_sigma_matches:
    key_findings.append(f"Rule Matches ({len(yara_sigma_matches)}): " + "; ".join(yara_sigma_matches[:5]))
  if network_iocs:
    key_findings.append(f"Network IOCs ({len(network_iocs)}): " + ", ".join(network_iocs[:8]))
  if process_cmds:
    key_findings.append(f"Execution Activity ({len(process_cmds)}): " + "; ".join(process_cmds[:5]))
  if attributions:
    key_findings.append(
        "Attributions: " + ", ".join(f"{a['name']} ({a['collection_type']})" for a in attributions[:5])
    )

  verdict_summary = (
      f"Entity {entity_id}: "
      + (f"GTI Verdict {gti_verdict}, " if gti_verdict else "")
      + (f"{malicious_count} malicious vendor detections, " if malicious_count else "")
      + (f"classified as {threat_label}." if threat_label else f"{len(key_findings)} high-signal findings extracted.")
  ).strip()

  result: dict[str, Any] = {
      "id": entity_id,
      "tool": tool_name,
      "query": query,
      "verbatim_anchors": anchors,
      "verdict_and_summary": verdict_summary,
      "answer": " | ".join(key_findings) if key_findings else verdict_summary,
      "key_findings": key_findings,
      "high_signal_iocs": {
          "network": network_iocs[:30],
          "files_dropped_or_modified": files_dropped[:25],
          "process_and_command_lines": process_cmds[:25],
          "persistence_and_mutexes": persistence_mutexes[:25],
          "yara_and_sigma_matches": yara_sigma_matches[:25],
      },
      "attributions": attributions[:20],
      "mitre_techniques": mitre_techniques[:25],
      "filtered_noise_summary": (
          f"Filtered {filtered_noise_total} benign OS/sandbox noise entries "
          f"(SyncRootManager, MSIExecute, Fonts/Adobe/NLS clutter) and omitted bulky static import/vendor tables."
      ),
  }

  output_bytes = len(json.dumps(result, default=str).encode("utf-8"))
  reduction_pct = (
      round((1.0 - (output_bytes / raw_bytes)) * 100.0, 2)
      if raw_bytes > 0
      else 0.0
  )
  result["compression_metrics"] = {
      "raw_bytes": raw_bytes,
      "output_bytes": output_bytes,
      "reduction_pct": reduction_pct,
      "api_calls_made": api_calls_made,
      "endpoints_called": endpoints_called or [],
      "rlm_iters": rlm_iters,
      "rlm_mode": rlm_mode,
  }
  return result


class GTISandboxedInterpreter(LocalInterpreter):
  """Hardened LocalInterpreter for GTI payload exploration and bound tool calls."""

  def __init__(
      self,
      tools: Optional[dict[str, Callable[..., Any]]] = None,
      output_fields: Optional[list[dict[str, Any]]] = None,
      *,
      min_sub_lm_prompt_chars: int = 35,
      execution_timeout: Optional[float] = 30.0,
      callbacks: Optional[list[Any]] = None,
  ) -> None:
    super().__init__(
        tools=tools,
        output_fields=output_fields,
        execution_timeout=execution_timeout,
        callbacks=callbacks,
    )
    self.user_turns: int = 0
    self.min_sub_lm_prompt_chars = min_sub_lm_prompt_chars

  def execute(
      self, code: str, variables: Optional[dict[str, Any]] = None
  ) -> Any:
    """Executes REPL Python while skipping FacadeInvocation SHIM_SETUP turn counting."""
    if variables and "__dspy_host_token" in variables:
      return super().execute(code, variables=variables)
    self.user_turns += 1
    return super().execute(code, variables=variables)

  def invoke_tool(
      self, tool_name: str, args: list[Any] | tuple[Any, ...], kwargs: dict[str, Any]
  ) -> Any:
    """Binds positional arguments on wrapped dspy.Tool functions and gates sub_lm grounding."""
    if tool_name in ("llm_query", "llm_query_batched"):
      prompts: list[str] = []
      if tool_name == "llm_query":
        p = args[0] if args else kwargs.get("prompt", "")
        prompts = [str(p)]
      else:
        batch = args[0] if args else kwargs.get("prompts", [])
        if isinstance(batch, list):
          prompts = [str(item) for item in batch]
      for prompt_text in prompts:
        if len(prompt_text.strip()) < self.min_sub_lm_prompt_chars:
          return (
              "GROUNDING_ERROR: sub-LM prompt is too short and lacks embedded "
              "payload context. Slice raw_data in Python first and include the "
              "relevant JSON snippet (>=35 chars) inside the prompt."
          )

    fn = (self.tools or {}).get(tool_name)
    if fn is not None and args and (
        hasattr(fn, "__wrapped__") or hasattr(fn, "__signature__")
    ):
      sig = getattr(fn, "__signature__", None) or inspect.signature(
          getattr(fn, "__wrapped__", fn)
      )
      bound = sig.bind(*args, **kwargs)
      bound.apply_defaults()
      return super().invoke_tool(tool_name, [], dict(bound.arguments))

    return super().invoke_tool(tool_name, list(args), kwargs)


class APICallTracker:
  """Tracks VT API call budget, caches duplicate calls, and accumulates raw payload bytes."""

  def __init__(
      self,
      *,
      max_api_calls: int = 4,
      initial_endpoint: Optional[str] = None,
      initial_bytes: int = 0,
  ) -> None:
    self.max_api_calls = max(1, min(int(max_api_calls), 10))
    self._lock = threading.Lock()
    self._cache: dict[str, Any] = {}
    self.endpoints_called: list[str] = (
        [initial_endpoint] if initial_endpoint else []
    )
    self.api_calls_made: int = 1 if initial_endpoint else 0
    self.total_raw_bytes: int = max(0, int(initial_bytes))

  def call(
      self,
      endpoint: str,
      params: Optional[dict[str, Any]],
      fetcher: Callable[[], Any],
  ) -> Any:
    """Executes fetcher if within max_api_calls budget or returns cached response."""
    cache_key = f"{endpoint}?{json.dumps(params or {}, sort_keys=True, default=str)}"
    with self._lock:
      if cache_key in self._cache:
        return self._cache[cache_key]
      if self.api_calls_made >= self.max_api_calls:
        return {
            "budget_exhausted": (
                f"API call budget ({self.max_api_calls}) reached; "
                f"already called {self.endpoints_called}. Synthesize findings from loaded data."
            )
        }
      self.api_calls_made += 1
      self.endpoints_called.append(endpoint)

    result = fetcher()
    payload_bytes = len(json.dumps(result, default=str).encode("utf-8"))
    with self._lock:
      self._cache[cache_key] = result
      self.total_raw_bytes += payload_bytes
    return result


class GTIPayloadDistillSignature(dspy.Signature):
  """Explore a Google Threat Intelligence (VirusTotal v3) payload in Python to extract high-signal threat intelligence.

  Instructions for the Python REPL:
  1. Inspect `payload_index` first to see collection sizes and benign noise counts without printing all of `raw_data`.
  2. Write Python slices over `raw_data` to filter out benign OS/sandbox clutter (SyncRootManager, MSIExecute, Fonts/Adobe/NLS reads, and `undetected` vendor rows).
  3. Never fabricate or alter cryptographic hashes (`sha256`, `sha1`, `md5`, `imphash`).
  4. If bound `fetch_*` tools are available and `raw_data` lacks behavioral or attribution details needed for `query`, call them selectively within the API budget.
  5. Call `SUBMIT(...)` with concise, high-signal fields grounded in `raw_data`.
  """

  entity_id: str = dspy.InputField(desc="Target file hash or behaviour ID.")
  tool_name: str = dspy.InputField(desc="MCP tool name being executed.")
  query: str = dspy.InputField(
      desc="Specific analyst question or triage objective."
  )
  payload_index: dict[str, Any] = dspy.InputField(
      desc="Compact structural index of top-level keys, collection lengths, and benign noise counts."
  )
  raw_data: Any = dspy.InputField(
      desc="Full un-truncated VirusTotal v3 JSON payload (dict or list) loaded in the Python REPL."
  )

  verdict_and_summary: str = dspy.OutputField(
      desc="Concise executive threat assessment (verdict, malware family, severity, and primary capability)."
  )
  answer: str = dspy.OutputField(
      desc="Direct, evidence-backed answer to `query`."
  )
  key_findings: list[str] = dspy.OutputField(
      desc="Bullet list of grounded technical findings."
  )
  high_signal_iocs: dict[str, list[str]] = dspy.OutputField(
      desc="Dict with keys: network, files_dropped_or_modified, process_and_command_lines, persistence_and_mutexes, yara_and_sigma_matches."
  )
  attributions: list[dict[str, str]] = dspy.OutputField(
      desc="List of associated threat actors, malware families, campaigns, or reports: [{'id': ..., 'name': ..., 'collection_type': ...}]."
  )
  mitre_techniques: list[dict[str, str]] = dspy.OutputField(
      desc="List of MITRE ATT&CK techniques: [{'id': ..., 'name': ..., 'evidence': ...}]."
  )
  filtered_noise_summary: str = dspy.OutputField(
      desc="Summary of noisy/benign fields and entries omitted during distillation."
  )


def configure_gti_rlm_lms(
    lm: Optional[dspy.LM] = None,
    sub_lm: Optional[dspy.LM] = None,
) -> tuple[Optional[dspy.LM], Optional[dspy.LM]]:
  """Resolves root LM and sub-LM from explicit args, dspy.settings, or environment variables."""
  if lm is not None:
    return lm, sub_lm or lm

  if getattr(dspy.settings, "lm", None) is not None:
    active_lm = dspy.settings.lm
    return active_lm, sub_lm or active_lm

  root_model = os.getenv("GTI_RLM_MODEL")
  sub_model = os.getenv("GTI_RLM_SUB_MODEL")

  if not root_model:
    if os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GOOGLE_GENAI_USE_VERTEXAI"):
      root_model = "vertex_ai/gemini-2.5-flash"
      sub_model = sub_model or "vertex_ai/gemini-2.5-flash-lite"
    elif os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"):
      root_model = "gemini/gemini-2.5-flash"
      sub_model = sub_model or "gemini/gemini-2.5-flash-lite"
    else:
      return None, None

  sub_model = sub_model or root_model
  resolved_lm = dspy.LM(root_model, temperature=0.0)
  resolved_sub_lm = dspy.LM(sub_model, temperature=0.0)
  return resolved_lm, resolved_sub_lm


def _ensure_json_compatible(data: Any) -> Any:
  """Ensures REPL input variables are strictly JSON-serializable for LocalInterpreter's pipe."""
  return json.loads(json.dumps(data, default=str))


def normalize_rlm_prediction(
    prediction: Any,
    *,
    raw_data: Any,
    entity_id: str,
    tool_name: str,
    query: str,
    api_calls_made: int,
    endpoints_called: list[str],
    raw_bytes: int,
    rlm_iters: int,
) -> dict[str, Any]:
  """Validates and normalizes a dspy.RLM Prediction and merges deterministic verbatim anchors."""
  anchors = extract_verbatim_anchors(raw_data)

  raw_iocs = getattr(prediction, "high_signal_iocs", None)
  if isinstance(raw_iocs, str):
    try:
      raw_iocs = json.loads(raw_iocs)
    except Exception:
      raw_iocs = {}
  if not isinstance(raw_iocs, dict):
    raw_iocs = {}

  normalized_iocs = {
      "network": [str(x) for x in (raw_iocs.get("network") or []) if x],
      "files_dropped_or_modified": [
          str(x) for x in (raw_iocs.get("files_dropped_or_modified") or []) if x
      ],
      "process_and_command_lines": [
          str(x) for x in (raw_iocs.get("process_and_command_lines") or []) if x
      ],
      "persistence_and_mutexes": [
          str(x)
          for x in (raw_iocs.get("persistence_and_mutexes") or [])
          if x and not is_benign_sandbox_noise(x)
      ],
      "yara_and_sigma_matches": [
          str(x) for x in (raw_iocs.get("yara_and_sigma_matches") or []) if x
      ],
  }

  raw_findings = getattr(prediction, "key_findings", None)
  if isinstance(raw_findings, str):
    key_findings = [line.strip("- *") for line in raw_findings.splitlines() if line.strip()]
  elif isinstance(raw_findings, list):
    key_findings = [str(item) for item in raw_findings if item]
  else:
    key_findings = []

  raw_attributions = getattr(prediction, "attributions", None)
  attributions: list[dict[str, str]] = []
  if isinstance(raw_attributions, list):
    for item in raw_attributions:
      if isinstance(item, dict):
        attributions.append(
            {
                "id": str(item.get("id") or ""),
                "name": str(item.get("name") or item.get("id") or ""),
                "collection_type": str(item.get("collection_type") or "collection"),
            }
        )
      elif isinstance(item, str):
        attributions.append({"id": item, "name": item, "collection_type": "collection"})

  raw_mitre = getattr(prediction, "mitre_techniques", None)
  mitre_techniques: list[dict[str, str]] = []
  if isinstance(raw_mitre, list):
    for item in raw_mitre:
      if isinstance(item, dict):
        mitre_techniques.append(
            {
                "id": str(item.get("id") or ""),
                "name": str(item.get("name") or item.get("id") or ""),
                "evidence": str(item.get("evidence") or ""),
            }
        )
      elif isinstance(item, str):
        mitre_techniques.append({"id": item, "name": item, "evidence": ""})

  verdict_summary = str(getattr(prediction, "verdict_and_summary", "") or "").strip()
  answer = str(getattr(prediction, "answer", "") or verdict_summary).strip()
  filtered_noise = str(
      getattr(prediction, "filtered_noise_summary", "")
      or "Filtered benign sandbox and vendor noise via DSPy RLM REPL."
  ).strip()

  result: dict[str, Any] = {
      "id": entity_id,
      "tool": tool_name,
      "query": query,
      "verbatim_anchors": anchors,
      "verdict_and_summary": verdict_summary,
      "answer": answer,
      "key_findings": key_findings,
      "high_signal_iocs": normalized_iocs,
      "attributions": attributions,
      "mitre_techniques": mitre_techniques,
      "filtered_noise_summary": filtered_noise,
  }
  output_bytes = len(json.dumps(result, default=str).encode("utf-8"))
  reduction_pct = (
      round((1.0 - (output_bytes / raw_bytes)) * 100.0, 2)
      if raw_bytes > 0
      else 0.0
  )
  result["compression_metrics"] = {
      "raw_bytes": raw_bytes,
      "output_bytes": output_bytes,
      "reduction_pct": reduction_pct,
      "api_calls_made": api_calls_made,
      "endpoints_called": endpoints_called,
      "rlm_iters": rlm_iters,
      "rlm_mode": "dspy_rlm",
  }
  return result


def distill_gti_payload(
    raw_data: Any,
    *,
    entity_id: str,
    tool_name: str,
    query: Optional[str] = None,
    default_objective: str = (
        "Extract verdict, malware family, high-signal IOCs (network, dropped files, "
        "process chains, persistence, YARA/Sigma/IDS hits), attributions, and MITRE "
        "techniques while filtering out benign OS/sandbox clutter."
    ),
    extra_tools: Optional[list[Callable[..., Any]]] = None,
    tracker: Optional[APICallTracker] = None,
    lm: Optional[dspy.LM] = None,
    sub_lm: Optional[dspy.LM] = None,
    max_iters: Optional[int] = None,
    max_llm_calls: Optional[int] = None,
) -> dict[str, Any]:
  """Runs dspy.RLM over a GTI payload in a sandboxed REPL, with deterministic fallback."""
  effective_query = (query or "").strip() or default_objective
  initial_bytes = len(json.dumps(raw_data, default=str).encode("utf-8"))
  if tracker is None:
    tracker = APICallTracker(
        max_api_calls=1,
        initial_endpoint=tool_name,
        initial_bytes=initial_bytes,
    )

  resolved_lm, resolved_sub_lm = configure_gti_rlm_lms(lm=lm, sub_lm=sub_lm)
  if resolved_lm is None:
    logger.info(
        "No DSPy LM configured for %s on %s; using deterministic distillation.",
        tool_name,
        entity_id,
    )
    return deterministic_distill_payload(
        raw_data,
        entity_id=entity_id,
        tool_name=tool_name,
        query=effective_query,
        api_calls_made=tracker.api_calls_made,
        endpoints_called=list(tracker.endpoints_called),
    )

  iters_cap = max_iters or int(os.getenv("GTI_RLM_MAX_ITERS", "5"))
  llm_calls_cap = max_llm_calls or int(os.getenv("GTI_RLM_MAX_LLM_CALLS", "10"))
  output_chars_cap = int(os.getenv("GTI_RLM_MAX_OUTPUT_CHARS", "12000"))

  created_interpreters: list[GTISandboxedInterpreter] = []

  def _make_interpreter() -> GTISandboxedInterpreter:
    interp = GTISandboxedInterpreter()
    created_interpreters.append(interp)
    return interp

  try:
    safe_raw_data = _ensure_json_compatible(raw_data)
    payload_index = _ensure_json_compatible(build_payload_index(safe_raw_data))

    rlm = dspy.RLM(
        GTIPayloadDistillSignature,
        max_iters=iters_cap,
        max_llm_calls=llm_calls_cap,
        max_output_chars=output_chars_cap,
        tools=extra_tools or [],
        sub_lm=resolved_sub_lm,
        interpreter_factory=_make_interpreter,
    )
    with dspy.context(lm=resolved_lm):
      prediction = rlm(
          entity_id=entity_id,
          tool_name=tool_name,
          query=effective_query,
          payload_index=payload_index,
          raw_data=safe_raw_data,
      )

    total_iters = sum(i.user_turns for i in created_interpreters) or 1
    return normalize_rlm_prediction(
        prediction,
        raw_data=safe_raw_data,
        entity_id=entity_id,
        tool_name=tool_name,
        query=effective_query,
        api_calls_made=tracker.api_calls_made,
        endpoints_called=list(tracker.endpoints_called),
        raw_bytes=tracker.total_raw_bytes,
        rlm_iters=total_iters,
    )
  except Exception as exc:
    logger.warning(
        "dspy.RLM failed for %s on %s (%s); falling back to deterministic distillation.",
        tool_name,
        entity_id,
        exc,
        exc_info=True,
    )
    return deterministic_distill_payload(
        raw_data,
        entity_id=entity_id,
        tool_name=tool_name,
        query=effective_query,
        api_calls_made=tracker.api_calls_made,
        endpoints_called=list(tracker.endpoints_called),
    )


async def distill_gti_payload_async(
    raw_data: Any,
    *,
    entity_id: str,
    tool_name: str,
    query: Optional[str] = None,
    default_objective: str = (
        "Extract verdict, malware family, high-signal IOCs (network, dropped files, "
        "process chains, persistence, YARA/Sigma/IDS hits), attributions, and MITRE "
        "techniques while filtering out benign OS/sandbox clutter."
    ),
    extra_tools: Optional[list[Callable[..., Any]]] = None,
    tracker: Optional[APICallTracker] = None,
    lm: Optional[dspy.LM] = None,
    sub_lm: Optional[dspy.LM] = None,
) -> dict[str, Any]:
  """Runs distill_gti_payload in a background worker thread so FastMCP event loop never blocks."""
  return await asyncio.to_thread(
      distill_gti_payload,
      raw_data,
      entity_id=entity_id,
      tool_name=tool_name,
      query=query,
      default_objective=default_objective,
      extra_tools=extra_tools,
      tracker=tracker,
      lm=lm,
      sub_lm=sub_lm,
  )
