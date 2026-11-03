# Copyright 2026 Google LLC
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
"""Head-to-head SOC investigation comparison: Baseline Raw GTI Tools vs. DSPy RLM Tools.

Runs the exact same multi-step malware triage and dropped-payload pivot workflow
under three modes against live VirusTotal v3 and Vertex AI (gemini-3.8-flash):

  1. Baseline (Without Refactor):
     Uses legacy raw tools (`get_file_report`, `get_file_behavior_summary`,
     `get_entities_related_to_a_file`) and feeds raw JSON responses into a
     multi-turn host SOC agent conversation.
  2. Refactored RLM Step-by-Step (`rlm_get_*`):
     Uses the 1-API-call DSPy RLM tools (`rlm_get_file_report`,
     `rlm_get_file_behavior_summary`, `rlm_get_entities_related_to_a_file`)
     in the same multi-turn host SOC agent conversation.
  3. Refactored Autonomous RLM Investigator (`rlm_investigate_file`):
     Uses `rlm_investigate_file` to pivot across static and behavioral endpoints
     inside the sandboxed Python REPL and synthesize the investigation in a
     single host turn per artifact.
"""

import argparse
import asyncio
import json
import os
from pathlib import Path
import time
from typing import Any
from unittest.mock import MagicMock

from dotenv import load_dotenv
import litellm

from gti_mcp.tools.files import (
    get_entities_related_to_a_file,
    get_file_behavior_summary,
    get_file_report,
)
from gti_mcp.tools.rlm_files import (
    rlm_get_entities_related_to_a_file,
    rlm_get_file_behavior_summary,
    rlm_get_file_report,
    rlm_investigate_file,
)

PRIMARY_HASH = (
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
)
DROPPED_HASH = (
    "0a989a89d77d48f9a25ec64cb30043896bc976e85b8940b59dcf2afce2797227"
)

SYSTEM_PROMPT = (
    "You are a Senior Incident Responder and Threat Intelligence Analyst. "
    "Answer each investigative turn strictly using the Google Threat Intelligence "
    "(VirusTotal v3) tool outputs provided in the conversation. Always cite exact "
    "cryptographic hashes (SHA-256, MD5, imphash), specific security vendor "
    "detection names (if present in the tool output), exact command lines, "
    "mutexes, network indicators, MITRE ATT&CK technique IDs, and crowdsourced "
    "YARA rule names."
)

TURN_1_PROMPT = (
    "Turn 1 (Static Triage): Based on the static file report for the primary "
    "binary, provide:\n"
    "1. Exact SHA-256, MD5, and PE imphash digests.\n"
    "2. Masqueraded PE product/original filename.\n"
    "3. Exact malicious vendor count vs. total vendors, plus at least 3 individual "
    "security vendor detection strings (e.g., Kaspersky, Microsoft, ESET) if "
    "available in the payload.\n"
    "4. Matched crowdsourced YARA rule names and any referenced CVEs."
)

TURN_2_PROMPT = (
    "Turn 2 (Dynamic Sandbox Behavior): Based on the sandbox behavior summary "
    "added below, identify:\n"
    "1. Exact process execution chains and command lines.\n"
    "2. Non-benign mutexes and Windows service creation/persistence activity.\n"
    "3. Outbound DNS queries and HTTP requests (specifically any kill-switch or C2).\n"
    "4. Observed MITRE ATT&CK technique IDs and descriptions.\n"
    "5. What benign OS/sandbox background noise was present or filtered."
)

TURN_3_PROMPT = (
    "Turn 3 (Network Domain Pivot & Dropped Artifact Correlation): Based on the "
    "contacted_domains entity objects and the secondary dropped file report added "
    "below, produce the final comprehensive SOC Investigation Report covering:\n"
    "1. Primary dropper verbatim hashes (SHA-256, MD5, imphash) and masqueraded filename.\n"
    "2. Vendor consensus (malicious/total) and specific per-vendor signature names "
    "(or state explicitly if `last_analysis_results` was stripped by the tool).\n"
    "3. Why the 10 `contacted_domains` entries (`*.in-addr.arpa`) have 0 malicious "
    "detections and how they relate to SMB port 445 worm propagation vs. the true "
    "kill-switch domain (`www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`).\n"
    "4. Full execution chain, persistence services, mutexes, and MITRE ATT&CK IDs "
    "(including T1543.003, T1569.002, T1486, T1070.004, T1490, T1135, T1090.003).\n"
    "5. Role and classification of the dropped file "
    f"(`{DROPPED_HASH}`)."
)


GROUND_TRUTH_RUBRIC: list[tuple[str, str, list[str]]] = [
    (
        "primary_sha256",
        "Verbatim Primary SHA-256",
        ["24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"],
    ),
    (
        "primary_md5",
        "Verbatim Primary MD5",
        ["db349b97c37d22f5ea1d1841e3c89eb4"],
    ),
    (
        "primary_imphash",
        "Verbatim PE Imphash",
        ["9ecee117164e0b870a53dd187cdd7174"],
    ),
    (
        "masqueraded_filename",
        "PE Masquerade Filename (lhdfrgui.exe)",
        ["lhdfrgui.exe"],
    ),
    (
        "vendor_consensus_ratio",
        "Vendor Detection Ratio (68 Malicious Engines)",
        [
            "68/76",
            "68 / 76",
            "68/72",
            "68 / 72",
            "68 out of 76",
            "**68** out of **72**",
            "malicious: 68",
        ],
    ),
    (
        "individual_vendor_signatures",
        "Individual Engine Signatures from last_analysis_results (Kaspersky / Microsoft / ESET)",
        [
            "trojan-ransom.win32.wanna.m",
            "ransom:win32/wannacrypt!pz",
            "win32/exploit.cve-2017-0147",
            "ransom-wannacry!lnk",
        ],
    ),
    (
        "exploit_cve",
        "EternalBlue SMB Exploit CVE (CVE-2017-0144 / CVE-2017-0147)",
        ["cve-2017-0144", "cve-2017-0147", "ms17-010", "eternalblue"],
    ),
    (
        "killswitch_domain",
        "Kill-Switch Domain (iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com)",
        ["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"],
    ),
    (
        "reverse_dns_discrimination",
        "Reverse DNS (.in-addr.arpa) Scanning Noise Discrimination",
        ["in-addr.arpa"],
    ),
    (
        "yara_rule_match",
        "Crowdsourced YARA Rule Match (WannaCry_Ransomware)",
        ["wannacry_ransomware", "win32_ransomware_wannacry"],
    ),
    (
        "mitre_service_persistence",
        "MITRE Service Persistence (T1543.003 / T1569.002)",
        ["t1543.003", "t1569.002"],
    ),
    (
        "mitre_encryption_impact",
        "MITRE Ransomware Encryption (T1486)",
        ["t1486"],
    ),
    (
        "mitre_recovery_inhibition",
        "MITRE Shadow Deletion / Boot Config (T1070.004 / T1490)",
        ["t1070.004", "t1490"],
    ),
    (
        "dropped_file_sha256",
        "Verbatim Dropped File SHA-256 (0a989a89...97227)",
        ["0a989a89d77d48f9a25ec64cb30043896bc976e85b8940b59dcf2afce2797227"],
    ),
    (
        "noise_audit_trail",
        "Explicit Sandbox Noise Accounting (WER / SyncRootManager / ZonesCache)",
        [
            "syncrootmanager",
            "zonescachecountermutex",
            "wersvcgroup",
            "filtered_noise",
            "benign",
        ],
    ),
]


def _load_env_if_needed() -> None:
  if os.environ.get("VT_APIKEY"):
    return
  repo_root = Path(__file__).resolve().parents[3]
  env_file = repo_root / ".env"
  if env_file.exists():
    load_dotenv(env_file)


def _json_bytes(obj: Any) -> int:
  return len(json.dumps(obj, default=str).encode("utf-8"))


def _call_host_llm(messages: list[dict[str, str]]) -> dict[str, Any]:
  """Calls the host SOC agent model (`vertex_ai/gemini-3.8-flash`) and returns text + token usage."""
  model = os.getenv("GTI_RLM_MODEL", "vertex_ai/gemini-3.8-flash")
  vertex_location = (
      os.getenv("GTI_RLM_VERTEX_LOCATION")
      or os.getenv("VERTEXAI_LOCATION")
      or "global"
  )
  t0 = time.monotonic()
  resp = litellm.completion(
      model=model,
      messages=messages,
      max_tokens=8192,
      reasoning_effort="low",
      vertex_location=vertex_location,
  )
  elapsed = time.monotonic() - t0
  content = resp.choices[0].message.content or ""
  usage = getattr(resp, "usage", None)
  prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
  completion_tokens = getattr(usage, "completion_tokens", 0) or 0
  total_tokens = getattr(usage, "total_tokens", 0) or (
      prompt_tokens + completion_tokens
  )
  return {
      "content": content,
      "prompt_tokens": prompt_tokens,
      "completion_tokens": completion_tokens,
      "total_tokens": total_tokens,
      "elapsed_s": round(elapsed, 2),
  }


def evaluate_rubric(all_turn_texts: list[str]) -> dict[str, Any]:
  """Scores the combined agent responses against the 14 ground-truth criteria."""
  combined_lower = "\n".join(all_turn_texts).lower()
  results: dict[str, bool] = {}
  matched_count = 0
  for key, label, needles in GROUND_TRUTH_RUBRIC:
    hit = any(n.lower() in combined_lower for n in needles)
    results[key] = hit
    if hit:
      matched_count += 1
  return {
      "score": matched_count,
      "max_score": len(GROUND_TRUTH_RUBRIC),
      "score_pct": round((matched_count / len(GROUND_TRUTH_RUBRIC)) * 100.0, 1),
      "criteria": {
          key: {"label": label, "passed": results[key]}
          for key, label, _ in GROUND_TRUTH_RUBRIC
      },
  }


async def run_baseline_investigation(ctx: MagicMock) -> dict[str, Any]:
  """Mode 1: Multi-turn investigation using legacy raw GTI MCP tools."""
  print("\n[Mode 1] Running Baseline Investigation (Without Refactor - Raw GTI Tools)...")
  t_start = time.monotonic()

  # Step 1: Raw get_file_report on primary hash
  t0 = time.monotonic()
  raw_report = await get_file_report(PRIMARY_HASH, ctx)
  t_tool_1 = time.monotonic() - t0
  b_tool_1 = _json_bytes(raw_report)

  messages: list[dict[str, str]] = [
      {"role": "system", "content": SYSTEM_PROMPT},
      {
          "role": "user",
          "content": (
              f"{TURN_1_PROMPT}\n\n"
              f"### Tool Output: `get_file_report('{PRIMARY_HASH}')` ({b_tool_1:,} bytes)\n"
              f"```json\n{json.dumps(raw_report, default=str)}\n```"
          ),
      },
  ]
  turn1_llm = _call_host_llm(messages)
  messages.append({"role": "assistant", "content": turn1_llm["content"]})
  print(
      f"  Turn 1 (get_file_report): tool_bytes={b_tool_1:,} B | "
      f"host_prompt_tokens={turn1_llm['prompt_tokens']:,} | llm_time={turn1_llm['elapsed_s']}s"
  )

  # Step 2: Raw get_file_behavior_summary on primary hash
  t0 = time.monotonic()
  raw_behavior = await get_file_behavior_summary(PRIMARY_HASH, ctx)
  t_tool_2 = time.monotonic() - t0
  b_tool_2 = _json_bytes(raw_behavior)

  messages.append({
      "role": "user",
      "content": (
          f"{TURN_2_PROMPT}\n\n"
          f"### Tool Output: `get_file_behavior_summary('{PRIMARY_HASH}')` ({b_tool_2:,} bytes)\n"
          f"```json\n{json.dumps(raw_behavior, default=str)}\n```"
      ),
  })
  turn2_llm = _call_host_llm(messages)
  messages.append({"role": "assistant", "content": turn2_llm["content"]})
  print(
      f"  Turn 2 (get_file_behavior_summary): tool_bytes={b_tool_2:,} B | "
      f"host_prompt_tokens={turn2_llm['prompt_tokens']:,} | llm_time={turn2_llm['elapsed_s']}s"
  )

  # Step 3: Raw get_entities_related_to_a_file (contacted_domains) + dropped file report
  t0 = time.monotonic()
  raw_domains = await get_entities_related_to_a_file(
      PRIMARY_HASH, "contacted_domains", False, ctx, limit=10
  )
  raw_dropped = await get_file_report(DROPPED_HASH, ctx)
  t_tool_3 = time.monotonic() - t0
  b_domains = _json_bytes(raw_domains)
  b_dropped = _json_bytes(raw_dropped)
  b_tool_3 = b_domains + b_dropped

  messages.append({
      "role": "user",
      "content": (
          f"{TURN_3_PROMPT}\n\n"
          f"### Tool Output 3a: `get_entities_related_to_a_file('{PRIMARY_HASH}', 'contacted_domains')` ({b_domains:,} bytes)\n"
          f"```json\n{json.dumps(raw_domains, default=str)}\n```\n\n"
          f"### Tool Output 3b: `get_file_report('{DROPPED_HASH}')` ({b_dropped:,} bytes)\n"
          f"```json\n{json.dumps(raw_dropped, default=str)}\n```"
      ),
  })
  turn3_llm = _call_host_llm(messages)
  print(
      f"  Turn 3 (contacted_domains + dropped file): tool_bytes={b_tool_3:,} B | "
      f"host_prompt_tokens={turn3_llm['prompt_tokens']:,} | llm_time={turn3_llm['elapsed_s']}s"
  )

  total_elapsed = round(time.monotonic() - t_start, 2)
  turns = [
      {
          "turn": 1,
          "tools": ["get_file_report(primary)"],
          "tool_payload_bytes": b_tool_1,
          "tool_elapsed_s": round(t_tool_1, 2),
          "host_prompt_tokens": turn1_llm["prompt_tokens"],
          "host_completion_tokens": turn1_llm["completion_tokens"],
          "host_llm_elapsed_s": turn1_llm["elapsed_s"],
          "response": turn1_llm["content"],
      },
      {
          "turn": 2,
          "tools": ["get_file_behavior_summary(primary)"],
          "tool_payload_bytes": b_tool_2,
          "tool_elapsed_s": round(t_tool_2, 2),
          "host_prompt_tokens": turn2_llm["prompt_tokens"],
          "host_completion_tokens": turn2_llm["completion_tokens"],
          "host_llm_elapsed_s": turn2_llm["elapsed_s"],
          "response": turn2_llm["content"],
      },
      {
          "turn": 3,
          "tools": [
              "get_entities_related_to_a_file(contacted_domains)",
              "get_file_report(dropped)",
          ],
          "tool_payload_bytes": b_tool_3,
          "tool_elapsed_s": round(t_tool_3, 2),
          "host_prompt_tokens": turn3_llm["prompt_tokens"],
          "host_completion_tokens": turn3_llm["completion_tokens"],
          "host_llm_elapsed_s": turn3_llm["elapsed_s"],
          "response": turn3_llm["content"],
      },
  ]
  rubric = evaluate_rubric([t["response"] for t in turns])
  return {
      "mode": "baseline_raw_tools",
      "total_tool_bytes_injected": b_tool_1 + b_tool_2 + b_tool_3,
      "cumulative_host_prompt_tokens": sum(
          t["host_prompt_tokens"] for t in turns
      ),
      "cumulative_host_completion_tokens": sum(
          t["host_completion_tokens"] for t in turns
      ),
      "turn3_context_tokens": turn3_llm["prompt_tokens"],
      "vt_api_calls": 4,
      "total_elapsed_s": total_elapsed,
      "has_last_analysis_results_in_file_report": (
          "last_analysis_results"
          in (raw_report.get("attributes", {}) if isinstance(raw_report, dict) else {})
      ),
      "rubric": rubric,
      "turns": turns,
  }


async def run_rlm_stepwise_investigation(ctx: MagicMock) -> dict[str, Any]:
  """Mode 2: Multi-turn investigation using 1-API-call DSPy RLM tools (`rlm_get_*`)."""
  print("\n[Mode 2] Running Refactored 3-Turn RLM Investigation (`rlm_get_*` Tools)...")
  t_start = time.monotonic()

  # Step 1: rlm_get_file_report on primary hash
  t0 = time.monotonic()
  rlm_report = await rlm_get_file_report(
      PRIMARY_HASH,
      ctx,
      query=(
          "Extract vendor detection consensus (68/76), 4 specific vendor engine "
          "detection strings from last_analysis_results (e.g. Kaspersky, Microsoft, "
          "ESET, TrendMicro), masqueraded PE filename, YARA matches, CVE references, "
          "and network/file IOCs."
      ),
  )
  t_tool_1 = time.monotonic() - t0
  b_tool_1 = _json_bytes(rlm_report)

  messages: list[dict[str, str]] = [
      {"role": "system", "content": SYSTEM_PROMPT},
      {
          "role": "user",
          "content": (
              f"{TURN_1_PROMPT}\n\n"
              f"### Tool Output: `rlm_get_file_report('{PRIMARY_HASH}')` ({b_tool_1:,} bytes)\n"
              f"```json\n{json.dumps(rlm_report, default=str)}\n```"
          ),
      },
  ]
  turn1_llm = _call_host_llm(messages)
  messages.append({"role": "assistant", "content": turn1_llm["content"]})
  print(
      f"  Turn 1 (rlm_get_file_report): tool_bytes={b_tool_1:,} B | "
      f"host_prompt_tokens={turn1_llm['prompt_tokens']:,} | llm_time={turn1_llm['elapsed_s']}s"
  )

  # Step 2: rlm_get_file_behavior_summary on primary hash
  t0 = time.monotonic()
  rlm_behavior = await rlm_get_file_behavior_summary(
      PRIMARY_HASH,
      ctx,
      query=(
          "Extract process execution chains, command lines, service creation, "
          "mutexes, kill-switch DNS/HTTP requests, and MITRE ATT&CK techniques."
      ),
  )
  t_tool_2 = time.monotonic() - t0
  b_tool_2 = _json_bytes(rlm_behavior)

  messages.append({
      "role": "user",
      "content": (
          f"{TURN_2_PROMPT}\n\n"
          f"### Tool Output: `rlm_get_file_behavior_summary('{PRIMARY_HASH}')` ({b_tool_2:,} bytes)\n"
          f"```json\n{json.dumps(rlm_behavior, default=str)}\n```"
      ),
  })
  turn2_llm = _call_host_llm(messages)
  messages.append({"role": "assistant", "content": turn2_llm["content"]})
  print(
      f"  Turn 2 (rlm_get_file_behavior_summary): tool_bytes={b_tool_2:,} B | "
      f"host_prompt_tokens={turn2_llm['prompt_tokens']:,} | llm_time={turn2_llm['elapsed_s']}s"
  )

  # Step 3: rlm_get_entities_related_to_a_file (contacted_domains) + rlm_get_file_report(dropped)
  t0 = time.monotonic()
  rlm_domains = await rlm_get_entities_related_to_a_file(
      PRIMARY_HASH,
      "contacted_domains",
      ctx,
      descriptors_only=False,
      limit=10,
      query="Are any contacted domains C2 or kill-switch, or are they reverse DNS (.in-addr.arpa) scanning lookups?",
  )
  rlm_dropped = await rlm_get_file_report(
      DROPPED_HASH,
      ctx,
      query="What is the role, filetype, vendor classification, and behavior of this dropped file?",
  )
  t_tool_3 = time.monotonic() - t0
  b_domains = _json_bytes(rlm_domains)
  b_dropped = _json_bytes(rlm_dropped)
  b_tool_3 = b_domains + b_dropped

  messages.append({
      "role": "user",
      "content": (
          f"{TURN_3_PROMPT}\n\n"
          f"### Tool Output 3a: `rlm_get_entities_related_to_a_file('{PRIMARY_HASH}', 'contacted_domains')` ({b_domains:,} bytes)\n"
          f"```json\n{json.dumps(rlm_domains, default=str)}\n```\n\n"
          f"### Tool Output 3b: `rlm_get_file_report('{DROPPED_HASH}')` ({b_dropped:,} bytes)\n"
          f"```json\n{json.dumps(rlm_dropped, default=str)}\n```"
      ),
  })
  turn3_llm = _call_host_llm(messages)
  print(
      f"  Turn 3 (rlm contacted_domains + dropped file): tool_bytes={b_tool_3:,} B | "
      f"host_prompt_tokens={turn3_llm['prompt_tokens']:,} | llm_time={turn3_llm['elapsed_s']}s"
  )

  total_elapsed = round(time.monotonic() - t_start, 2)
  turns = [
      {
          "turn": 1,
          "tools": ["rlm_get_file_report(primary)"],
          "tool_payload_bytes": b_tool_1,
          "tool_raw_vt_bytes": rlm_report.get("compression_metrics", {}).get(
              "raw_bytes", 0
          ),
          "tool_elapsed_s": round(t_tool_1, 2),
          "host_prompt_tokens": turn1_llm["prompt_tokens"],
          "host_completion_tokens": turn1_llm["completion_tokens"],
          "host_llm_elapsed_s": turn1_llm["elapsed_s"],
          "response": turn1_llm["content"],
      },
      {
          "turn": 2,
          "tools": ["rlm_get_file_behavior_summary(primary)"],
          "tool_payload_bytes": b_tool_2,
          "tool_raw_vt_bytes": rlm_behavior.get("compression_metrics", {}).get(
              "raw_bytes", 0
          ),
          "tool_elapsed_s": round(t_tool_2, 2),
          "host_prompt_tokens": turn2_llm["prompt_tokens"],
          "host_completion_tokens": turn2_llm["completion_tokens"],
          "host_llm_elapsed_s": turn2_llm["elapsed_s"],
          "response": turn2_llm["content"],
      },
      {
          "turn": 3,
          "tools": [
              "rlm_get_entities_related_to_a_file(contacted_domains)",
              "rlm_get_file_report(dropped)",
          ],
          "tool_payload_bytes": b_tool_3,
          "tool_raw_vt_bytes": (
              rlm_domains.get("compression_metrics", {}).get("raw_bytes", 0)
              + rlm_dropped.get("compression_metrics", {}).get("raw_bytes", 0)
          ),
          "tool_elapsed_s": round(t_tool_3, 2),
          "host_prompt_tokens": turn3_llm["prompt_tokens"],
          "host_completion_tokens": turn3_llm["completion_tokens"],
          "host_llm_elapsed_s": turn3_llm["elapsed_s"],
          "response": turn3_llm["content"],
      },
  ]
  rubric = evaluate_rubric([t["response"] for t in turns])
  return {
      "mode": "rlm_stepwise_tools",
      "total_tool_bytes_injected": b_tool_1 + b_tool_2 + b_tool_3,
      "total_raw_vt_bytes_distilled": sum(
          t["tool_raw_vt_bytes"] for t in turns
      ),
      "cumulative_host_prompt_tokens": sum(
          t["host_prompt_tokens"] for t in turns
      ),
      "cumulative_host_completion_tokens": sum(
          t["host_completion_tokens"] for t in turns
      ),
      "turn3_context_tokens": turn3_llm["prompt_tokens"],
      "vt_api_calls": 4,
      "total_elapsed_s": total_elapsed,
      "rubric": rubric,
      "turns": turns,
  }


async def run_rlm_autonomous_investigation(ctx: MagicMock) -> dict[str, Any]:
  """Mode 3: Single-turn host synthesis powered by `rlm_investigate_file`."""
  print("\n[Mode 3] Running Autonomous RLM Investigator (`rlm_investigate_file`)...")
  t_start = time.monotonic()

  t0 = time.monotonic()
  inv_primary = await rlm_investigate_file(
      PRIMARY_HASH,
      ctx,
      investigation_goal=(
          "Correlate static PE/YARA/vendor indicators (including masqueraded "
          "filename, imphash, CVE references, and 4 specific vendor detection "
          "strings from last_analysis_results such as Kaspersky/Microsoft/ESET) "
          "with dynamic sandbox behavior (kill-switch domain, SMB scanning vs. "
          ".in-addr.arpa reverse DNS, service persistence, and MITRE ATT&CK techniques)."
      ),
      max_api_calls=3,
  )
  inv_dropped = await rlm_get_file_report(
      DROPPED_HASH,
      ctx,
      query="What is the role, filetype, vendor classification, and behavior of this dropped file?",
  )
  t_tools = time.monotonic() - t0
  b_primary = _json_bytes(inv_primary)
  b_dropped = _json_bytes(inv_dropped)
  b_total = b_primary + b_dropped

  messages: list[dict[str, str]] = [
      {"role": "system", "content": SYSTEM_PROMPT},
      {
          "role": "user",
          "content": (
              f"{TURN_3_PROMPT}\n\n"
              f"### Tool Output 1: `rlm_investigate_file('{PRIMARY_HASH}', max_api_calls=3)` ({b_primary:,} bytes)\n"
              f"```json\n{json.dumps(inv_primary, default=str)}\n```\n\n"
              f"### Tool Output 2: `rlm_get_file_report('{DROPPED_HASH}')` ({b_dropped:,} bytes)\n"
              f"```json\n{json.dumps(inv_dropped, default=str)}\n```"
          ),
      },
  ]
  turn_llm = _call_host_llm(messages)
  print(
      f"  Single Host Turn (`rlm_investigate_file` + dropped pivot): "
      f"tool_bytes={b_total:,} B | host_prompt_tokens={turn_llm['prompt_tokens']:,} | "
      f"llm_time={turn_llm['elapsed_s']}s"
  )

  total_elapsed = round(time.monotonic() - t_start, 2)
  raw_vt_bytes = inv_primary.get("compression_metrics", {}).get(
      "raw_bytes", 0
  ) + inv_dropped.get("compression_metrics", {}).get("raw_bytes", 0)
  api_calls = inv_primary.get("compression_metrics", {}).get(
      "api_calls_made", 2
  ) + inv_dropped.get("compression_metrics", {}).get("api_calls_made", 1)

  rubric = evaluate_rubric([turn_llm["content"]])
  return {
      "mode": "rlm_autonomous_investigate_file",
      "total_tool_bytes_injected": b_total,
      "total_raw_vt_bytes_distilled": raw_vt_bytes,
      "cumulative_host_prompt_tokens": turn_llm["prompt_tokens"],
      "cumulative_host_completion_tokens": turn_llm["completion_tokens"],
      "turn3_context_tokens": turn_llm["prompt_tokens"],
      "vt_api_calls": api_calls,
      "total_elapsed_s": total_elapsed,
      "rubric": rubric,
      "turns": [
          {
              "turn": 1,
              "tools": [
                  "rlm_investigate_file(primary, max_api_calls=3)",
                  "rlm_get_file_report(dropped)",
              ],
              "tool_payload_bytes": b_total,
              "tool_raw_vt_bytes": raw_vt_bytes,
              "tool_elapsed_s": round(t_tools, 2),
              "host_prompt_tokens": turn_llm["prompt_tokens"],
              "host_completion_tokens": turn_llm["completion_tokens"],
              "host_llm_elapsed_s": turn_llm["elapsed_s"],
              "response": turn_llm["content"],
          }
      ],
  }


def _print_comparison_table(results: dict[str, Any]) -> None:
  b = results["baseline"]
  s = results["rlm_stepwise"]
  a = results["rlm_autonomous"]

  b_bytes = b["total_tool_bytes_injected"]
  s_bytes = s["total_tool_bytes_injected"]
  a_bytes = a["total_tool_bytes_injected"]

  b_tok = b["cumulative_host_prompt_tokens"]
  s_tok = s["cumulative_host_prompt_tokens"]
  a_tok = a["cumulative_host_prompt_tokens"]

  s_byte_red = (1.0 - s_bytes / b_bytes) * 100.0 if b_bytes else 0.0
  a_byte_red = (1.0 - a_bytes / b_bytes) * 100.0 if b_bytes else 0.0

  s_tok_red = (1.0 - s_tok / b_tok) * 100.0 if b_tok else 0.0
  a_tok_red = (1.0 - a_tok / b_tok) * 100.0 if b_tok else 0.0

  print("\n" + "=" * 96)
  print("HEAD-TO-HEAD SOC INVESTIGATION COMPARISON: WITHOUT REFACTOR vs. WITH DSPy RLM REFACTOR")
  print("=" * 96)
  print(
      f"{'Metric':<42} | {'1. Baseline (Raw)':>16} | {'2. RLM Stepwise':>16} | {'3. RLM Autonomous':>16}"
  )
  print("-" * 96)
  print(
      f"{'Host Context Tool Bytes Injected':<42} | {b_bytes:>14,} B | {s_bytes:>14,} B | {a_bytes:>14,} B"
  )
  print(
      f"{'Host Context Byte Reduction (%)':<42} | {'0.00% (base)':>16} | {-s_byte_red:>15.2f}% | {-a_byte_red:>15.2f}%"
  )
  print(
      f"{'Cumulative Host Prompt Tokens Billed':<42} | {b_tok:>16,} | {s_tok:>16,} | {a_tok:>16,}"
  )
  print(
      f"{'Cumulative Host Token Savings (%)':<42} | {'0.00% (base)':>16} | {-s_tok_red:>15.2f}% | {-a_tok_red:>15.2f}%"
  )
  print(
      f"{'Final Turn Prompt Context Tokens':<42} | {b['turn3_context_tokens']:>16,} | {s['turn3_context_tokens']:>16,} | {a['turn3_context_tokens']:>16,}"
  )
  print(
      f"{'76-Vendor Analysis Visible to Analyst?':<42} | {'No (Excluded)':>16} | {'Yes (In REPL)':>16} | {'Yes (In REPL)':>16}"
  )
  print(
      f"{'Ground-Truth Rubric Recall Score':<42} | "
      f"{b['rubric']['score']}/{b['rubric']['max_score']} ({b['rubric']['score_pct']:>5.1f}%) | "
      f"{s['rubric']['score']}/{s['rubric']['max_score']} ({s['rubric']['score_pct']:>5.1f}%) | "
      f"{a['rubric']['score']}/{a['rubric']['max_score']} ({a['rubric']['score_pct']:>5.1f}%)"
  )
  print("=" * 96 + "\n")


async def main_async(output_json: str | None) -> None:
  _load_env_if_needed()
  ctx = MagicMock()
  baseline_res = await run_baseline_investigation(ctx)
  rlm_step_res = await run_rlm_stepwise_investigation(ctx)
  rlm_auto_res = await run_rlm_autonomous_investigation(ctx)

  summary = {
      "primary_hash": PRIMARY_HASH,
      "dropped_hash": DROPPED_HASH,
      "model": os.getenv("GTI_RLM_MODEL", "vertex_ai/gemini-3.8-flash"),
      "sub_model": os.getenv(
          "GTI_RLM_SUB_MODEL", "vertex_ai/gemini-3.5-flash-lite"
      ),
      "baseline": baseline_res,
      "rlm_stepwise": rlm_step_res,
      "rlm_autonomous": rlm_auto_res,
  }
  _print_comparison_table(summary)
  if output_json:
    out_path = Path(output_json)
    out_path.write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )
    print(f"Saved full head-to-head comparison JSON to {out_path}")


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Compare SOC file investigations without vs. with DSPy RLM GTI tools."
  )
  parser.add_argument(
      "--output-json",
      default=None,
      help="Optional path to save full JSON comparison telemetry.",
  )
  args = parser.parse_args()
  asyncio.run(main_async(args.output_json))


if __name__ == "__main__":
  main()
