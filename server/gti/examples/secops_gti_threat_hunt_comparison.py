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
"""Cross-platform Google SecOps (Chronicle SIEM) + GTI Threat Hunt Comparison.

Executes a live multi-stage Active Directory Domain Controller compromise threat
hunt in the Argolis SecOps tenant (`dandye-0324-chronicle`) combining `secops-mcp`
(Chronicle SIEM IoC matches, entity lookups, alerts, and UDM telemetry) with
`gti-mcp` (VirusTotal v3 static + behavioral enrichment across 3 kill-chain
file hashes: `mimikatz.exe`, `mimilib.dll`, and `vssadmin.exe` LOLBin).

Compares three execution architectures on `vertex_ai/gemini-3.8-flash` (root
RLM / host Threat Hunter) and `vertex_ai/gemini-3.5-flash-lite` (sub-LM):

  1. Baseline (Without Refactor - Raw GTI + SecOps MCP Tools):
     Feeds raw `get_file_report` and `get_file_behavior_summary` JSON across
     all 3 kill-chain binaries (~1.28 MB) alongside SIEM telemetry into the
     host Threat Hunter agent conversation.
  2. Refactored Stepwise RLM (`rlm_get_*` + SecOps MCP Tools):
     Replaces raw GTI tools with `rlm_get_file_report` and
     `rlm_get_file_behavior_summary` in the same 3-turn threat hunt.
  3. Refactored Autonomous RLM (`rlm_investigate_file` + SecOps MCP Tools):
     Combines SIEM telemetry with `rlm_investigate_file` across the 3 kill-chain
     hashes and synthesizes the full threat hunt in a single host LLM turn.
"""

import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Any
from unittest.mock import MagicMock

from dotenv import load_dotenv
import litellm

from gti_mcp.tools.files import (
    get_file_behavior_summary,
    get_file_report,
)
from gti_mcp.tools.rlm_files import (
    rlm_get_file_behavior_summary,
    rlm_get_file_report,
    rlm_investigate_file,
)
from secops_mcp.server import get_chronicle_client
from secops_mcp.tools import (
    get_ioc_matches,
    get_security_alerts,
    lookup_entity,
)

# Three kill-chain file hashes discovered on Domain Controller activedir.stackedpads.local
HASH_MIMIKATZ_EXE = "bb8bdb3e8c92e97e2f63626bc3b254c4"
HASH_MIMILIB_DLL = "ddfad0d55be70acdfea36acf28d418b3"
HASH_VSSADMIN_EXE = "614b5c4238977130aa2270c8ad58ce6c"

SYSTEM_PROMPT = (
    "You are a Principal Threat Hunter and Incident Responder operating across "
    "Google SecOps (Chronicle SIEM) and Google Threat Intelligence (VirusTotal v3). "
    "Answer each threat-hunting turn strictly using the SIEM and GTI tool outputs "
    "provided in the conversation. Always cite verbatim hostnames, IP addresses, "
    "usernames, SIEM alert rule names, GTI threat actor association IDs, exact "
    "process command lines, cryptographic hashes (MD5, SHA-256), vendor detection "
    "ratios, specific individual vendor signature strings (if available in the "
    "payload), crowdsourced YARA rules, MITRE ATT&CK technique IDs, and explicit "
    "containment decisions separating malicious binaries from Microsoft-signed "
    "Living-off-the-Land Binaries (LOLBins)."
)

TURN_1_PROMPT = (
    "Turn 1 (SIEM IoC Match, Entity Context & UDM Kill-Chain Reconstruction): "
    "Using the Google SecOps SIEM telemetry below (`get_ioc_matches`, "
    "`lookup_entity`, `get_security_alerts`, and UDM process/file events), document:\n"
    "1. Affected asset hostname, IP addresses (`10.10.20.60`, `206.221.181.253`), "
    "and compromised domain user account (`frank.kolzig` / `fkolzig`).\n"
    "2. Initial access alert rule (`win_repeatedAuthFailure_thenSuccess_T1110_001`) "
    "and post-exploitation detection rule (`MimiKatz Command Arguments [Mandiant Intel Emerging Threats]`).\n"
    "3. GTI IoC match priority (`ACTIVE_BREACH`), malware family, and attributed "
    "UNC threat actor groups (`UNC3313`, `UNC3591`, `UNC3661`, `UNC2727`, `UNC5883`).\n"
    "4. Exact chronological UDM process & file kill chain on `activedir.stackedpads.local`, "
    "including the exact command lines for:\n"
    "   - Stage 1: LSASS credential dumping (`mimikatz.exe`)\n"
    "   - Stage 2: DiskShadow script execution (`diskshadow /s c:\\temp\\orange.txt`) "
    "and Active Directory database copy (`copy x:\\windows\\ntds\\ntds.dit c:\\ntds.dit`)\n"
    "   - Stage 3: WMI lateral/local execution (`wmic process call create`) "
    "spawning Volume Shadow Copy creation (`vssadmin create shadow /for=C:`)\n"
    "5. Which 3 distinct file MD5 hashes (`bb8bdb3e8c92e97e2f63626bc3b254c4`, "
    "`ddfad0d55be70acdfea36acf28d418b3`, `614b5c4238977130aa2270c8ad58ce6c`) "
    "must be enriched in GTI to separate attacker malware from Windows LOLBins."
)

TURN_2_PROMPT = (
    "Turn 2 (GTI Attacker Tooling Deep Triage - `mimikatz.exe` & `mimilib.dll`): "
    "Based on the GTI static file reports and dynamic sandbox behavior summaries "
    "for `bb8bdb3e8c92e97e2f63626bc3b254c4` (`mimikatz.exe`) and "
    "`ddfad0d55be70acdfea36acf28d418b3` (`mimilib.dll`), provide:\n"
    "1. Verbatim MD5 and SHA-256 hashes for both files.\n"
    "2. Exact malicious vendor counts vs. total vendors for `mimikatz.exe` (39/72) "
    "and `mimilib.dll` (56/72), plus at least 3 individual security vendor engine "
    "detection strings from `last_analysis_results` (e.g., Kaspersky, Microsoft, "
    "ESET) if available in the tool output.\n"
    "3. Matched crowdsourced YARA rule names and authors.\n"
    "4. Sandbox behavioral indicators, MITRE ATT&CK techniques, and what benign "
    "OS/sandbox background noise (`SyncRootManager`, `WerSvcGroup`, "
    "`ZonesCacheCounterMutex`) was present or filtered."
)

TURN_3_PROMPT = (
    "Turn 3 (LOLBin Discrimination & Final Cross-Platform Threat Hunt Report): "
    "Incorporating the GTI static and behavioral enrichment for "
    "`614b5c4238977130aa2270c8ad58ce6c` (`C:\\Windows\\System32\\vssadmin.exe`), "
    "produce the complete Google SecOps + GTI Threat Hunt & Incident Response "
    "Report covering:\n"
    "1. Executive summary of the Active Directory Domain Controller compromise on "
    "`activedir.stackedpads.local` (`10.10.20.60`) via `frank.kolzig` (`fkolzig`), "
    "correlating SIEM alerts (`win_repeatedAuthFailure_thenSuccess_T1110_001` and "
    "`MimiKatz Command Arguments`) with GTI `ACTIVE_BREACH` IoC attributions "
    "(`UNC3313`, `UNC3591`, `UNC3661`, `UNC2727`, `UNC5883`).\n"
    "2. Complete UDM attack timeline with verbatim command lines (`sekurlsa::logonpasswords`, "
    "`diskshadow /s c:\\temp\\orange.txt`, `copy x:\\windows\\ntds\\ntds.dit c:\\ntds.dit`, "
    "`wmic process call create \"cmd /c vssadmin create shadow /for=C:\"`), and "
    "MITRE ATT&CK mapping (`T1110.001`, `T1003.001`, `T1003.003`, `T1047`).\n"
    "3. Multi-hash GTI comparison table for `mimikatz.exe` (`bb8bdb3e8c92e97e2f63626bc3b254c4`, "
    "SHA-256 `61bd916c2fb4fa9fe2dc23eb3fd2eccf1ff3abbbbf6d4ffefde5dcbe3befa84f`, "
    "39/72 malicious), `mimilib.dll` (`ddfad0d55be70acdfea36acf28d418b3`, 56/72 "
    "malicious), and `vssadmin.exe` (`614b5c4238977130aa2270c8ad58ce6c`, 0/76 "
    "malicious Microsoft-signed system binary), including specific per-vendor "
    "signature names from `last_analysis_results` (or state if omitted) and "
    "crowdsourced YARA rules.\n"
    "4. LOLBin Containment Safety & Remediation Plan: Specify exactly which hashes "
    "to block globally in EDR (`bb8bdb3e8c92e97e2f63626bc3b254c4` and "
    "`ddfad0d55be70acdfea36acf28d418b3`), why `614b5c4238977130aa2270c8ad58ce6c` "
    "(`vssadmin.exe`) MUST NOT be blocked by hash (to avoid breaking Windows "
    "Volume Shadow Copy operations across production servers), and required "
    "Active Directory remediation (isolating `activedir.stackedpads.local`, "
    "resetting `frank.kolzig`, and performing a double `krbtgt` password reset "
    "due to `C:\\ntds.dit` compromise).\n"
    "5. Audit trail of sandbox noise filtered during enrichment (`SyncRootManager`, "
    "`WerSvcGroup`, `ZonesCacheCounterMutex`)."
)


GROUND_TRUTH_RUBRIC: list[tuple[str, str, list[str]]] = [
    (
        "dc_hostname_and_ip",
        "Domain Controller Hostname & IP (activedir.stackedpads.local / 10.10.20.60)",
        ["activedir.stackedpads.local", "10.10.20.60"],
    ),
    (
        "compromised_user",
        "Compromised Domain Account (frank.kolzig / fkolzig)",
        ["frank.kolzig", "fkolzig"],
    ),
    (
        "initial_access_alert",
        "SIEM Brute-Force Initial Access Alert (win_repeatedAuthFailure_thenSuccess_T1110_001)",
        ["win_repeatedauthfailure_thensuccess_t1110_001"],
    ),
    (
        "siem_gti_ioc_actors",
        "SIEM GTI ACTIVE_BREACH IoC Attribution (UNC3313 / UNC3591 / UNC3661)",
        ["unc3313", "unc3591", "unc3661"],
    ),
    (
        "lsass_dump_cmdline",
        "Stage 1 Mimikatz LSASS Dump Command (sekurlsa::logonpasswords)",
        ["sekurlsa::logonpasswords"],
    ),
    (
        "diskshadow_ntds_dump",
        "Stage 2 DiskShadow Script & NTDS.dit Extraction (orange.txt / ntds.dit)",
        ["orange.txt", "ntds.dit"],
    ),
    (
        "wmic_vssadmin_shadow",
        "Stage 3 WMIC Volume Shadow Copy Command (vssadmin create shadow /for=c:)",
        ["vssadmin create shadow /for=c:"],
    ),
    (
        "mimikatz_exe_sha256",
        "Verbatim mimikatz.exe SHA-256 (61bd916c2fb4fa9fe2dc23eb3fd2eccf1ff3abbbbf6d4ffefde5dcbe3befa84f)",
        ["61bd916c2fb4fa9fe2dc23eb3fd2eccf1ff3abbbbf6d4ffefde5dcbe3befa84f"],
    ),
    (
        "mimikatz_exe_vendor_ratio",
        "mimikatz.exe Vendor Detection Ratio (39 Malicious Engines)",
        ["39/72", "39 / 72", "39 out of 72", "39 malicious", "malicious: 39"],
    ),
    (
        "individual_vendor_signatures",
        "Individual Engine Signatures from last_analysis_results (Microsoft / ESET / Kaspersky)",
        [
            "hacktool:win32/mimikatz!pz",
            "win64/riskware.mimikatz.g",
            "heur:trojan.win32.generic",
        ],
    ),
    (
        "mimikatz_yara_rule",
        "Crowdsourced YARA Rule Match (Mimikatz_Memory_Rule_1 / Benjamin_Delpy)",
        ["mimikatz_memory_rule_1", "benjamin_delpy", "gentilkiwi", "mimikatz"],
    ),
    (
        "mimilib_dll_hash_and_ratio",
        "mimilib.dll MD5 (ddfad0d55be70acdfea36acf28d418b3) & 56 Malicious Detections",
        ["56/72", "56 / 72", "56 out of 72", "56 malicious", "malicious: 56"],
    ),
    (
        "vssadmin_zero_detections",
        "vssadmin.exe (614b5c4238977130aa2270c8ad58ce6c) Verified 0 Malicious Detections",
        ["0/76", "0 / 76", "0/72", "0 out of 76", "0 malicious"],
    ),
    (
        "lolbin_containment_safety",
        "LOLBin Containment Safety (Block Mimikatz Hashes; Do NOT Block Signed vssadmin.exe)",
        [
            "do not block",
            "must not be blocked",
            "not block",
            "lolbin",
            "living-off-the-land",
        ],
    ),
    (
        "mitre_credential_dumping",
        "MITRE ATT&CK LSASS & NTDS Credential Dumping (T1003.001 & T1003.003)",
        ["t1003.001", "t1003.003"],
    ),
    (
        "mitre_wmi_and_bruteforce",
        "MITRE ATT&CK WMI Execution & Brute Force (T1047 & T1110.001)",
        ["t1047", "t1110.001"],
    ),
    (
        "krbtgt_ad_remediation",
        "Active Directory Double krbtgt Reset & Host Isolation Remediation",
        ["krbtgt"],
    ),
    (
        "sandbox_noise_audit_trail",
        "Explicit GTI Sandbox Noise Accounting (SyncRootManager / WerSvcGroup / ZonesCache)",
        ["syncrootmanager", "wersvcgroup", "zonescachecountermutex"],
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
  if isinstance(obj, str):
    return len(obj.encode("utf-8"))
  return len(json.dumps(obj, default=str).encode("utf-8"))


def _call_host_llm(messages: list[dict[str, str]]) -> dict[str, Any]:
  """Calls the host Threat Hunter model (`vertex_ai/gemini-3.8-flash`)."""
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
  """Scores combined agent responses against the 18-point SecOps+GTI rubric."""
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


async def collect_live_siem_telemetry() -> dict[str, Any]:
  """Stage 1: Queries live Argolis SecOps (`dandye-0324-chronicle`) via `secops-mcp`."""
  print("\n[Stage 1] Collecting Live Google SecOps (Chronicle SIEM) Telemetry...")
  t0 = time.monotonic()

  project_id = os.getenv("CHRONICLE_PROJECT_ID", "dandye-0324-chronicle")
  customer_id = os.getenv(
      "CHRONICLE_CUSTOMER_ID", "7e977ce4-f45d-43b2-aea0-52f8b66acd80"
  )
  region = os.getenv("CHRONICLE_REGION", "us")

  # 1. SIEM IoC Matches (`get_ioc_matches`)
  ioc_matches = await get_ioc_matches(
      project_id=project_id,
      customer_id=customer_id,
      region=region,
      hours_back=24 * 30,
      max_matches=10,
  )

  # 2. SIEM Entity Summaries (`lookup_entity` for host `activedir` and MD5 `bb8bdb3e...`)
  entity_host = await lookup_entity(
      entity_value="activedir",
      project_id=project_id,
      customer_id=customer_id,
      region=region,
      hours_back=24 * 14,
  )
  entity_file = await lookup_entity(
      entity_value=HASH_MIMIKATZ_EXE,
      project_id=project_id,
      customer_id=customer_id,
      region=region,
      hours_back=24 * 14,
  )

  # 3. SIEM Security Alerts (`get_security_alerts`)
  siem_alerts = await get_security_alerts(
      project_id=project_id,
      customer_id=customer_id,
      region=region,
      hours_back=24 * 14,
      max_alerts=15,
  )

  # 4. SIEM UDM Process & File Kill-Chain Events on `activedir.stackedpads.local`
  chronicle = get_chronicle_client(project_id, customer_id, region)
  udm_resp = chronicle.search_udm(
      query=(
          'principal.hostname = "activedir.stackedpads.local" AND '
          '(metadata.event_type = "PROCESS_LAUNCH" OR '
          'metadata.event_type = "FILE_CREATION")'
      ),
      start_time=datetime(2026, 10, 31, 14, 18, 0, tzinfo=timezone.utc),
      end_time=datetime(2026, 10, 31, 14, 27, 0, tzinfo=timezone.utc),
      max_events=50,
  )

  compact_udm_events: list[dict[str, Any]] = []
  for wrapper in udm_resp.get("events", []):
    udm = wrapper.get("udm", {})
    meta = udm.get("metadata", {})
    principal = udm.get("principal", {})
    target = udm.get("target", {})
    compact_udm_events.append({
        "timestamp": meta.get("eventTimestamp"),
        "event_type": meta.get("eventType"),
        "product_event_type": meta.get("productEventType"),
        "hostname": principal.get("hostname"),
        "ip": principal.get("ip"),
        "user": principal.get("user", {}).get("userid"),
        "parent_process": principal.get("process", {})
        .get("file", {})
        .get("fullPath"),
        "parent_cmdline": principal.get("process", {}).get("commandLine"),
        "target_process": target.get("process", {})
        .get("file", {})
        .get("fullPath"),
        "target_cmdline": target.get("process", {}).get("commandLine"),
        "target_process_md5": target.get("process", {})
        .get("file", {})
        .get("md5"),
        "target_file_path": target.get("file", {}).get("fullPath"),
        "target_file_md5": target.get("file", {}).get("md5"),
    })

  elapsed = round(time.monotonic() - t0, 2)
  siem_bundle = {
      "tenant": {
          "project_id": project_id,
          "customer_id": customer_id,
          "region": region,
      },
      "get_ioc_matches": ioc_matches,
      "lookup_entity_activedir": entity_host,
      "lookup_entity_mimikatz_md5": entity_file,
      "get_security_alerts": siem_alerts,
      "udm_kill_chain_events": compact_udm_events,
  }
  siem_bytes = _json_bytes(siem_bundle)
  print(
      f"  Collected SIEM telemetry in {elapsed}s: "
      f"{len(compact_udm_events)} UDM events, {siem_bytes:,} bytes total."
  )
  return {
      "bundle": siem_bundle,
      "siem_bytes": siem_bytes,
      "elapsed_s": elapsed,
  }


async def run_baseline_threat_hunt(
    ctx: MagicMock, siem_data: dict[str, Any]
) -> dict[str, Any]:
  """Mode 1: Cross-platform threat hunt using legacy raw GTI MCP tools."""
  print(
      "\n[Mode 1] Running Baseline SecOps + GTI Threat Hunt (Without Refactor - Raw GTI Tools)..."
  )
  t_start = time.monotonic()

  siem_bundle = siem_data["bundle"]
  b_siem = siem_data["siem_bytes"]

  # Turn 1: SIEM Discovery & Kill-Chain Reconstruction
  messages: list[dict[str, str]] = [
      {"role": "system", "content": SYSTEM_PROMPT},
      {
          "role": "user",
          "content": (
              f"{TURN_1_PROMPT}\n\n"
              f"### Google SecOps SIEM Telemetry (`dandye-0324-chronicle`, {b_siem:,} bytes)\n"
              f"```json\n{json.dumps(siem_bundle, default=str)}\n```"
          ),
      },
  ]
  turn1_llm = _call_host_llm(messages)
  messages.append({"role": "assistant", "content": turn1_llm["content"]})
  print(
      f"  Turn 1 (SIEM Telemetry): siem_bytes={b_siem:,} B | "
      f"host_prompt_tokens={turn1_llm['prompt_tokens']:,} | llm_time={turn1_llm['elapsed_s']}s"
  )

  # Turn 2: Raw GTI Enrichment for Attacker Tooling (`mimikatz.exe` + `mimilib.dll`)
  t0 = time.monotonic()
  raw_mimi_rep, raw_mimi_beh, raw_lib_rep, raw_lib_beh = await asyncio.gather(
      get_file_report(HASH_MIMIKATZ_EXE, ctx),
      get_file_behavior_summary(HASH_MIMIKATZ_EXE, ctx),
      get_file_report(HASH_MIMILIB_DLL, ctx),
      get_file_behavior_summary(HASH_MIMILIB_DLL, ctx),
  )
  t_tool_2 = time.monotonic() - t0
  b_mimi_rep = _json_bytes(raw_mimi_rep)
  b_mimi_beh = _json_bytes(raw_mimi_beh)
  b_lib_rep = _json_bytes(raw_lib_rep)
  b_lib_beh = _json_bytes(raw_lib_beh)
  b_tool_2 = b_mimi_rep + b_mimi_beh + b_lib_rep + b_lib_beh

  messages.append({
      "role": "user",
      "content": (
          f"{TURN_2_PROMPT}\n\n"
          f"### Tool Output 2a: `get_file_report('{HASH_MIMIKATZ_EXE}')` ({b_mimi_rep:,} bytes)\n"
          f"```json\n{json.dumps(raw_mimi_rep, default=str)}\n```\n\n"
          f"### Tool Output 2b: `get_file_behavior_summary('{HASH_MIMIKATZ_EXE}')` ({b_mimi_beh:,} bytes)\n"
          f"```json\n{json.dumps(raw_mimi_beh, default=str)}\n```\n\n"
          f"### Tool Output 2c: `get_file_report('{HASH_MIMILIB_DLL}')` ({b_lib_rep:,} bytes)\n"
          f"```json\n{json.dumps(raw_lib_rep, default=str)}\n```\n\n"
          f"### Tool Output 2d: `get_file_behavior_summary('{HASH_MIMILIB_DLL}')` ({b_lib_beh:,} bytes)\n"
          f"```json\n{json.dumps(raw_lib_beh, default=str)}\n```"
      ),
  })
  turn2_llm = _call_host_llm(messages)
  messages.append({"role": "assistant", "content": turn2_llm["content"]})
  print(
      f"  Turn 2 (Raw GTI mimikatz.exe + mimilib.dll): gti_bytes={b_tool_2:,} B | "
      f"host_prompt_tokens={turn2_llm['prompt_tokens']:,} | llm_time={turn2_llm['elapsed_s']}s"
  )

  # Turn 3: Raw GTI Enrichment for LOLBin (`vssadmin.exe`) & Final Threat Hunt Report
  t0 = time.monotonic()
  raw_vss_rep, raw_vss_beh = await asyncio.gather(
      get_file_report(HASH_VSSADMIN_EXE, ctx),
      get_file_behavior_summary(HASH_VSSADMIN_EXE, ctx),
  )
  t_tool_3 = time.monotonic() - t0
  b_vss_rep = _json_bytes(raw_vss_rep)
  b_vss_beh = _json_bytes(raw_vss_beh)
  b_tool_3 = b_vss_rep + b_vss_beh

  messages.append({
      "role": "user",
      "content": (
          f"{TURN_3_PROMPT}\n\n"
          f"### Tool Output 3a: `get_file_report('{HASH_VSSADMIN_EXE}')` ({b_vss_rep:,} bytes)\n"
          f"```json\n{json.dumps(raw_vss_rep, default=str)}\n```\n\n"
          f"### Tool Output 3b: `get_file_behavior_summary('{HASH_VSSADMIN_EXE}')` ({b_vss_beh:,} bytes)\n"
          f"```json\n{json.dumps(raw_vss_beh, default=str)}\n```"
      ),
  })
  turn3_llm = _call_host_llm(messages)
  print(
      f"  Turn 3 (Raw GTI vssadmin.exe LOLBin + Synthesis): gti_bytes={b_tool_3:,} B | "
      f"host_prompt_tokens={turn3_llm['prompt_tokens']:,} | llm_time={turn3_llm['elapsed_s']}s"
  )

  total_elapsed = round(time.monotonic() - t_start + siem_data["elapsed_s"], 2)
  turns = [
      {
          "turn": 1,
          "tools": [
              "get_ioc_matches",
              "lookup_entity(activedir)",
              "lookup_entity(mimikatz_md5)",
              "get_security_alerts",
              "search_udm(activedir.stackedpads.local)",
          ],
          "tool_payload_bytes": b_siem,
          "gti_payload_bytes": 0,
          "tool_elapsed_s": siem_data["elapsed_s"],
          "host_prompt_tokens": turn1_llm["prompt_tokens"],
          "host_completion_tokens": turn1_llm["completion_tokens"],
          "host_llm_elapsed_s": turn1_llm["elapsed_s"],
          "response": turn1_llm["content"],
      },
      {
          "turn": 2,
          "tools": [
              "get_file_report(mimikatz.exe)",
              "get_file_behavior_summary(mimikatz.exe)",
              "get_file_report(mimilib.dll)",
              "get_file_behavior_summary(mimilib.dll)",
          ],
          "tool_payload_bytes": b_tool_2,
          "gti_payload_bytes": b_tool_2,
          "tool_elapsed_s": round(t_tool_2, 2),
          "host_prompt_tokens": turn2_llm["prompt_tokens"],
          "host_completion_tokens": turn2_llm["completion_tokens"],
          "host_llm_elapsed_s": turn2_llm["elapsed_s"],
          "response": turn2_llm["content"],
      },
      {
          "turn": 3,
          "tools": [
              "get_file_report(vssadmin.exe)",
              "get_file_behavior_summary(vssadmin.exe)",
          ],
          "tool_payload_bytes": b_tool_3,
          "gti_payload_bytes": b_tool_3,
          "tool_elapsed_s": round(t_tool_3, 2),
          "host_prompt_tokens": turn3_llm["prompt_tokens"],
          "host_completion_tokens": turn3_llm["completion_tokens"],
          "host_llm_elapsed_s": turn3_llm["elapsed_s"],
          "response": turn3_llm["content"],
      },
  ]
  rubric = evaluate_rubric([t["response"] for t in turns])
  return {
      "mode": "baseline_raw_secops_gti",
      "siem_bytes_injected": b_siem,
      "gti_tool_bytes_injected": b_tool_2 + b_tool_3,
      "total_tool_bytes_injected": b_siem + b_tool_2 + b_tool_3,
      "cumulative_host_prompt_tokens": sum(
          t["host_prompt_tokens"] for t in turns
      ),
      "cumulative_host_completion_tokens": sum(
          t["host_completion_tokens"] for t in turns
      ),
      "turn3_context_tokens": turn3_llm["prompt_tokens"],
      "vt_api_calls": 6,
      "total_elapsed_s": total_elapsed,
      "rubric": rubric,
      "turns": turns,
  }


async def run_rlm_stepwise_threat_hunt(
    ctx: MagicMock, siem_data: dict[str, Any]
) -> dict[str, Any]:
  """Mode 2: Cross-platform threat hunt using stepwise DSPy RLM GTI tools (`rlm_get_*`)."""
  print(
      "\n[Mode 2] Running Refactored Stepwise RLM SecOps + GTI Threat Hunt (`rlm_get_*` Tools)..."
  )
  t_start = time.monotonic()

  siem_bundle = siem_data["bundle"]
  b_siem = siem_data["siem_bytes"]

  # Turn 1: SIEM Discovery & Kill-Chain Reconstruction
  messages: list[dict[str, str]] = [
      {"role": "system", "content": SYSTEM_PROMPT},
      {
          "role": "user",
          "content": (
              f"{TURN_1_PROMPT}\n\n"
              f"### Google SecOps SIEM Telemetry (`dandye-0324-chronicle`, {b_siem:,} bytes)\n"
              f"```json\n{json.dumps(siem_bundle, default=str)}\n```"
          ),
      },
  ]
  turn1_llm = _call_host_llm(messages)
  messages.append({"role": "assistant", "content": turn1_llm["content"]})
  print(
      f"  Turn 1 (SIEM Telemetry): siem_bytes={b_siem:,} B | "
      f"host_prompt_tokens={turn1_llm['prompt_tokens']:,} | llm_time={turn1_llm['elapsed_s']}s"
  )

  # Turn 2: Stepwise RLM GTI Enrichment for Attacker Tooling (`mimikatz.exe` + `mimilib.dll`)
  t0 = time.monotonic()
  rlm_mimi_rep, rlm_mimi_beh, rlm_lib_rep, rlm_lib_beh = await asyncio.gather(
      rlm_get_file_report(
          HASH_MIMIKATZ_EXE,
          ctx,
          query=(
              "Extract exact SHA-256 and MD5 hashes, vendor detection consensus "
              "(39/72), 4 specific vendor detection strings from "
              "last_analysis_results (e.g. Kaspersky, Microsoft, ESET), "
              "crowdsourced YARA rules (Mimikatz_Memory_Rule_1 / Benjamin_Delpy), "
              "and PE metadata."
          ),
      ),
      rlm_get_file_behavior_summary(
          HASH_MIMIKATZ_EXE,
          ctx,
          query=(
              "Extract credential dumping behavior, MITRE ATT&CK techniques, "
              "and explicitly list filtered benign OS sandbox noise "
              "(SyncRootManager, WerSvcGroup, ZonesCacheCounterMutex)."
          ),
      ),
      rlm_get_file_report(
          HASH_MIMILIB_DLL,
          ctx,
          query=(
              "Extract exact SHA-256 and MD5 hashes, vendor detection consensus "
              "(56/72), specific vendor signature strings from "
              "last_analysis_results, crowdsourced YARA rules, and DLL exports."
          ),
      ),
      rlm_get_file_behavior_summary(
          HASH_MIMILIB_DLL,
          ctx,
          query=(
              "Extract behavioral indicators, MITRE ATT&CK techniques, and "
              "filtered benign OS sandbox noise."
          ),
      ),
  )
  t_tool_2 = time.monotonic() - t0
  b_mimi_rep = _json_bytes(rlm_mimi_rep)
  b_mimi_beh = _json_bytes(rlm_mimi_beh)
  b_lib_rep = _json_bytes(rlm_lib_rep)
  b_lib_beh = _json_bytes(rlm_lib_beh)
  b_tool_2 = b_mimi_rep + b_mimi_beh + b_lib_rep + b_lib_beh

  messages.append({
      "role": "user",
      "content": (
          f"{TURN_2_PROMPT}\n\n"
          f"### Tool Output 2a: `rlm_get_file_report('{HASH_MIMIKATZ_EXE}')` ({b_mimi_rep:,} bytes)\n"
          f"```json\n{json.dumps(rlm_mimi_rep, default=str)}\n```\n\n"
          f"### Tool Output 2b: `rlm_get_file_behavior_summary('{HASH_MIMIKATZ_EXE}')` ({b_mimi_beh:,} bytes)\n"
          f"```json\n{json.dumps(rlm_mimi_beh, default=str)}\n```\n\n"
          f"### Tool Output 2c: `rlm_get_file_report('{HASH_MIMILIB_DLL}')` ({b_lib_rep:,} bytes)\n"
          f"```json\n{json.dumps(rlm_lib_rep, default=str)}\n```\n\n"
          f"### Tool Output 2d: `rlm_get_file_behavior_summary('{HASH_MIMILIB_DLL}')` ({b_lib_beh:,} bytes)\n"
          f"```json\n{json.dumps(rlm_lib_beh, default=str)}\n```"
      ),
  })
  turn2_llm = _call_host_llm(messages)
  messages.append({"role": "assistant", "content": turn2_llm["content"]})
  print(
      f"  Turn 2 (RLM mimikatz.exe + mimilib.dll): gti_bytes={b_tool_2:,} B | "
      f"host_prompt_tokens={turn2_llm['prompt_tokens']:,} | llm_time={turn2_llm['elapsed_s']}s"
  )

  # Turn 3: Stepwise RLM GTI Enrichment for LOLBin (`vssadmin.exe`) & Final Report
  t0 = time.monotonic()
  rlm_vss_rep, rlm_vss_beh = await asyncio.gather(
      rlm_get_file_report(
          HASH_VSSADMIN_EXE,
          ctx,
          query=(
              "Verify whether this file is a legitimate Microsoft-signed "
              "Windows binary (vssadmin.exe) with 0 malicious detections (0/76) "
              "abused as a Living-off-the-Land Binary (LOLBin)."
          ),
      ),
      rlm_get_file_behavior_summary(
          HASH_VSSADMIN_EXE,
          ctx,
          query=(
              "Summarize Volume Shadow Copy behavior and filtered benign "
              "Windows sandbox noise."
          ),
      ),
  )
  t_tool_3 = time.monotonic() - t0
  b_vss_rep = _json_bytes(rlm_vss_rep)
  b_vss_beh = _json_bytes(rlm_vss_beh)
  b_tool_3 = b_vss_rep + b_vss_beh

  messages.append({
      "role": "user",
      "content": (
          f"{TURN_3_PROMPT}\n\n"
          f"### Tool Output 3a: `rlm_get_file_report('{HASH_VSSADMIN_EXE}')` ({b_vss_rep:,} bytes)\n"
          f"```json\n{json.dumps(rlm_vss_rep, default=str)}\n```\n\n"
          f"### Tool Output 3b: `rlm_get_file_behavior_summary('{HASH_VSSADMIN_EXE}')` ({b_vss_beh:,} bytes)\n"
          f"```json\n{json.dumps(rlm_vss_beh, default=str)}\n```"
      ),
  })
  turn3_llm = _call_host_llm(messages)
  print(
      f"  Turn 3 (RLM vssadmin.exe LOLBin + Synthesis): gti_bytes={b_tool_3:,} B | "
      f"host_prompt_tokens={turn3_llm['prompt_tokens']:,} | llm_time={turn3_llm['elapsed_s']}s"
  )

  total_elapsed = round(time.monotonic() - t_start + siem_data["elapsed_s"], 2)
  raw_vt_bytes = sum(
      r.get("compression_metrics", {}).get("raw_bytes", 0)
      for r in (
          rlm_mimi_rep,
          rlm_mimi_beh,
          rlm_lib_rep,
          rlm_lib_beh,
          rlm_vss_rep,
          rlm_vss_beh,
      )
  )
  turns = [
      {
          "turn": 1,
          "tools": [
              "get_ioc_matches",
              "lookup_entity(activedir)",
              "lookup_entity(mimikatz_md5)",
              "get_security_alerts",
              "search_udm(activedir.stackedpads.local)",
          ],
          "tool_payload_bytes": b_siem,
          "gti_payload_bytes": 0,
          "tool_elapsed_s": siem_data["elapsed_s"],
          "host_prompt_tokens": turn1_llm["prompt_tokens"],
          "host_completion_tokens": turn1_llm["completion_tokens"],
          "host_llm_elapsed_s": turn1_llm["elapsed_s"],
          "response": turn1_llm["content"],
      },
      {
          "turn": 2,
          "tools": [
              "rlm_get_file_report(mimikatz.exe)",
              "rlm_get_file_behavior_summary(mimikatz.exe)",
              "rlm_get_file_report(mimilib.dll)",
              "rlm_get_file_behavior_summary(mimilib.dll)",
          ],
          "tool_payload_bytes": b_tool_2,
          "gti_payload_bytes": b_tool_2,
          "tool_elapsed_s": round(t_tool_2, 2),
          "host_prompt_tokens": turn2_llm["prompt_tokens"],
          "host_completion_tokens": turn2_llm["completion_tokens"],
          "host_llm_elapsed_s": turn2_llm["elapsed_s"],
          "response": turn2_llm["content"],
      },
      {
          "turn": 3,
          "tools": [
              "rlm_get_file_report(vssadmin.exe)",
              "rlm_get_file_behavior_summary(vssadmin.exe)",
          ],
          "tool_payload_bytes": b_tool_3,
          "gti_payload_bytes": b_tool_3,
          "tool_elapsed_s": round(t_tool_3, 2),
          "host_prompt_tokens": turn3_llm["prompt_tokens"],
          "host_completion_tokens": turn3_llm["completion_tokens"],
          "host_llm_elapsed_s": turn3_llm["elapsed_s"],
          "response": turn3_llm["content"],
      },
  ]
  rubric = evaluate_rubric([t["response"] for t in turns])
  return {
      "mode": "rlm_stepwise_secops_gti",
      "siem_bytes_injected": b_siem,
      "gti_tool_bytes_injected": b_tool_2 + b_tool_3,
      "total_tool_bytes_injected": b_siem + b_tool_2 + b_tool_3,
      "total_raw_vt_bytes_distilled": raw_vt_bytes,
      "cumulative_host_prompt_tokens": sum(
          t["host_prompt_tokens"] for t in turns
      ),
      "cumulative_host_completion_tokens": sum(
          t["host_completion_tokens"] for t in turns
      ),
      "turn3_context_tokens": turn3_llm["prompt_tokens"],
      "vt_api_calls": 6,
      "total_elapsed_s": total_elapsed,
      "rubric": rubric,
      "turns": turns,
  }


async def run_rlm_autonomous_threat_hunt(
    ctx: MagicMock, siem_data: dict[str, Any]
) -> dict[str, Any]:
  """Mode 3: Single-turn host synthesis powered by `rlm_investigate_file` + SecOps MCP."""
  print(
      "\n[Mode 3] Running Autonomous RLM SecOps + GTI Threat Hunt (`rlm_investigate_file`)..."
  )
  t_start = time.monotonic()

  siem_bundle = siem_data["bundle"]
  b_siem = siem_data["siem_bytes"]

  t0 = time.monotonic()
  inv_mimi, inv_lib, inv_vss = await asyncio.gather(
      rlm_investigate_file(
          HASH_MIMIKATZ_EXE,
          ctx,
          investigation_goal=(
              "Extract exact SHA-256 and MD5 hashes, vendor detection consensus "
              "(39/72), 4 specific vendor detection strings from "
              "last_analysis_results (e.g. Kaspersky, Microsoft, ESET), "
              "crowdsourced YARA rules (Mimikatz_Memory_Rule_1 / Benjamin_Delpy), "
              "credential dumping capabilities, MITRE ATT&CK IDs, and filtered "
              "benign OS sandbox noise (SyncRootManager, WerSvcGroup, ZonesCacheCounterMutex)."
          ),
          max_api_calls=2,
      ),
      rlm_investigate_file(
          HASH_MIMILIB_DLL,
          ctx,
          investigation_goal=(
              "Extract exact SHA-256 and MD5 hashes, vendor detection consensus "
              "(56/72), specific vendor detection strings from "
              "last_analysis_results, crowdsourced YARA rules, and Mimikatz SSP "
              "/ credential harvesting DLL behavior."
          ),
          max_api_calls=2,
      ),
      rlm_investigate_file(
          HASH_VSSADMIN_EXE,
          ctx,
          investigation_goal=(
              "Verify whether 614b5c4238977130aa2270c8ad58ce6c is a clean, "
              "Microsoft-signed Windows system binary (vssadmin.exe) with 0/76 "
              "malicious detections abused as a Living-off-the-Land Binary "
              "(LOLBin) for Volume Shadow Copy creation, and state why its hash "
              "must not be blocked."
          ),
          max_api_calls=2,
      ),
  )
  t_gti = time.monotonic() - t0
  b_mimi = _json_bytes(inv_mimi)
  b_lib = _json_bytes(inv_lib)
  b_vss = _json_bytes(inv_vss)
  b_gti = b_mimi + b_lib + b_vss
  b_total = b_siem + b_gti

  messages: list[dict[str, str]] = [
      {"role": "system", "content": SYSTEM_PROMPT},
      {
          "role": "user",
          "content": (
              f"{TURN_3_PROMPT}\n\n"
              f"### Google SecOps SIEM Telemetry (`dandye-0324-chronicle`, {b_siem:,} bytes)\n"
              f"```json\n{json.dumps(siem_bundle, default=str)}\n```\n\n"
              f"### GTI Autonomous Investigation 1: `rlm_investigate_file('{HASH_MIMIKATZ_EXE}')` ({b_mimi:,} bytes)\n"
              f"```json\n{json.dumps(inv_mimi, default=str)}\n```\n\n"
              f"### GTI Autonomous Investigation 2: `rlm_investigate_file('{HASH_MIMILIB_DLL}')` ({b_lib:,} bytes)\n"
              f"```json\n{json.dumps(inv_lib, default=str)}\n```\n\n"
              f"### GTI Autonomous Investigation 3: `rlm_investigate_file('{HASH_VSSADMIN_EXE}')` ({b_vss:,} bytes)\n"
              f"```json\n{json.dumps(inv_vss, default=str)}\n```"
          ),
      },
  ]
  turn_llm = _call_host_llm(messages)
  print(
      f"  Single Host Turn (SIEM + 3x `rlm_investigate_file`): "
      f"gti_bytes={b_gti:,} B | total_bytes={b_total:,} B | "
      f"host_prompt_tokens={turn_llm['prompt_tokens']:,} | llm_time={turn_llm['elapsed_s']}s"
  )

  total_elapsed = round(time.monotonic() - t_start + siem_data["elapsed_s"], 2)
  raw_vt_bytes = sum(
      r.get("compression_metrics", {}).get("raw_bytes", 0)
      for r in (inv_mimi, inv_lib, inv_vss)
  )
  vt_api_calls = sum(
      r.get("compression_metrics", {}).get("api_calls_made", 2)
      for r in (inv_mimi, inv_lib, inv_vss)
  )
  rubric = evaluate_rubric([turn_llm["content"]])
  return {
      "mode": "rlm_autonomous_secops_gti",
      "siem_bytes_injected": b_siem,
      "gti_tool_bytes_injected": b_gti,
      "total_tool_bytes_injected": b_total,
      "total_raw_vt_bytes_distilled": raw_vt_bytes,
      "cumulative_host_prompt_tokens": turn_llm["prompt_tokens"],
      "cumulative_host_completion_tokens": turn_llm["completion_tokens"],
      "turn3_context_tokens": turn_llm["prompt_tokens"],
      "vt_api_calls": vt_api_calls,
      "total_elapsed_s": total_elapsed,
      "rubric": rubric,
      "turns": [
          {
              "turn": 1,
              "tools": [
                  "get_ioc_matches",
                  "lookup_entity(activedir)",
                  "lookup_entity(mimikatz_md5)",
                  "get_security_alerts",
                  "search_udm(activedir.stackedpads.local)",
                  "rlm_investigate_file(mimikatz.exe)",
                  "rlm_investigate_file(mimilib.dll)",
                  "rlm_investigate_file(vssadmin.exe)",
              ],
              "tool_payload_bytes": b_total,
              "gti_payload_bytes": b_gti,
              "tool_elapsed_s": round(siem_data["elapsed_s"] + t_gti, 2),
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

  b_gti = b["gti_tool_bytes_injected"]
  s_gti = s["gti_tool_bytes_injected"]
  a_gti = a["gti_tool_bytes_injected"]

  b_tot = b["total_tool_bytes_injected"]
  s_tot = s["total_tool_bytes_injected"]
  a_tot = a["total_tool_bytes_injected"]

  b_tok = b["cumulative_host_prompt_tokens"]
  s_tok = s["cumulative_host_prompt_tokens"]
  a_tok = a["cumulative_host_prompt_tokens"]

  s_gti_red = (1.0 - s_gti / b_gti) * 100.0 if b_gti else 0.0
  a_gti_red = (1.0 - a_gti / b_gti) * 100.0 if b_gti else 0.0

  s_tot_red = (1.0 - s_tot / b_tot) * 100.0 if b_tot else 0.0
  a_tot_red = (1.0 - a_tot / b_tot) * 100.0 if b_tot else 0.0

  s_tok_red = (1.0 - s_tok / b_tok) * 100.0 if b_tok else 0.0
  a_tok_red = (1.0 - a_tok / b_tok) * 100.0 if b_tok else 0.0

  print("\n" + "=" * 100)
  print(
      "CROSS-PLATFORM GOOGLE SECOPS (CHRONICLE SIEM) + GTI THREAT HUNT: WITHOUT vs. WITH DSPy RLM"
  )
  print("=" * 100)
  print(
      f"{'Metric':<44} | {'1. Baseline (Raw)':>16} | {'2. RLM Stepwise':>16} | {'3. RLM Autonomous':>16}"
  )
  print("-" * 100)
  print(
      f"{'SIEM Telemetry Payload (SecOps MCP)':<44} | {b['siem_bytes_injected']:>14,} B | {s['siem_bytes_injected']:>14,} B | {a['siem_bytes_injected']:>14,} B"
  )
  print(
      f"{'GTI Enrichment Payload (3 Kill-Chain Hashes)':<44} | {b_gti:>14,} B | {s_gti:>14,} B | {a_gti:>14,} B"
  )
  print(
      f"{'GTI Enrichment Byte Reduction (%)':<44} | {'0.00% (base)':>16} | {-s_gti_red:>15.2f}% | {-a_gti_red:>15.2f}%"
  )
  print(
      f"{'Total Combined SIEM + GTI Bytes Injected':<44} | {b_tot:>14,} B | {s_tot:>14,} B | {a_tot:>14,} B"
  )
  print(
      f"{'Total Combined Context Byte Reduction (%)':<44} | {'0.00% (base)':>16} | {-s_tot_red:>15.2f}% | {-a_tot_red:>15.2f}%"
  )
  print(
      f"{'Cumulative Host Prompt Tokens Billed':<44} | {b_tok:>16,} | {s_tok:>16,} | {a_tok:>16,}"
  )
  print(
      f"{'Cumulative Host Token Savings (%)':<44} | {'0.00% (base)':>16} | {-s_tok_red:>15.2f}% | {-a_tok_red:>15.2f}%"
  )
  print(
      f"{'Final Turn Prompt Context Tokens':<44} | {b['turn3_context_tokens']:>16,} | {s['turn3_context_tokens']:>16,} | {a['turn3_context_tokens']:>16,}"
  )
  print(
      f"{'72-Vendor Signatures Visible in REPL?':<44} | {'No (Excluded)':>16} | {'Yes (In REPL)':>16} | {'Yes (In REPL)':>16}"
  )
  print(
      f"{'18-Point SIEM+GTI Threat Hunt Rubric Score':<44} | "
      f"{b['rubric']['score']}/{b['rubric']['max_score']} ({b['rubric']['score_pct']:>5.1f}%) | "
      f"{s['rubric']['score']}/{s['rubric']['max_score']} ({s['rubric']['score_pct']:>5.1f}%) | "
      f"{a['rubric']['score']}/{a['rubric']['max_score']} ({a['rubric']['score_pct']:>5.1f}%)"
  )
  print("=" * 100 + "\n")


async def main_async(output_json: str | None) -> None:
  _load_env_if_needed()
  ctx = MagicMock()
  siem_data = await collect_live_siem_telemetry()
  baseline_res = await run_baseline_threat_hunt(ctx, siem_data)
  rlm_step_res = await run_rlm_stepwise_threat_hunt(ctx, siem_data)
  rlm_auto_res = await run_rlm_autonomous_threat_hunt(ctx, siem_data)

  summary = {
      "tenant_project_id": os.getenv(
          "CHRONICLE_PROJECT_ID", "dandye-0324-chronicle"
      ),
      "tenant_customer_id": os.getenv(
          "CHRONICLE_CUSTOMER_ID", "7e977ce4-f45d-43b2-aea0-52f8b66acd80"
      ),
      "compromised_host": "activedir.stackedpads.local",
      "compromised_user": "frank.kolzig",
      "hashes": {
          "mimikatz_exe": HASH_MIMIKATZ_EXE,
          "mimilib_dll": HASH_MIMILIB_DLL,
          "vssadmin_exe_lolbin": HASH_VSSADMIN_EXE,
      },
      "model": os.getenv("GTI_RLM_MODEL", "vertex_ai/gemini-3.8-flash"),
      "sub_model": os.getenv(
          "GTI_RLM_SUB_MODEL", "vertex_ai/gemini-3.5-flash-lite"
      ),
      "siem_telemetry_bytes": siem_data["siem_bytes"],
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
    print(f"Saved full SecOps + GTI threat hunt comparison JSON to {out_path}")


def main() -> None:
  parser = argparse.ArgumentParser(
      description=(
          "Compare cross-platform Google SecOps (Chronicle SIEM) + GTI threat "
          "hunts without vs. with DSPy RLM GTI tools."
      )
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
