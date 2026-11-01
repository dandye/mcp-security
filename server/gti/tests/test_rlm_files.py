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
"""Tests for DSPy RLM distillation engine and GTI RLM MCP tools."""

import json
import typing

import pytest

from gti_mcp import rlm_engine


SHA256_SAMPLE = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
SHA1_SAMPLE = "3395856ce81f2b7382dee72602f798b642f14140"
MD5_SAMPLE = "44d88612fea8a8f36de82e1278abb02f"
IMPHASH_SAMPLE = "f34d5f2d4577ed6d9ceec516c1f5a744"


def make_bloated_file_report() -> dict[str, typing.Any]:
  """Constructs a realistic 150KB+ bloated VirusTotal v3 file report fixture."""
  vendor_results = {
      f"Vendor_{i:02d}": {
          "category": "malicious" if i < 52 else "undetected",
          "engine_name": f"Vendor_{i:02d}",
          "engine_version": "2026.11.01",
          "result": "Trojan.Win32.CobaltStrike.gen" if i < 52 else None,
          "method": "blacklist",
          "engine_update": "20261101",
      }
      for i in range(76)
  }
  pe_imports = [
      {
          "library_name": f"KERNEL32_{lib_idx}.dll",
          "imported_functions": [
              f"VirtualAllocEx_{fn_idx}" for fn_idx in range(60)
          ],
      }
      for lib_idx in range(20)
  ]
  submission_names = [f"invoice_scan_{idx:04d}.exe" for idx in range(300)]

  return {
      "id": SHA256_SAMPLE,
      "type": "file",
      "attributes": {
          "sha256": SHA256_SAMPLE,
          "sha1": SHA1_SAMPLE,
          "md5": MD5_SAMPLE,
          "meaningful_name": "stage2_beacon.exe",
          "type_description": "Win32 EXE",
          "size": 294912,
          "names": submission_names,
          "last_analysis_stats": {
              "malicious": 52,
              "suspicious": 2,
              "undetected": 22,
              "harmless": 0,
              "timeout": 0,
          },
          "popular_threat_classification": {
              "suggested_threat_label": "trojan.cobaltstrike/beacon",
              "popular_threat_category": [{"value": "trojan", "count": 41}],
              "popular_threat_name": [{"value": "cobaltstrike", "count": 38}],
          },
          "gti_assessment": {
              "verdict": {"value": "VERDICT_MALICIOUS"},
              "severity": {"value": "SEVERITY_HIGH"},
              "threat_score": {"value": 95},
              "description": "High-confidence Cobalt Strike malleable C2 beacon.",
          },
          "crowdsourced_ai_results": [
              {
                  "category": "code_insight",
                  "source": "Code Insight",
                  "analysis": (
                      "Allocates RWX memory, resolves WinInet APIs dynamically, "
                      "and initiates HTTPS beacon callbacks to 198.51.100.42."
                  ),
              }
          ],
          "pe_info": {
              "imphash": IMPHASH_SAMPLE,
              "import_list": pe_imports,
              "sections": [
                  {"name": ".text", "entropy": 6.42, "raw_size": 163840},
                  {"name": ".rdata", "entropy": 7.89, "raw_size": 98304},
              ],
          },
          "crowdsourced_yara_results": [
              {
                  "rule_name": "apt_cobaltstrike_beacon_x64",
                  "ruleset_id": "0011223344",
                  "ruleset_name": "CobaltStrike",
                  "description": "Detects Cobalt Strike x64 Reflective Loader",
                  "author": "Google GTI",
              }
          ],
          "sigma_analysis_results": [
              {
                  "rule_title": "Cobalt Strike Named Pipe Pattern",
                  "rule_level": "critical",
                  "rule_id": "sigma-cs-pipe-01",
                  "match_context": [{"values": {"PipeName": "\\\\.\\pipe\\MSSE-4412-server"}}],
              }
          ],
          "crowdsourced_ids_results": [
              {
                  "alert_severity": "high",
                  "rule_msg": "ET PRO TROJAN CobaltStrike Malleable C2 Beacon",
                  "rule_id": "2841920",
              }
          ],
          "last_analysis_results": vendor_results,
      },
      "relationships": {
          "contacted_domains": [
              {"type": "domain", "id": "cdn-update-telemetry.com"},
          ],
          "contacted_ips": [
              {"type": "ip_address", "id": "198.51.100.42"},
          ],
          "contacted_urls": [
              {"type": "url", "id": "https://cdn-update-telemetry.com/jquery-3.3.1.min.js"},
          ],
          "dropped_files": [
              {"type": "file", "id": "8e570e32aa99bb11cc22dd33ee44ff556677889900aabbccddeeff0011223344"},
          ],
          "associations": [
              {
                  "type": "collection",
                  "id": "threat-actor--apt41-dragon",
                  "attributes": {
                      "name": "APT41",
                      "collection_type": "threat-actor",
                  },
              },
              {
                  "type": "collection",
                  "id": "malware-family--cobalt-strike",
                  "attributes": {
                      "name": "Cobalt Strike",
                      "collection_type": "malware-family",
                  },
              },
          ],
      },
  }


def make_bloated_behavior_summary() -> dict[str, typing.Any]:
  """Constructs a realistic 150KB+ bloated sandbox behaviour_summary fixture."""
  noisy_registry_opened = (
      [
          f"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts\\Font_{i}"
          for i in range(450)
      ]
      + [
          f"HKCU\\Software\\Adobe\\Acrobat Reader\\DC\\Privileged\\Key_{i}"
          for i in range(300)
      ]
  )
  noisy_files_opened = [
      f"C:\\Windows\\System32\\locale_{i:03d}.nls" for i in range(400)
  ]
  return {
      "processes_tree": [
          {
              "process_id": "1420",
              "name": "stage2_beacon.exe",
              "children": [
                  {
                      "process_id": "2188",
                      "name": "powershell.exe",
                      "children": [],
                  }
              ],
          }
      ],
      "command_executions": [
          "stage2_beacon.exe --init",
          "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
      ],
      "mutexes_created": [
          "SyncRootManager",
          "Global\\MSIExecute",
          "Local\\SM0:1420:304:WilStaging_02",
          "Global\\MSSE-4412-server-mutex",
      ],
      "mutexes_opened": [
          "SyncRootManager",
          "MSIExecute",
      ],
      "registry_keys_opened": noisy_registry_opened,
      "registry_keys_set": [
          {
              "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
              "value": "C:\\Users\\Public\\stage2_beacon.exe",
          }
      ],
      "files_opened": noisy_files_opened,
      "files_dropped": [
          {
              "path": "C:\\Users\\Public\\beacon_cfg.bin",
              "sha256": "8e570e32aa99bb11cc22dd33ee44ff556677889900aabbccddeeff0011223344",
          }
      ],
      "ip_traffic": [
          {
              "destination_ip": "198.51.100.42",
              "destination_port": 443,
              "transport_layer_protocol": "TCP",
          }
      ],
      "dns_lookups": [
          {
              "hostname": "cdn-update-telemetry.com",
              "resolved_ips": ["198.51.100.42"],
          }
      ],
      "http_conversations": [
          {
              "url": "https://cdn-update-telemetry.com/jquery-3.3.1.min.js",
              "request_method": "GET",
              "response_status_code": 200,
          }
      ],
      "attack_techniques": [
          "T1059.001",
          "T1547.001",
          "T1071.001",
      ],
      "signature_matches": [
          {
              "id": "sig_1",
              "description": "Creates a persistence Run key in HKCU",
              "severity": "IMPACT_SEVERITY_HIGH",
          },
          {
              "id": "sig_2",
              "description": "Spawns hidden encoded PowerShell command",
              "severity": "IMPACT_SEVERITY_HIGH",
          },
      ],
  }


def test_extract_verbatim_anchors_preserves_exact_digests():
  """Verbatim anchor extractor must copy exact cryptographic digests and stats."""
  report = make_bloated_file_report()
  anchors = rlm_engine.extract_verbatim_anchors(report)

  assert anchors["sha256"] == SHA256_SAMPLE
  assert anchors["sha1"] == SHA1_SAMPLE
  assert anchors["md5"] == MD5_SAMPLE
  assert anchors["imphash"] == IMPHASH_SAMPLE
  assert anchors["meaningful_name"] == "stage2_beacon.exe"
  assert anchors["type_description"] == "Win32 EXE"
  assert anchors["size"] == 294912
  assert anchors["last_analysis_stats"]["malicious"] == 52
  assert (
      anchors["popular_threat_classification"]["suggested_threat_label"]
      == "trojan.cobaltstrike/beacon"
  )
  assert anchors["gti_assessment"]["verdict"]["value"] == "VERDICT_MALICIOUS"
  assert "198.51.100.42" in anchors["code_insights"]


def test_is_benign_sandbox_noise_filters_known_os_clutter():
  """Known benign sandbox artifacts (SyncRootManager, MSIExecute, Fonts) are flagged."""
  assert rlm_engine.is_benign_sandbox_noise("SyncRootManager") is True
  assert rlm_engine.is_benign_sandbox_noise("Global\\MSIExecute") is True
  assert (
      rlm_engine.is_benign_sandbox_noise(
          "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts\\Arial"
      )
      is True
  )
  assert (
      rlm_engine.is_benign_sandbox_noise(
          "HKCU\\Software\\Adobe\\Acrobat Reader\\DC\\Privileged"
      )
      is True
  )
  assert (
      rlm_engine.is_benign_sandbox_noise("Global\\MSSE-4412-server-mutex")
      is False
  )
  assert (
      rlm_engine.is_benign_sandbox_noise(
          "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
      )
      is False
  )


def test_build_payload_index_summarizes_structure_and_noise_counts():
  """Payload index summarizes key shapes and counts benign noise without copying huge arrays."""
  behavior = make_bloated_behavior_summary()
  index = rlm_engine.build_payload_index(behavior)

  assert "top_level_keys" in index
  assert index["collection_counts"]["registry_keys_opened"] == 750
  assert index["collection_counts"]["files_opened"] == 400
  assert index["benign_noise_counts"]["mutexes_created"] >= 3
  assert index["benign_noise_counts"]["registry_keys_opened"] == 750
  assert len(json.dumps(index)) < 4000


def test_deterministic_distill_payload_achieves_high_signal_compression():
  """Deterministic fallback distills bloated file report and behavior summary with >90% compression."""
  report = make_bloated_file_report()
  raw_bytes = len(json.dumps(report).encode("utf-8"))
  assert raw_bytes > 40000

  distilled = rlm_engine.deterministic_distill_payload(
      report,
      entity_id=SHA256_SAMPLE,
      tool_name="rlm_get_file_report",
      query="Summarize malware family, detections, and C2 infrastructure.",
      api_calls_made=1,
      endpoints_called=[f"/files/{SHA256_SAMPLE}"],
  )

  assert distilled["id"] == SHA256_SAMPLE
  assert distilled["tool"] == "rlm_get_file_report"
  assert distilled["verbatim_anchors"]["sha256"] == SHA256_SAMPLE
  assert distilled["verbatim_anchors"]["imphash"] == IMPHASH_SAMPLE
  assert "198.51.100.42" in distilled["high_signal_iocs"]["network"]
  assert (
      "cdn-update-telemetry.com" in distilled["high_signal_iocs"]["network"]
  )
  assert any(
      "apt_cobaltstrike_beacon_x64" in m
      for m in distilled["high_signal_iocs"]["yara_and_sigma_matches"]
  )
  assert any(a["name"] == "APT41" for a in distilled["attributions"])
  assert distilled["compression_metrics"]["reduction_pct"] > 85.0
  assert distilled["compression_metrics"]["rlm_mode"] == "deterministic_fallback"

  behavior = make_bloated_behavior_summary()
  distilled_beh = rlm_engine.deterministic_distill_payload(
      behavior,
      entity_id=SHA256_SAMPLE,
      tool_name="rlm_get_file_behavior_summary",
      query="Identify persistence, process execution, and network C2.",
      api_calls_made=1,
      endpoints_called=[f"/files/{SHA256_SAMPLE}/behaviour_summary"],
  )
  assert (
      "Global\\MSSE-4412-server-mutex"
      in distilled_beh["high_signal_iocs"]["persistence_and_mutexes"]
  )
  assert (
      "SyncRootManager"
      not in distilled_beh["high_signal_iocs"]["persistence_and_mutexes"]
  )
  assert any(
      "powershell.exe" in cmd
      for cmd in distilled_beh["high_signal_iocs"]["process_and_command_lines"]
  )
  assert any(
      t["id"] == "T1059.001" for t in distilled_beh["mitre_techniques"]
  )
  assert distilled_beh["compression_metrics"]["reduction_pct"] > 90.0
