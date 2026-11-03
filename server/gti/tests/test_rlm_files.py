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


SHA256_SAMPLE = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
SHA1_SAMPLE = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
MD5_SAMPLE = "098f6bcd4621d373cade4e832627b4f6"
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
  """Payload index summarizes key shapes, verbatim anchors, and noise counts without copying huge arrays."""
  behavior = make_bloated_behavior_summary()
  index = rlm_engine.build_payload_index(behavior)

  assert "top_level_keys" in index
  assert "verbatim_anchors" in index
  assert index["collection_counts"]["registry_keys_opened"] == 750
  assert index["collection_counts"]["files_opened"] == 400
  assert index["benign_noise_counts"]["mutexes_created"] >= 3
  assert index["benign_noise_counts"]["registry_keys_opened"] == 750
  assert len(json.dumps(index)) < 4000

  # Verify live VT v3 {"data": [...]} relationship envelope unwrapping
  enveloped_report = make_bloated_file_report()
  enveloped_report["relationships"] = {
      "contacted_domains": {
          "data": [{"type": "domain", "id": "cdn-update-telemetry.com"}],
          "links": {"self": "https://www.virustotal.com/api/v3/..."},
      },
      "associations": {
          "data": {
              "type": "collection",
              "id": "threat-actor--apt41-dragon",
              "attributes": {"name": "APT41", "collection_type": "threat-actor"},
          }
      },
  }
  env_index = rlm_engine.build_payload_index(enveloped_report)
  assert env_index["verbatim_anchors"]["sha256"] == SHA256_SAMPLE
  assert env_index["relationship_counts"]["contacted_domains"] == 1
  assert env_index["relationship_counts"]["associations"] == 1
  env_distilled = rlm_engine.deterministic_distill_payload(
      enveloped_report,
      entity_id=SHA256_SAMPLE,
      tool_name="rlm_get_file_report",
      query="Check enveloped relationships",
  )
  assert "cdn-update-telemetry.com" in env_distilled["high_signal_iocs"]["network"]
  assert any(a["name"] == "APT41" for a in env_distilled["attributions"])


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


class ScriptedRLMEngine:
  """Hermetic dspy>=3.4.1 engine implementing complete(request) -> Response."""

  def __init__(self, responses: list[str]):
    self.responses = list(responses)
    self.calls: list[typing.Any] = []

  def complete(self, request: typing.Any) -> typing.Any:
    import dspy

    self.calls.append(request)
    idx = min(len(self.calls) - 1, len(self.responses) - 1)
    text = self.responses[idx]
    return dspy.lm15.Response(
        id=f"scripted-{len(self.calls)}",
        model=getattr(request, "model", "test/scripted"),
        message=dspy.lm15.Message.assistant(text),
        finish_reason="stop",
        usage=dspy.lm15.Usage(),
    )


def test_gti_sandboxed_interpreter_shim_bypass_and_positional_tool_binding():
  """GTISandboxedInterpreter skips __dspy_host_token turn counting and binds positional tool args."""
  import inspect
  import dspy

  def fetch_rel(relationship_name: str, limit: int = 5) -> list[str]:
    return [f"{relationship_name}:{limit}"]

  dspy_tool = dspy.Tool(fetch_rel)

  # Simulate RLM._make_interpreter_tool wrapper (keyword-only **kwargs with __wrapped__)
  def wrapped_invoke(**kwargs):
    return dspy_tool(**kwargs)

  wrapped_invoke.__wrapped__ = dspy_tool.func
  wrapped_invoke.__signature__ = inspect.signature(dspy_tool.func)

  interp = rlm_engine.GTISandboxedInterpreter(
      tools={"fetch_rel": wrapped_invoke}
  )
  try:
    # 1. Internal FacadeInvocation SHIM_SETUP must not increment user_turns
    interp.execute("x = 1", variables={"__dspy_host_token": "tok-123"})
    assert interp.user_turns == 0

    # 2. Normal user turn increments user_turns
    interp.execute("y = x + 1")
    assert interp.user_turns == 1

    # 3. Positional tool invocation via invoke_tool works without TypeError
    res = interp.invoke_tool("fetch_rel", ("contacted_domains", 3), {})
    assert res == ["contacted_domains:3"]

    # 4. Ungrounded short llm_query prompt is rejected with actionable guidance
    short_res = interp.invoke_tool("llm_query", ("Explain Cobalt Strike",), {})
    assert "GROUNDING_ERROR" in str(short_res)
  finally:
    interp.shutdown()


def test_api_call_tracker_enforces_budget_and_deduplicates():
  """APICallTracker tracks bytes, caches duplicate calls, and enforces max_api_calls."""
  tracker = rlm_engine.APICallTracker(
      max_api_calls=2,
      initial_endpoint=f"/files/{SHA256_SAMPLE}",
      initial_bytes=1024,
  )
  assert tracker.api_calls_made == 1

  call_count = 0

  def fake_fetch() -> dict[str, typing.Any]:
    nonlocal call_count
    call_count += 1
    return {"data": ["item1", "item2"]}

  # Second unique endpoint succeeds (2/2 budget)
  res1 = tracker.call("/files/hash/behaviour_summary", {}, fake_fetch)
  assert res1 == {"data": ["item1", "item2"]}
  assert tracker.api_calls_made == 2
  assert call_count == 1

  # Duplicate call to same endpoint/params hits cache without spending budget
  res_cached = tracker.call("/files/hash/behaviour_summary", {}, fake_fetch)
  assert res_cached == {"data": ["item1", "item2"]}
  assert tracker.api_calls_made == 2
  assert call_count == 1

  # Third unique endpoint exceeds max_api_calls=2
  res_over = tracker.call("/files/hash/associations", {"limit": 10}, fake_fetch)
  assert "budget_exhausted" in res_over
  assert tracker.api_calls_made == 2
  assert call_count == 1

  # Fetcher exceptions are caught and returned as {"error": ...} dicts
  err_tracker = rlm_engine.APICallTracker(max_api_calls=3)

  def failing_fetch() -> dict[str, typing.Any]:
    raise RuntimeError("VT endpoint timeout")

  res_err = err_tracker.call("/files/hash/behaviours", {}, failing_fetch)
  assert "error" in res_err
  assert "VT endpoint timeout" in res_err["error"]


def test_distill_gti_payload_runs_dspy_rlm_end_to_end_with_scripted_lm():
  """distill_gti_payload executes dspy.RLM in GTISandboxedInterpreter and merges verbatim anchors."""
  import dspy

  step_0_resp = (
      "[[ ## reasoning ## ]]\n"
      "Inspect payload_index and extract vendor detections, YARA/Sigma rules, and network IOCs.\n\n"
      "[[ ## code ## ]]\n"
      "```python\n"
      "attrs = raw_data.get('attributes', {})\n"
      "rels = raw_data.get('relationships', {})\n"
      "net_iocs = [d['id'] for d in rels.get('contacted_domains', [])] + [ip['id'] for ip in rels.get('contacted_ips', [])]\n"
      "yara_hits = [r['rule_name'] for r in attrs.get('crowdsourced_yara_results', [])]\n"
      "SUBMIT(\n"
      "    verdict_and_summary='Malicious Cobalt Strike x64 beacon (52/76 detections, GTI VERDICT_MALICIOUS).',\n"
      "    answer='The sample is a Cobalt Strike beacon contacting 198.51.100.42 and cdn-update-telemetry.com.',\n"
      "    key_findings=['52/76 vendors detect Trojan.Win32.CobaltStrike.gen', 'Matches YARA rule apt_cobaltstrike_beacon_x64'],\n"
      "    high_signal_iocs={\n"
      "        'network': net_iocs,\n"
      "        'files_dropped_or_modified': ['8e570e32aa99bb11cc22dd33ee44ff556677889900aabbccddeeff0011223344'],\n"
      "        'process_and_command_lines': [],\n"
      "        'persistence_and_mutexes': ['\\\\\\\\.\\\\pipe\\\\MSSE-4412-server'],\n"
      "        'yara_and_sigma_matches': yara_hits,\n"
      "    },\n"
      "    attributions=[{'id': 'threat-actor--apt41-dragon', 'name': 'APT41', 'collection_type': 'threat-actor'}],\n"
      "    mitre_techniques=[{'id': 'T1071.001', 'name': 'Application Layer Protocol: Web Protocols', 'evidence': 'HTTPS C2 beacon'}],\n"
      "    filtered_noise_summary='Omitted 76 raw vendor entries, 300 submission filenames, and 1,200 PE imported functions.'\n"
      ")\n"
      "```\n"
  )
  engine = ScriptedRLMEngine([step_0_resp])
  test_lm = dspy.LM("test/scripted", engine=engine, cache=False)

  report = make_bloated_file_report()
  distilled = rlm_engine.distill_gti_payload(
      report,
      entity_id=SHA256_SAMPLE,
      tool_name="rlm_get_file_report",
      query="What malware family is this and what C2 infrastructure does it contact?",
      lm=test_lm,
      sub_lm=test_lm,
  )

  assert distilled["id"] == SHA256_SAMPLE
  assert distilled["verbatim_anchors"]["sha256"] == SHA256_SAMPLE
  assert distilled["verbatim_anchors"]["imphash"] == IMPHASH_SAMPLE
  assert "Cobalt Strike" in distilled["verdict_and_summary"]
  assert "198.51.100.42" in distilled["high_signal_iocs"]["network"]
  assert "cdn-update-telemetry.com" in distilled["high_signal_iocs"]["network"]
  assert distilled["compression_metrics"]["rlm_mode"] == "dspy_rlm"
  assert distilled["compression_metrics"]["rlm_iters"] == 1
  assert distilled["compression_metrics"]["reduction_pct"] > 85.0


def test_distill_gti_payload_falls_back_when_lm_raises():
  """If the RLM LM fails at runtime, distill_gti_payload falls back to deterministic distillation."""
  import dspy

  class FailingEngine:
    def complete(self, request: typing.Any) -> typing.Any:
      raise RuntimeError("Simulated Vertex AI quota error")

  bad_lm = dspy.LM("test/failing", engine=FailingEngine(), cache=False)
  report = make_bloated_file_report()
  distilled = rlm_engine.distill_gti_payload(
      report,
      entity_id=SHA256_SAMPLE,
      tool_name="rlm_get_file_report",
      query="Summarize file report.",
      lm=bad_lm,
      sub_lm=bad_lm,
  )

  assert distilled["id"] == SHA256_SAMPLE
  assert distilled["verbatim_anchors"]["sha256"] == SHA256_SAMPLE
  assert distilled["compression_metrics"]["rlm_mode"] == "deterministic_fallback"
  assert "198.51.100.42" in distilled["high_signal_iocs"]["network"]


@pytest.mark.asyncio(loop_scope="session")
async def test_rlm_tools_registered_in_fastmcp_server():
  """All 5 additive RLM file tools must be registered on the FastMCP server."""
  from gti_mcp.server import server
  from mcp.shared.memory import (
      create_connected_server_and_client_session as client_session,
  )

  async with client_session(server._mcp_server) as client:
    tools_result = await client.list_tools()
    tool_names = {t.name for t in tools_result.tools}
    expected_rlm_tools = {
        "rlm_get_file_report",
        "rlm_get_file_behavior_summary",
        "rlm_get_file_behavior_report",
        "rlm_get_entities_related_to_a_file",
        "rlm_investigate_file",
    }
    assert expected_rlm_tools.issubset(tool_names)
    # Existing raw tools must still be present
    assert "get_file_report" in tool_names
    assert "get_file_behavior_summary" in tool_names


@pytest.mark.asyncio(loop_scope="session")
async def test_rlm_get_file_report_single_api_call_over_mcp(
    make_httpserver_ipv4, monkeypatch
):
  """rlm_get_file_report makes 1 VT API call and distills the bloated report via dspy.RLM."""
  import dspy
  import vt
  from gti_mcp.server import server
  from mcp.shared.memory import (
      create_connected_server_and_client_session as client_session,
  )

  monkeypatch.setattr(
      "gti_mcp.server.vt_client_factory",
      lambda _ctx: vt.Client(
          "dummy_api_key",
          host=f"http://{make_httpserver_ipv4.host}:{make_httpserver_ipv4.port}",
          timeout=500,
      ),
  )

  bloated = make_bloated_file_report()
  make_httpserver_ipv4.expect_request(
      f"/api/v3/files/{SHA256_SAMPLE}",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"data": bloated})

  step_0_resp = (
      "[[ ## reasoning ## ]]\n"
      "Slice raw_data in Python to summarize vendor consensus and network IOCs.\n\n"
      "[[ ## code ## ]]\n"
      "```python\n"
      "attrs = raw_data.get('attributes', {})\n"
      "stats = attrs.get('last_analysis_stats', {})\n"
      "SUBMIT(\n"
      "    verdict_and_summary=f\"Malicious Cobalt Strike beacon ({stats.get('malicious', 0)} detections).\",\n"
      "    answer='Cobalt Strike beacon contacting 198.51.100.42.',\n"
      "    key_findings=['52 malicious detections', 'Code Insights confirms HTTPS C2'],\n"
      "    high_signal_iocs={'network': ['198.51.100.42', 'cdn-update-telemetry.com'], 'files_dropped_or_modified': [], 'process_and_command_lines': [], 'persistence_and_mutexes': [], 'yara_and_sigma_matches': ['apt_cobaltstrike_beacon_x64']},\n"
      "    attributions=[{'id': 'threat-actor--apt41-dragon', 'name': 'APT41', 'collection_type': 'threat-actor'}],\n"
      "    mitre_techniques=[],\n"
      "    filtered_noise_summary='Omitted 76 raw vendor entries and 20 PE import DLL tables.'\n"
      ")\n"
      "```\n"
  )
  test_lm = dspy.LM(
      "test/scripted", engine=ScriptedRLMEngine([step_0_resp]), cache=False
  )
  monkeypatch.setattr(
      rlm_engine,
      "configure_gti_rlm_lms",
      lambda lm=None, sub_lm=None: (test_lm, test_lm),
  )

  async with client_session(server._mcp_server) as client:
    res = await client.call_tool(
        "rlm_get_file_report",
        {
            "hash": SHA256_SAMPLE,
            "query": "What C2 does this file contact?",
        },
    )
    assert not res.isError
    payload = json.loads(res.content[0].text)
    assert payload["id"] == SHA256_SAMPLE
    assert payload["tool"] == "rlm_get_file_report"
    assert payload["verbatim_anchors"]["sha256"] == SHA256_SAMPLE
    assert payload["verbatim_anchors"]["imphash"] == IMPHASH_SAMPLE
    assert payload["compression_metrics"]["api_calls_made"] == 1
    assert payload["compression_metrics"]["rlm_mode"] == "dspy_rlm"
    assert payload["compression_metrics"]["reduction_pct"] > 85.0


@pytest.mark.asyncio(loop_scope="session")
async def test_rlm_get_file_behavior_summary_and_report_and_related_entities(
    make_httpserver_ipv4, monkeypatch
):
  """rlm_get_file_behavior_summary, rlm_get_file_behavior_report, and rlm_get_entities_related_to_a_file each make 1 VT call."""
  import vt
  from gti_mcp.server import server
  from mcp.shared.memory import (
      create_connected_server_and_client_session as client_session,
  )

  monkeypatch.setattr(
      "gti_mcp.server.vt_client_factory",
      lambda _ctx: vt.Client(
          "dummy_api_key",
          host=f"http://{make_httpserver_ipv4.host}:{make_httpserver_ipv4.port}",
          timeout=500,
      ),
  )

  # Force deterministic fallback to test end-to-end MCP wiring without LM overhead
  monkeypatch.setattr(
      rlm_engine, "configure_gti_rlm_lms", lambda lm=None, sub_lm=None: (None, None)
  )

  beh_summary = make_bloated_behavior_summary()
  make_httpserver_ipv4.expect_request(
      f"/api/v3/files/{SHA256_SAMPLE}/behaviour_summary",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"data": beh_summary})

  beh_id = f"{SHA256_SAMPLE}_VirusTotal Jujubox"
  make_httpserver_ipv4.expect_request(
      f"/api/v3/file_behaviours/{beh_id}",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": {
              "id": beh_id,
              "type": "file_behaviour",
              "attributes": beh_summary,
          }
      }
  )

  make_httpserver_ipv4.expect_request(
      f"/api/v3/files/{SHA256_SAMPLE}/contacted_domains",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": [
              {
                  "id": "cdn-update-telemetry.com",
                  "type": "domain",
                  "attributes": {"reputation": -45},
              }
          ]
      }
  )

  async with client_session(server._mcp_server) as client:
    # 1. rlm_get_file_behavior_summary
    res_sum = await client.call_tool(
        "rlm_get_file_behavior_summary",
        {"hash": SHA256_SAMPLE, "query": "Check persistence and mutexes"},
    )
    assert not res_sum.isError
    data_sum = json.loads(res_sum.content[0].text)
    assert data_sum["compression_metrics"]["api_calls_made"] == 1
    assert (
        "Global\\MSSE-4412-server-mutex"
        in data_sum["high_signal_iocs"]["persistence_and_mutexes"]
    )
    assert (
        "SyncRootManager"
        not in data_sum["high_signal_iocs"]["persistence_and_mutexes"]
    )

    # 2. rlm_get_file_behavior_report
    res_rep = await client.call_tool(
        "rlm_get_file_behavior_report",
        {"file_behaviour_id": beh_id},
    )
    assert not res_rep.isError
    data_rep = json.loads(res_rep.content[0].text)
    assert data_rep["id"] == beh_id
    assert data_rep["compression_metrics"]["api_calls_made"] == 1

    # 3. rlm_get_entities_related_to_a_file (valid relationship)
    res_rel = await client.call_tool(
        "rlm_get_entities_related_to_a_file",
        {
            "hash": SHA256_SAMPLE,
            "relationship_name": "contacted_domains",
            "descriptors_only": False,
            "limit": 5,
        },
    )
    assert not res_rel.isError
    data_rel = json.loads(res_rel.content[0].text)
    assert data_rel["compression_metrics"]["api_calls_made"] == 1

    # 4. rlm_get_entities_related_to_a_file (invalid relationship short-circuits)
    res_bad = await client.call_tool(
        "rlm_get_entities_related_to_a_file",
        {
            "hash": SHA256_SAMPLE,
            "relationship_name": "not_a_valid_rel",
        },
    )
    assert not res_bad.isError
    data_bad = json.loads(res_bad.content[0].text)
    assert "error" in data_bad


@pytest.mark.asyncio(loop_scope="session")
async def test_rlm_investigate_file_autonomous_multi_call_pivoting_and_budget_cap(
    make_httpserver_ipv4, monkeypatch
):
  """rlm_investigate_file binds VT tools inside the REPL, pivots across endpoints, and respects max_api_calls."""
  import dspy
  import vt
  from gti_mcp.server import server
  from mcp.shared.memory import (
      create_connected_server_and_client_session as client_session,
  )

  monkeypatch.setattr(
      "gti_mcp.server.vt_client_factory",
      lambda _ctx: vt.Client(
          "dummy_api_key",
          host=f"http://{make_httpserver_ipv4.host}:{make_httpserver_ipv4.port}",
          timeout=500,
      ),
  )

  bloated_report = make_bloated_file_report()
  beh_summary = make_bloated_behavior_summary()

  make_httpserver_ipv4.expect_request(
      f"/api/v3/files/{SHA256_SAMPLE}",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"data": bloated_report})

  make_httpserver_ipv4.expect_request(
      f"/api/v3/files/{SHA256_SAMPLE}/behaviour_summary",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"data": beh_summary})

  make_httpserver_ipv4.expect_request(
      "/api/v3/collections/threat-actor--apt41-dragon",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": {
              "id": "threat-actor--apt41-dragon",
              "type": "collection",
              "attributes": {
                  "name": "APT41",
                  "collection_type": "threat-actor",
                  "description": "State-sponsored cyber espionage group using Cobalt Strike.",
              },
          }
      }
  )

  # Turn 0: REPL calls bound tools positionally and by keyword (also tries a 4th call over max_api_calls=3)
  step_0_resp = (
      "[[ ## reasoning ## ]]\n"
      "Pivot into behaviour_summary and collection threat-actor--apt41-dragon from inside the REPL.\n\n"
      "[[ ## code ## ]]\n"
      "```python\n"
      "beh = fetch_behavior_summary()\n"
      "actor = fetch_collection_summary('threat-actor--apt41-dragon')\n"
      "# Duplicate call should hit cache without spending budget\n"
      "beh_dup = fetch_behavior_summary()\n"
      "# 4th unique call should hit max_api_calls=3 cap\n"
      "over_budget = fetch_related_entities('dropped_files', False, 5)\n"
      "cmds = beh.get('command_executions', [])\n"
      "actor_desc = actor.get('attributes', {}).get('description', '')\n"
      "SUBMIT(\n"
      "    verdict_and_summary=f'Malicious APT41 Cobalt Strike beacon: {actor_desc}',\n"
      "    answer=f'Executes {len(cmds)} commands and is attributed to APT41. Budget check: { \"budget_exhausted\" in over_budget }',\n"
      "    key_findings=['Static + dynamic pivot succeeded', f'Commands: {cmds[0]}'],\n"
      "    high_signal_iocs={'network': ['198.51.100.42'], 'files_dropped_or_modified': ['C:\\\\Users\\\\Public\\\\beacon_cfg.bin'], 'process_and_command_lines': cmds, 'persistence_and_mutexes': ['Global\\\\MSSE-4412-server-mutex'], 'yara_and_sigma_matches': ['apt_cobaltstrike_beacon_x64']},\n"
      "    attributions=[{'id': 'threat-actor--apt41-dragon', 'name': 'APT41', 'collection_type': 'threat-actor'}],\n"
      "    mitre_techniques=[{'id': 'T1059.001', 'name': 'PowerShell', 'evidence': cmds[-1]}],\n"
      "    filtered_noise_summary='Filtered 750 noisy registry reads and 400 locale file opens.'\n"
      ")\n"
      "```\n"
  )
  test_lm = dspy.LM(
      "test/scripted", engine=ScriptedRLMEngine([step_0_resp]), cache=False
  )
  monkeypatch.setattr(
      rlm_engine,
      "configure_gti_rlm_lms",
      lambda lm=None, sub_lm=None: (test_lm, test_lm),
  )

  async with client_session(server._mcp_server) as client:
    res = await client.call_tool(
        "rlm_investigate_file",
        {
            "hash": SHA256_SAMPLE,
            "investigation_goal": "Correlate static report, sandbox behavior, and threat actor attribution.",
            "max_api_calls": 3,
        },
    )
    assert not res.isError
    payload = json.loads(res.content[0].text)
    assert payload["id"] == SHA256_SAMPLE
    assert payload["tool"] == "rlm_investigate_file"
    assert payload["verbatim_anchors"]["sha256"] == SHA256_SAMPLE
    assert "APT41" in payload["verdict_and_summary"]
    assert "Budget check: True" in payload["answer"]
    assert payload["compression_metrics"]["api_calls_made"] == 3
    assert payload["compression_metrics"]["endpoints_called"] == [
        f"/files/{SHA256_SAMPLE}",
        f"/files/{SHA256_SAMPLE}/behaviour_summary",
        "/collections/threat-actor--apt41-dragon",
    ]
    assert payload["compression_metrics"]["reduction_pct"] > 90.0
