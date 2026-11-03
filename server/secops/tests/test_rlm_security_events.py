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
"""Unit tests for DSPy RLM Chronicle SIEM UDM compaction tools (`rlm_security_events`)."""

import os
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

current_dir = os.path.dirname(os.path.abspath(__file__))
server_secops_dir = os.path.dirname(current_dir)
if server_secops_dir not in sys.path:
  sys.path.insert(0, server_secops_dir)

from secops_mcp import rlm_engine
from secops_mcp.tools.rlm_security_events import (
    rlm_investigate_entity_timeline,
    rlm_search_security_events,
)

HASH_MIMIKATZ_EXE = "bb8bdb3e8c92e97e2f63626bc3b254c4"
HASH_MIMILIB_DLL = "ddfad0d55be70acdfea36acf28d418b3"
HASH_VSSADMIN_EXE = "614b5c4238977130aa2270c8ad58ce6c"


class ScriptedRLMEngine:
  """Hermetic dspy>=3.4.1 engine implementing complete(request) -> Response."""

  def __init__(self, responses: list[str]) -> None:
    self.responses = list(responses)
    self.calls: list[Any] = []

  def complete(self, request: Any) -> Any:
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


def make_bloated_udm_events_fixture(num_background: int = 80) -> dict[str, Any]:
  """Constructs a ~550KB Chronicle UDM search response combining kill-chain and background events."""
  events: list[dict[str, Any]] = []
  bloated_labels = [
      {"key": f"sysmon_extended_property_{i}", "value": "X" * 160}
      for i in range(30)
  ]

  # 1. Stage 1: Mimikatz credential dumping
  events.append({
      "name": "events/ev-mimikatz-1",
      "udm": {
          "metadata": {
              "id": "ev-mimikatz-1",
              "eventTimestamp": "2026-10-31T14:22:08.532Z",
              "eventType": "PROCESS_LAUNCH",
              "productEventType": "1",
              "productName": "Microsoft-Windows-Sysmon",
          },
          "principal": {
              "hostname": "activedir.stackedpads.local",
              "ip": ["10.10.20.60"],
              "user": {"userid": "fkolzig"},
              "process": {
                  "commandLine": "C:\\Windows\\system32\\cmd.exe",
                  "file": {"fullPath": "C:\\Windows\\System32\\cmd.exe"},
              },
          },
          "target": {
              "process": {
                  "commandLine": (
                      'c:\\temp\\mimikatz.exe "privilege::debug" '
                      '"sekurlsa::logonpasswords full" exit'
                  ),
                  "file": {
                      "fullPath": "C:\\temp\\mimikatz.exe",
                      "md5": HASH_MIMIKATZ_EXE,
                      "sha256": "61bd916c2fb4fa9fe2dc23eb3fd2eccf1ff3abbbbf6d4ffefde5dcbe3befa84f",
                  },
              },
          },
          "about": [{"labels": bloated_labels}],
      },
  })

  # 2. Stage 1b: mimilib.dll creation
  events.append({
      "name": "events/ev-mimilib-2",
      "udm": {
          "metadata": {
              "id": "ev-mimilib-2",
              "eventTimestamp": "2026-10-31T14:21:20.236Z",
              "eventType": "FILE_CREATION",
              "productEventType": "11",
          },
          "principal": {
              "hostname": "activedir.stackedpads.local",
              "ip": ["10.10.20.60"],
              "user": {"userid": "fkolzig"},
          },
          "target": {
              "file": {
                  "fullPath": "C:\\temp\\mimilib.dll",
                  "md5": HASH_MIMILIB_DLL,
                  "sha256": "a302d2ce6ab6fb3cf7d4cd2f5cd0ffce8be2c7aa17ca895ca1ee0a1f00d1bd2d",
              },
          },
          "about": [{"labels": bloated_labels}],
      },
  })

  # 3. Stage 2: Diskshadow + NTDS.dit copy
  events.append({
      "name": "events/ev-ntds-3",
      "udm": {
          "metadata": {
              "id": "ev-ntds-3",
              "eventTimestamp": "2026-10-31T14:23:15.100Z",
              "eventType": "PROCESS_LAUNCH",
              "productEventType": "4688",
          },
          "principal": {
              "hostname": "activedir.stackedpads.local",
              "ip": ["10.10.20.60"],
              "user": {"userid": "fkolzig"},
              "process": {
                  "commandLine": "cmd /c copy x:\\windows\\ntds\\ntds.dit c:\\ntds.dit",
                  "file": {"fullPath": "C:\\Windows\\System32\\cmd.exe"},
              },
          },
          "target": {
              "process": {
                  "commandLine": "diskshadow /s c:\\temp\\orange.txt",
                  "file": {"fullPath": "C:\\Windows\\System32\\diskshadow.exe"},
              },
          },
          "about": [{"labels": bloated_labels}],
      },
  })

  # 4. Stage 3: WMI -> vssadmin shadow copy creation
  events.append({
      "name": "events/ev-vssadmin-4",
      "udm": {
          "metadata": {
              "id": "ev-vssadmin-4",
              "eventTimestamp": "2026-10-31T14:25:15.059Z",
              "eventType": "PROCESS_LAUNCH",
              "productEventType": "1",
          },
          "principal": {
              "hostname": "activedir.stackedpads.local",
              "ip": ["10.10.20.60"],
              "user": {"userid": "fkolzig"},
              "process": {
                  "commandLine": 'wmic process call create "cmd /c vssadmin create shadow /for=C:"',
                  "file": {"fullPath": "C:\\Windows\\System32\\wbem\\WMIC.exe"},
              },
          },
          "target": {
              "ip": ["206.221.181.253"],
              "process": {
                  "commandLine": "vssadmin create shadow /for=C:",
                  "file": {
                      "fullPath": "C:\\Windows\\System32\\vssadmin.exe",
                      "md5": HASH_VSSADMIN_EXE,
                  },
              },
          },
          "about": [{"labels": bloated_labels}],
      },
  })

  # 5. Repetitive Windows OS background noise (svchost.exe, conhost.exe, MpCmdRun.exe)
  for idx in range(num_background):
    proc_path = (
        "C:\\Windows\\System32\\svchost.exe"
        if idx % 2 == 0
        else "C:\\Windows\\System32\\conhost.exe"
    )
    events.append({
        "name": f"events/ev-bg-{idx}",
        "udm": {
            "metadata": {
                "id": f"ev-bg-{idx}",
                "eventTimestamp": f"2026-10-31T14:19:{idx % 60:02d}.000Z",
                "eventType": "PROCESS_LAUNCH",
                "productEventType": "4688",
            },
            "principal": {
                "hostname": "activedir.stackedpads.local",
                "ip": ["10.10.20.60"],
                "user": {"userid": "ACTIVEDIR$"},
            },
            "target": {
                "process": {
                    "commandLine": f"{proc_path} -k LocalServiceNetworkRestricted",
                    "file": {"fullPath": proc_path},
                },
            },
            "about": [{"labels": bloated_labels}],
        },
    })

  return {
      "udm_query": 'principal.hostname = "activedir.stackedpads.local"',
      "events": {
          "events": events,
          "total_events": len(events),
      },
  }


def test_extract_udm_verbatim_anchors_preserves_hashes_hosts_ips_users_and_cmdlines():
  """extract_udm_verbatim_anchors extracts exact hashes, IPs, hosts, users, and command lines."""
  fixture = make_bloated_udm_events_fixture(num_background=20)
  anchors = rlm_engine.extract_udm_verbatim_anchors(fixture)

  assert anchors["total_raw_events"] == 24
  assert "activedir.stackedpads.local" in anchors["hostnames"]
  assert "10.10.20.60" in anchors["ip_addresses"]
  assert "206.221.181.253" in anchors["ip_addresses"]
  assert "fkolzig" in anchors["users"]
  assert "ACTIVEDIR$" not in anchors["users"]

  md5_set = {h["md5"] for h in anchors["file_hashes"]}
  assert HASH_MIMIKATZ_EXE in md5_set
  assert HASH_MIMILIB_DLL in md5_set
  assert HASH_VSSADMIN_EXE in md5_set

  assert any("sekurlsa::logonpasswords" in c for c in anchors["command_lines"])
  assert any("diskshadow /s c:\\temp\\orange.txt" in c for c in anchors["command_lines"])
  assert any("vssadmin create shadow /for=C:" in c for c in anchors["command_lines"])


def test_deduplicate_and_compact_udm_events_collapses_background_noise():
  """deduplicate_and_compact_udm_events collapses repetitive svchost/conhost events."""
  fixture = make_bloated_udm_events_fixture(num_background=80)
  compacted = rlm_engine.deduplicate_and_compact_udm_events(fixture)

  assert compacted["raw_event_count"] == 84
  assert compacted["background_events_collapsed"] == 80
  assert compacted["unique_signal_groups"] == 4


def test_deterministic_distill_udm_achieves_95_pct_compaction_on_bloated_udm_dump():
  """deterministic_distill_udm compacts a ~500KB UDM dump by >95% while keeping all IOCs."""
  fixture = make_bloated_udm_events_fixture(num_background=96)
  distilled = rlm_engine.deterministic_distill_udm(
      raw_payload=fixture,
      entity_or_search_text='principal.hostname = "activedir.stackedpads.local"',
      tool_name="rlm_search_security_events",
      query="Reconstruct the Domain Controller compromise timeline.",
  )
  metrics = distilled["compression_metrics"]
  assert metrics["raw_bytes"] > 500_000
  assert metrics["reduction_pct"] > 95.0
  assert any(
      HASH_MIMIKATZ_EXE in h
      for h in distilled["high_signal_iocs"]["file_hashes"]
  )
  mitre_ids = {m["id"] for m in distilled["mitre_techniques"]}
  assert "T1003.001" in mitre_ids
  assert "T1003.003" in mitre_ids
  assert "T1047" in mitre_ids


@pytest.mark.asyncio
async def test_rlm_search_security_events_executes_and_compacts(monkeypatch):
  """rlm_search_security_events supports both natural-language and raw UDM queries."""
  fixture = make_bloated_udm_events_fixture(num_background=96)
  mock_chronicle = MagicMock()
  mock_chronicle.translate_nl_to_udm.return_value = (
      'principal.hostname = "activedir.stackedpads.local"'
  )
  mock_chronicle.search_udm.return_value = fixture["events"]

  monkeypatch.setattr(
      rlm_engine,
      "configure_secops_rlm_lms",
      lambda lm=None, sub_lm=None: (None, None),
  )

  with patch(
      "secops_mcp.tools.rlm_security_events.get_chronicle_client",
      return_value=mock_chronicle,
  ):
    res_nl = await rlm_search_security_events(
        text="Show process launches and file creations on activedir.stackedpads.local",
        start_time="2026-10-31T14:18:00Z",
        end_time="2026-10-31T14:27:00Z",
        max_events=100,
    )
    assert res_nl["tool"] == "rlm_search_security_events"
    assert res_nl["compression_metrics"]["reduction_pct"] > 95.0
    mock_chronicle.translate_nl_to_udm.assert_called_once()

    # Raw UDM query bypasses translate_nl_to_udm automatically
    mock_chronicle.translate_nl_to_udm.reset_mock()
    res_raw = await rlm_search_security_events(
        text='principal.hostname = "activedir.stackedpads.local" AND metadata.event_type = "PROCESS_LAUNCH"',
        start_time="2026-10-31T14:18:00Z",
        end_time="2026-10-31T14:27:00Z",
        max_events=100,
    )
    assert not mock_chronicle.translate_nl_to_udm.called
    assert res_raw["compression_metrics"]["reduction_pct"] > 95.0


@pytest.mark.asyncio
async def test_rlm_investigate_entity_timeline_pivots_inside_repl(monkeypatch):
  """rlm_investigate_entity_timeline pivots via fetch_entity_summary and enforces budget."""
  import dspy

  fixture = make_bloated_udm_events_fixture(num_background=80)
  mock_chronicle = MagicMock()
  mock_chronicle.search_udm.return_value = fixture["events"]

  summary_mock = MagicMock()
  summary_mock.primary_entity.metadata.entity_type = "ASSET"
  summary_mock.primary_entity.metric.first_seen = "2026-10-31T14:00:00Z"
  summary_mock.primary_entity.metric.last_seen = "2026-10-31T14:30:00Z"
  alert_item = MagicMock()
  alert_item.rule = "MimiKatz Command Arguments [Mandiant Intel Emerging Threats]"
  alert_item.count = 3
  summary_mock.alert_counts = [alert_item]
  mock_chronicle.summarize_entity.return_value = summary_mock

  step_0_resp = (
      "[[ ## reasoning ## ]]\n"
      "Inspect compact_timeline and call fetch_entity_summary inside the REPL.\n\n"
      "[[ ## code ## ]]\n"
      "```python\n"
      "ent = fetch_entity_summary()\n"
      "over_budget = search_entity_udm_events('principal.ip = \"10.10.20.60\"', 10)\n"
      "procs = get_process_tree()\n"
      "SUBMIT(\n"
      "    verdict_and_summary=f'Compromised Domain Controller {entity_or_search_text} with alert {ent[\"alert_counts\"][0][\"rule\"]}',\n"
      "    answer=f'Observed {len(procs)} attack processes. Budget exhausted on 3rd call: {over_budget.get(\"budget_exhausted\")}',\n"
      "    kill_chain_timeline=procs,\n"
      "    high_signal_iocs={'hostnames': ['activedir.stackedpads.local'], 'ip_addresses': ['10.10.20.60', '206.221.181.253'], 'users': ['fkolzig'], 'file_hashes': [], 'process_command_lines': [], 'files_created_or_modified': []},\n"
      "    mitre_techniques=[{'id': 'T1003.001', 'name': 'LSASS Memory', 'evidence': 'mimikatz.exe'}],\n"
      "    filtered_noise_summary='Collapsed 80 background svchost/conhost events.'\n"
      ")\n"
      "```\n"
  )
  test_lm = dspy.LM(
      "test/scripted", engine=ScriptedRLMEngine([step_0_resp]), cache=False
  )
  monkeypatch.setattr(
      rlm_engine,
      "configure_secops_rlm_lms",
      lambda lm=None, sub_lm=None: (test_lm, test_lm),
  )

  with patch(
      "secops_mcp.tools.rlm_security_events.get_chronicle_client",
      return_value=mock_chronicle,
  ):
    res = await rlm_investigate_entity_timeline(
        entity_value="activedir.stackedpads.local",
        start_time="2026-10-31T14:18:00Z",
        end_time="2026-10-31T14:27:00Z",
        max_api_calls=2,
    )
    assert res["tool"] == "rlm_investigate_entity_timeline"
    assert "MimiKatz Command Arguments" in res["verdict_and_summary"]
    assert "Budget exhausted on 3rd call: True" in res["answer"]
    assert res["compression_metrics"]["api_calls_made"] == 2
    assert res["compression_metrics"]["reduction_pct"] > 95.0
