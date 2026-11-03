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
"""Tests for DSPy RLM network infrastructure tools (IP, domain, URL)."""

import json
import typing

import pytest

from gti_mcp import rlm_engine
from gti_mcp.tools import rlm_netloc
from gti_mcp.tools.urls import url_to_base64


IP_SAMPLE = "206.221.181.253"
DOMAIN_SAMPLE = "cdn-update-telemetry.com"
URL_SAMPLE = "http://206.221.181.253/data/cheditor/dir2/F.php"
FILE_SHA256_SAMPLE = (
    "29a8b2a2dbac349f919923d25af4f9162bc58c29b2daac41a56f5b25ba24276d"
)


class ScriptedRLMEngine:
  """Hermetic dspy>=3.4.1 engine implementing complete(request) -> Response."""

  def __init__(self, responses: list[str]) -> None:
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


def make_bloated_ip_report() -> dict[str, typing.Any]:
  """Constructs a realistic 90KB+ VirusTotal v3 IP address report fixture."""
  vendor_results = {
      f"Scanner_{i:02d}": {
          "category": "malicious" if i < 6 else "harmless",
          "engine_name": f"Scanner_{i:02d}",
          "result": "malicious" if i < 6 else "clean",
          "method": "blacklist",
      }
      for i in range(92)
  }
  whois_blob = "\n".join(
      f"NetRange: 206.221.176.0 - 206.221.191.255Line_{i:03d}: ReliableSite Hosting Infrastructure"
      for i in range(600)
  )
  return {
      "id": IP_SAMPLE,
      "type": "ip_address",
      "attributes": {
          "asn": 23470,
          "as_owner": "ReliableSite.Net LLC",
          "country": "US",
          "continent": "NA",
          "network": "206.221.176.0/20",
          "regional_internet_registry": "ARIN",
          "jarm": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
          "reputation": -18,
          "whois": whois_blob,
          "last_analysis_stats": {
              "malicious": 6,
              "suspicious": 1,
              "undetected": 31,
              "harmless": 54,
              "timeout": 0,
          },
          "gti_assessment": {
              "verdict": {"value": "VERDICT_MALICIOUS"},
              "severity": {"value": "SEVERITY_HIGH"},
              "threat_score": {"value": 85},
          },
          "last_https_certificate": {
              "thumbprint_sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
              "serial_number": "04a1b2c3d4",
              "subject": {"CN": "iquadrigacx.com"},
              "issuer": {"CN": "R3", "O": "Let's Encrypt"},
              "validity": {
                  "not_before": "2026-09-01 00:00:00",
                  "not_after": "2026-12-01 00:00:00",
              },
          },
          "last_analysis_results": vendor_results,
      },
      "relationships": {
          "resolutions": {
              "data": [
                  {
                      "type": "resolution",
                      "id": f"{IP_SAMPLE}iquadrigacx.com",
                      "attributes": {
                          "host_name": "iquadrigacx.com",
                          "ip_address": IP_SAMPLE,
                          "date": 1761868800,
                      },
                  }
              ]
          },
          "downloaded_files": {
              "data": [
                  {
                      "type": "file",
                      "id": FILE_SHA256_SAMPLE,
                  }
              ]
          },
          "urls": {
              "data": [
                  {
                      "type": "url",
                      "id": "6f55252f6aee0c214d7cd1865b36231ae0ad54178fd868e1c6b8910deabd6532",
                      "context_attributes": {
                          "url": URL_SAMPLE,
                      },
                  }
              ]
          },
          "associations": {
              "data": [
                  {
                      "type": "collection",
                      "id": "threat-actor--unc3313",
                      "attributes": {
                          "name": "UNC3313",
                          "collection_type": "threat-actor",
                      },
                  }
              ]
          },
      },
  }


def test_detect_network_ioc_type_identifies_ips_domains_and_urls():
  """detect_network_ioc_type resolves IPv4, IPv6, domain, and URL inputs."""
  assert rlm_netloc.detect_network_ioc_type("206.221.181.253") == "ip_address"
  assert rlm_netloc.detect_network_ioc_type("2001:4860:4860::8888") == "ip_address"
  assert rlm_netloc.detect_network_ioc_type("cdn-update-telemetry.com") == "domain"
  assert (
      rlm_netloc.detect_network_ioc_type("http://206.221.181.253/payload.exe")
      == "url"
  )
  assert (
      rlm_netloc.detect_network_ioc_type("cdn-update-telemetry.com/login")
      == "url"
  )
  assert (
      rlm_netloc.detect_network_ioc_type("206.221.181.253", ioc_type="ip")
      == "ip_address"
  )
  assert (
      rlm_netloc.detect_network_ioc_type("example.org", ioc_type="fqdn")
      == "domain"
  )


def test_extract_verbatim_anchors_and_deterministic_distill_on_ip_report():
  """IP report distillation preserves network_infrastructure anchors, resolutions, URLs, and downloaded hashes."""
  ip_report = make_bloated_ip_report()
  anchors = rlm_engine.extract_verbatim_anchors(ip_report)

  net_infra = anchors.get("network_infrastructure", {})
  assert net_infra["asn"] == 23470
  assert net_infra["as_owner"] == "ReliableSite.Net LLC"
  assert net_infra["country"] == "US"
  assert net_infra["network"] == "206.221.176.0/20"
  assert net_infra["jarm"].startswith("27d40d40d29d40d1dc42d43d")
  assert net_infra["tls_certificate"]["subject_cn"] == "iquadrigacx.com"

  distilled = rlm_engine.deterministic_distill_payload(
      ip_report,
      entity_id=IP_SAMPLE,
      tool_name="rlm_get_ip_address_report",
      query="Identify ASN, passive DNS resolutions, downloaded files, and threat actor attributions.",
  )
  assert distilled["compression_metrics"]["reduction_pct"] > 80.0
  assert any(
      "iquadrigacx.com" in ioc
      for ioc in distilled["high_signal_iocs"]["network"]
  )
  assert URL_SAMPLE in distilled["high_signal_iocs"]["network"]
  assert any(
      FILE_SHA256_SAMPLE in f
      for f in distilled["high_signal_iocs"]["files_dropped_or_modified"]
  )
  assert any(a["name"] == "UNC3313" for a in distilled["attributions"])
  assert any("ASN=23470" in f for f in distilled["key_findings"])


@pytest.mark.asyncio(loop_scope="session")
async def test_rlm_network_report_tools_end_to_end(
    make_httpserver_ipv4, monkeypatch
):
  """rlm_get_ip_address_report, rlm_get_domain_report, and rlm_get_url_report execute via FastMCP."""
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
  monkeypatch.setattr(
      rlm_engine, "configure_gti_rlm_lms", lambda lm=None, sub_lm=None: (None, None)
  )

  ip_report = make_bloated_ip_report()
  make_httpserver_ipv4.expect_request(
      f"/api/v3/ip_addresses/{IP_SAMPLE}",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"data": ip_report})

  domain_report = {
      "id": DOMAIN_SAMPLE,
      "type": "domain",
      "attributes": {
          "registrar": "NameCheap, Inc.",
          "reputation": -42,
          "last_analysis_stats": {"malicious": 14, "suspicious": 2, "harmless": 60, "undetected": 14},
          "last_dns_records": [{"type": "A", "value": IP_SAMPLE, "ttl": 300}],
      },
      "relationships": {
          "communicating_files": {
              "data": [{"type": "file", "id": FILE_SHA256_SAMPLE}]
          }
      },
  }
  make_httpserver_ipv4.expect_request(
      f"/api/v3/domains/{DOMAIN_SAMPLE}",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"data": domain_report})

  url_id = url_to_base64(URL_SAMPLE)
  url_report = {
      "id": url_id,
      "type": "url",
      "attributes": {
          "url": URL_SAMPLE,
          "final_url": URL_SAMPLE,
          "last_http_response_code": 200,
          "last_http_response_content_sha256": FILE_SHA256_SAMPLE,
          "last_analysis_stats": {"malicious": 9, "suspicious": 1, "harmless": 65, "undetected": 15},
      },
      "relationships": {
          "downloaded_files": {
              "data": [{"type": "file", "id": FILE_SHA256_SAMPLE}]
          }
      },
  }
  make_httpserver_ipv4.expect_request(
      f"/api/v3/urls/{url_id}",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"data": url_report})

  async with client_session(server._mcp_server) as client:
    res_ip = await client.call_tool(
        "rlm_get_ip_address_report", {"ip_address": IP_SAMPLE}
    )
    assert not res_ip.isError
    ip_data = json.loads(res_ip.content[0].text)
    assert ip_data["id"] == IP_SAMPLE
    assert (
        ip_data["verbatim_anchors"]["network_infrastructure"]["asn"] == 23470
    )

    res_dom = await client.call_tool(
        "rlm_get_domain_report", {"domain": DOMAIN_SAMPLE}
    )
    assert not res_dom.isError
    dom_data = json.loads(res_dom.content[0].text)
    assert dom_data["id"] == DOMAIN_SAMPLE
    assert f"A:{IP_SAMPLE}" in dom_data["high_signal_iocs"]["network"]

    res_url = await client.call_tool(
        "rlm_get_url_report", {"url": URL_SAMPLE}
    )
    assert not res_url.isError
    url_data = json.loads(res_url.content[0].text)
    assert url_data["id"] == URL_SAMPLE
    assert (
        url_data["verbatim_anchors"]["network_infrastructure"][
            "last_http_response_code"
        ]
        == 200
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_rlm_investigate_network_ioc_pivots_across_files_urls_and_resolutions(
    make_httpserver_ipv4, monkeypatch
):
  """rlm_investigate_network_ioc pivots into full downloaded_files, resolutions, and urls inside the REPL."""
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

  ip_report = make_bloated_ip_report()
  make_httpserver_ipv4.expect_request(
      f"/api/v3/ip_addresses/{IP_SAMPLE}",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json({"data": ip_report})

  make_httpserver_ipv4.expect_request(
      f"/api/v3/ip_addresses/{IP_SAMPLE}/downloaded_files",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": [
              {
                  "id": FILE_SHA256_SAMPLE,
                  "type": "file",
                  "attributes": {
                      "sha256": FILE_SHA256_SAMPLE,
                      "md5": "bb8bdb3e8c92e97e2f63626bc3b254c4",
                      "meaningful_name": "mimikatz_stage.exe",
                      "first_submission_date": 1761868000,
                      "last_analysis_stats": {"malicious": 48, "undetected": 24},
                      "popular_threat_classification": {
                          "suggested_threat_label": "hacktool.mimikatz/credstealer"
                      },
                  },
              }
          ]
      }
  )

  make_httpserver_ipv4.expect_request(
      f"/api/v3/ip_addresses/{IP_SAMPLE}/urls",
      method="GET",
      headers={"X-Apikey": "dummy_api_key"},
  ).respond_with_json(
      {
          "data": [
              {
                  "id": "6f55252f6aee0c214d7cd1865b36231ae0ad54178fd868e1c6b8910deabd6532",
                  "type": "url",
                  "attributes": {
                      "url": URL_SAMPLE,
                      "last_http_response_code": 200,
                      "last_analysis_stats": {"malicious": 11, "harmless": 60},
                  },
                  "context_attributes": {"url": URL_SAMPLE},
              }
          ]
      }
  )

  step_0_resp = (
      "[[ ## reasoning ## ]]\n"
      "Pivot into downloaded_files and related_urls for IP 206.221.181.253.\n\n"
      "[[ ## code ## ]]\n"
      "```python\n"
      "dl_files = fetch_downloaded_files(5)\n"
      "rel_urls = fetch_related_urls(5)\n"
      "over_cap = fetch_resolutions(5)\n"
      "f0 = dl_files[0] if dl_files else {}\n"
      "u0 = rel_urls[0] if rel_urls else {}\n"
      "SUBMIT(\n"
      "    verdict_and_summary=f'Malicious staging IP {entity_id} (ASN 23470 ReliableSite.Net LLC) hosting {f0.get(\"meaningful_name\")}',\n"
      "    answer=f'Downloaded file {f0.get(\"sha256\")} via URL {u0.get(\"url\")} (HTTP {u0.get(\"last_http_response_code\")}). Budget cap: {\"budget_exhausted\" in over_cap}',\n"
      "    key_findings=['ASN 23470 ReliableSite.Net LLC', f'Payload: {f0.get(\"meaningful_name\")} ({f0.get(\"sha256\")})'],\n"
      "    high_signal_iocs={'network': [u0.get('url', ''), 'iquadrigacx.com'], 'files_dropped_or_modified': [f0.get('sha256', '')], 'process_and_command_lines': [], 'persistence_and_mutexes': [], 'yara_and_sigma_matches': []},\n"
      "    attributions=[{'id': 'threat-actor--unc3313', 'name': 'UNC3313', 'collection_type': 'threat-actor'}],\n"
      "    mitre_techniques=[{'id': 'T1105', 'name': 'Ingress Tool Transfer', 'evidence': u0.get('url', '')}],\n"
      "    filtered_noise_summary='Omitted raw WHOIS lines and harmless URL scanner entries.'\n"
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
        "rlm_investigate_network_ioc",
        {
            "ioc": IP_SAMPLE,
            "ioc_type": "auto",
            "investigation_goal": "Pivot into downloaded files and staging URLs on 206.221.181.253.",
            "max_api_calls": 3,
        },
    )
    assert not res.isError
    payload = json.loads(res.content[0].text)
    assert payload["id"] == IP_SAMPLE
    assert payload["tool"] == "rlm_investigate_network_ioc"
    assert (
        payload["verbatim_anchors"]["network_infrastructure"]["asn"] == 23470
    )
    assert "Budget cap: True" in payload["answer"]
    assert FILE_SHA256_SAMPLE in payload["answer"]
    assert payload["compression_metrics"]["api_calls_made"] == 3
    assert payload["compression_metrics"]["endpoints_called"] == [
        f"/ip_addresses/{IP_SAMPLE}",
        f"/ip_addresses/{IP_SAMPLE}/downloaded_files",
        f"/ip_addresses/{IP_SAMPLE}/urls",
    ]
    assert payload["compression_metrics"]["reduction_pct"] > 80.0
