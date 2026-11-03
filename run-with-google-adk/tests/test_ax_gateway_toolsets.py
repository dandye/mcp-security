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
"""Unit tests for AX Workspace MCP gateway discovery and zero-secret sandbox mode."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import sys
import threading
from unittest.mock import patch

import pytest

src_dir = str(Path(__file__).resolve().parents[1] / "src")
if src_dir not in sys.path:
  sys.path.insert(0, src_dir)

from mcp_security_agent.ax_workspace import (  # noqa: E402
    DEFAULT_GATEWAY_AUTH_PLACEHOLDER,
    discover_ax_workspace_mcp_endpoints,
    verify_zero_secret_sandbox,
)
from mcp_security_agent.config import AgentSettings  # noqa: E402
from mcp_security_agent.toolsets import build_mcp_toolsets  # noqa: E402

SAMPLE_AX_WORKSPACE_YAML = """
apiVersion: ax.io/v1alpha1
kind: Workspace
metadata:
  name: secops-gateway-ws
  atespace: secops
spec:
  mcp:
    servers:
      - name: secops
        endpoint: "http://secops-mcp.secops-gateways.svc.cluster.local:8080/mcp"
      - name: gti
        endpoint: "http://gti-mcp.secops-gateways.svc.cluster.local:8080/mcp"
      - name: secops-soar
        endpoint: "http://secops-soar-mcp.secops-gateways.svc.cluster.local:8080/mcp"
      - name: scc
        endpoint: "http://scc-mcp.secops-gateways.svc.cluster.local:8080/mcp"
"""


def test_discover_ax_workspace_yaml_populates_all_four_streamable_http_toolsets() -> None:
  with patch.dict(
      os.environ,
      {
          "AX_ZERO_SECRET_SANDBOX": "true",
          "AX_WORKSPACE_YAML": SAMPLE_AX_WORKSPACE_YAML,
      },
      clear=True,
  ):
    settings = AgentSettings(_env_file=None)
    assert settings.ax_zero_secret_sandbox is True
    assert settings.mcp_gateway_auth_header == DEFAULT_GATEWAY_AUTH_PLACEHOLDER
    assert settings.load_secops_mcp is True
    assert settings.load_gti_mcp is True
    assert settings.load_secops_soar_mcp is True
    assert settings.load_scc_mcp is True

    with patch(
        "google.adk.tools.mcp_tool.mcp_toolset.McpToolset",
        side_effect=lambda connection_params: connection_params,
    ):
      toolsets = build_mcp_toolsets(settings)
      assert len(toolsets) == 4
      urls = {conn.url for conn in toolsets}
      assert urls == {
          "http://secops-mcp.secops-gateways.svc.cluster.local:8080/mcp",
          "http://gti-mcp.secops-gateways.svc.cluster.local:8080/mcp",
          "http://secops-soar-mcp.secops-gateways.svc.cluster.local:8080/mcp",
          "http://scc-mcp.secops-gateways.svc.cluster.local:8080/mcp",
      }
      for conn in toolsets:
        assert conn.headers == {"Authorization": "Bearer ate-egress-injected"}


def test_discover_ax_metadata_url_loopback_endpoint() -> None:
  class _MetadataHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
      if self.path == "/metadata/v1alpha1/ax/workspace":
        body = SAMPLE_AX_WORKSPACE_YAML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/yaml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
      else:
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
      return

  httpd = HTTPServer(("127.0.0.1", 0), _MetadataHandler)
  port = httpd.server_address[1]
  thread = threading.Thread(target=httpd.serve_forever, daemon=True)
  thread.start()
  try:
    discovered = discover_ax_workspace_mcp_endpoints(
        environ={"AX_METADATA_URL": f"http://127.0.0.1:{port}"}
    )
    assert discovered == {
        "secops": "http://secops-mcp.secops-gateways.svc.cluster.local:8080/mcp",
        "gti": "http://gti-mcp.secops-gateways.svc.cluster.local:8080/mcp",
        "secops_soar": "http://secops-soar-mcp.secops-gateways.svc.cluster.local:8080/mcp",
        "scc": "http://scc-mcp.secops-gateways.svc.cluster.local:8080/mcp",
    }
  finally:
    httpd.shutdown()
    httpd.server_close()


def test_zero_secret_sandbox_rejects_leaked_secrets_in_env_and_proc(
    tmp_path: Path,
) -> None:
  # 1. Leaked VT_APIKEY in os.environ fails closed without echoing the secret value.
  secret_value = "super-secret-vt-key-do-not-echo-99999"
  with patch.dict(
      os.environ,
      {
          "AX_ZERO_SECRET_SANDBOX": "true",
          "VT_APIKEY": secret_value,
      },
      clear=True,
  ):
    with pytest.raises(ValueError, match="os.environ:VT_APIKEY") as exc_info:
      AgentSettings(_env_file=None)
    assert secret_value not in str(exc_info.value)

  # 2. Leaked OAuth token in /proc/self/environ fails closed even if cleared from os.environ.
  synthetic_oauth = "ya" + "29.synthetic_unit_test_leak_fixture"
  proc_env = tmp_path / "proc_environ"
  proc_env.write_bytes(
      f"AX_ZERO_SECRET_SANDBOX=true\x00STRAY_VAR={synthetic_oauth}\x00".encode(
          "utf-8"
      )
  )
  with pytest.raises(ValueError, match="google_oauth_access_token") as exc_info:
    verify_zero_secret_sandbox(
        environ={
            "AX_ZERO_SECRET_SANDBOX": "true",
            "MCP_GATEWAY_AUTH_HEADER": "Bearer ate-egress-injected",
        },
        proc_environ_path=str(proc_env),
    )
  assert synthetic_oauth not in str(exc_info.value)


def test_zero_secret_sandbox_agent_builds_egress_llm() -> None:
  """Verifies create_security_agent uses placeholder credentials + LLM_GATEWAY_URL in zero-secret mode."""
  from google.adk.models.google_llm import Gemini
  from mcp_security_agent.agent import create_security_agent

  with patch.dict(
      os.environ,
      {
          "AX_ZERO_SECRET_SANDBOX": "true",
          "SECOPS_MCP_URL": "http://secops-mcp.secops-gateways.svc.cluster.local:8080/mcp",
          "LLM_GATEWAY_URL": "http://llm-gateway.secops-gateways.svc.cluster.local:8080/vertex",
          "GOOGLE_CLOUD_PROJECT": "my-secops-project",
          "GOOGLE_CLOUD_LOCATION": "global",
          "GOOGLE_MODEL": "gemini-3.8-flash",
      },
      clear=True,
  ):
    settings = AgentSettings(_env_file=None)
    agent = create_security_agent(settings)
    assert isinstance(agent.model, Gemini)
    assert (
        agent.model.base_url
        == "http://llm-gateway.secops-gateways.svc.cluster.local:8080/vertex"
    )
    creds = agent.model.client_kwargs["credentials"]
    assert creds.valid is True
    assert creds.expired is False
    assert creds.token == "ate-egress-injected"
