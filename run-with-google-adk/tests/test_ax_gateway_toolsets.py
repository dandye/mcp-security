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
"""Unit tests for AX Workspace MCP gateway discovery and zero-secret sandbox hardening."""

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
from mcp_security_agent.config import (  # noqa: E402
    AgentSettings,
    discover_user_identity,
)
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


def test_discover_ax_metadata_url_loopback_and_rejects_remote_or_redirect() -> None:
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

  # Non-loopback AX_METADATA_URL is rejected to prevent SSRF to 169.254.169.254
  with pytest.raises(ValueError, match="loopback"):
    discover_ax_workspace_mcp_endpoints(
        environ={"AX_METADATA_URL": "http://169.254.169.254"}
    )


def test_zero_secret_sandbox_ignores_dotenv_and_rejects_leaked_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
  # 1. Leaked VT_APIKEY in os.environ fails closed BEFORE network/dotenv without echoing value.
  secret_value = "super-secret-vt-key-do-not-echo-99999"
  with patch.dict(
      os.environ,
      {
          "AX_ZERO_SECRET_SANDBOX": "true",
          "HOME": str(tmp_path),
          "VT_APIKEY": secret_value,
      },
      clear=True,
  ):
    with pytest.raises(ValueError, match="os.environ:VT_APIKEY") as exc_info:
      AgentSettings()
    assert secret_value not in str(exc_info.value)

  # 2. Poisoned /workspace/.env is ignored when AX_ZERO_SECRET_SANDBOX=true.
  ws_dir = tmp_path / "poisoned_ws"
  ws_dir.mkdir()
  (ws_dir / ".env").write_text(
      "VT_APIKEY=poisoned-dotenv-secret\nGOOGLE_API_KEY=AIzaPoisonedKey123456789012345678\n",
      encoding="utf-8",
  )
  monkeypatch.chdir(ws_dir)
  with patch.dict(
      os.environ,
      {
          "AX_ZERO_SECRET_SANDBOX": "true",
          "HOME": str(tmp_path),
          "SECOPS_MCP_URL": "http://secops-mcp.secops-gateways.svc.cluster.local:8080/mcp",
      },
      clear=True,
  ):
    clean_settings = AgentSettings()
    assert clean_settings.vt_apikey is None
    assert clean_settings.google_api_key is None
    assert discover_user_identity() == "ax_sandbox_agent"

  # 3. Custom MCP_GATEWAY_AUTH_HEADER (possible real token) is rejected in zero-secret mode.
  with pytest.raises(ValueError, match="MCP_GATEWAY_AUTH_HEADER"):
    verify_zero_secret_sandbox(
        environ={
            "AX_ZERO_SECRET_SANDBOX": "true",
            "HOME": str(tmp_path),
            "MCP_GATEWAY_AUTH_HEADER": "Bearer real-token-attempt",
        },
        k8s_sa_token_path=str(tmp_path / "no-k8s-token"),
    )

  # 4. Mounted local ADC file in HOME fails closed in zero-secret mode.
  adc_dir = tmp_path / "adc_home" / ".config" / "gcloud"
  adc_dir.mkdir(parents=True)
  (adc_dir / "application_default_credentials.json").write_text("{}", encoding="utf-8")
  with pytest.raises(ValueError, match="application_default_credentials.json"):
    verify_zero_secret_sandbox(
        environ={
            "AX_ZERO_SECRET_SANDBOX": "true",
            "HOME": str(tmp_path / "adc_home"),
            "MCP_GATEWAY_AUTH_HEADER": "Bearer ate-egress-injected",
        },
        k8s_sa_token_path=str(tmp_path / "no-k8s-token"),
    )

  # 5. Leaked OAuth token in /proc/self/environ fails closed even if cleared from os.environ.
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
            "HOME": str(tmp_path),
            "MCP_GATEWAY_AUTH_HEADER": "Bearer ate-egress-injected",
        },
        proc_environ_path=str(proc_env),
        k8s_sa_token_path=str(tmp_path / "no-k8s-token"),
    )
  assert synthetic_oauth not in str(exc_info.value)


def test_zero_secret_sandbox_forbids_stdio_fallback_and_missing_llm_gateway(
    tmp_path: Path,
) -> None:
  from mcp_security_agent.agent import create_security_agent

  with patch.dict(
      os.environ,
      {
          "AX_ZERO_SECRET_SANDBOX": "true",
          "HOME": str(tmp_path),
          "LOAD_SECOPS_MCP": "Y",
          "LLM_GATEWAY_URL": "http://llm-gateway.secops-gateways.svc.cluster.local:8080/vertex",
          "GOOGLE_CLOUD_PROJECT": "my-secops-project",
      },
      clear=True,
  ):
    settings = AgentSettings()
    with pytest.raises(ValueError, match="cannot spawn local stdio MCP server"):
      build_mcp_toolsets(settings)

  with patch.dict(
      os.environ,
      {
          "AX_ZERO_SECRET_SANDBOX": "true",
          "HOME": str(tmp_path),
          "SECOPS_MCP_URL": "http://secops-mcp.secops-gateways.svc.cluster.local:8080/mcp",
          "GOOGLE_CLOUD_PROJECT": "my-secops-project",
      },
      clear=True,
  ):
    settings_no_llm = AgentSettings()
    with pytest.raises(ValueError, match="LLM_GATEWAY_URL"):
      create_security_agent(settings_no_llm)


def test_zero_secret_sandbox_agent_builds_egress_llm(tmp_path: Path) -> None:
  """Verifies create_security_agent uses placeholder credentials + LLM_GATEWAY_URL in zero-secret mode."""
  from google.adk.models.google_llm import Gemini
  from mcp_security_agent.agent import create_security_agent

  with patch.dict(
      os.environ,
      {
          "AX_ZERO_SECRET_SANDBOX": "true",
          "HOME": str(tmp_path),
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
