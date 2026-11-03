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
"""Live multi-process end-to-end verification for Out-of-Sandbox MCP & LLM Gateways.

Spawns five out-of-sandbox `mcp-security-gateway` Uvicorn processes (`secops`,
`gti`, `secops-soar` with `SOAR_INTEGRATIONS=Siemplify`, `scc`, and `vertex-llm`)
backed by live credentials, starts a local `atenet-egress` HTTP mediation proxy
that replaces present `Authorization` headers with per-service ES256 `KindActor`
JWTs, and runs `/usr/local/bin/ax-task-runner` (`ax_task_runner`, deployments/ax-task-runner)
supervising a sanitized `AX_ZERO_SECRET_SANDBOX=true` child process with zero
credentials in `os.environ`, `/proc/self/environ`, or `/workspace` to verify:
1. AX `ax-task-runner` `/readyz` probe, `/workspace` file materialization, and
   loopback `AX_METADATA_URL` MCP endpoint discovery.
2. Fail-closed zero-secret sandbox checks and live `actorJwt` boundary rejections
   (401 unauthenticated / missing header, 403 `worker-for-actor.ate.dev`).
3. Live Streamable HTTP tool execution across Chronicle SIEM, GTI, SOAR
   (verifying dynamic `SOAR_INTEGRATIONS` marketplace tools), and SCC.
4. Live Google ADK `create_security_agent()` multi-tool execution through the
   out-of-sandbox `vertex-llm` Gemini gateway.
"""

import asyncio
import base64
from contextlib import AsyncExitStack
import json
import logging
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO
import uuid

from cryptography.hazmat.primitives.asymmetric import ec
import google.auth
from google.auth.transport.requests import Request as GoogleAuthRequest
import httpx
import jwt
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

logger = logging.getLogger(__name__)

ACTOR_JWT_ISSUER = "https://idp.ate-system.svc"
WANNACRY_SHA256 = (
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
)


def _b64url_uint(val: int, length: int) -> str:
  return (
      base64.urlsafe_b64encode(val.to_bytes(length, "big"))
      .rstrip(b"=")
      .decode("ascii")
  )


def _free_port() -> int:
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    return int(sock.getsockname()[1])


def _mint_es256_jwks() -> tuple[ec.EllipticCurvePrivateKey, str, dict[str, Any]]:
  priv = ec.generate_private_key(ec.SECP256R1())
  nums = priv.public_key().public_numbers()
  kid = "ate-live-es256-kid-1"
  jwks = {
      "keys": [
          {
              "kty": "EC",
              "crv": "P-256",
              "alg": "ES256",
              "use": "sig",
              "kid": kid,
              "x": _b64url_uint(nums.x, 32),
              "y": _b64url_uint(nums.y, 32),
          }
      ]
  }
  return priv, kid, jwks


def _sign_actor_jwt(
    priv_key: ec.EllipticCurvePrivateKey,
    kid: str,
    *,
    atespace: str,
    actor_name: str,
    actor_uid: str,
    audience: str,
    worker_token: bool = False,
) -> str:
  now = int(time.time())
  claims: dict[str, Any] = {
      "iss": ACTOR_JWT_ISSUER,
      "sub": f"actor/{atespace}/{actor_name}",
      "aud": [audience],
      "iat": now,
      "nbf": now,
      "exp": now + 300,
      "jti": str(uuid.uuid4()),
  }
  if worker_token:
    claims["worker-for-actor.ate.dev"] = {
        "atespace": atespace,
        "actorName": actor_name,
        "actorUID": actor_uid,
        "node": "worker-node-1",
    }
  else:
    claims["actor.ate.dev"] = {
        "atespace": atespace,
        "actorName": actor_name,
        "actorUID": actor_uid,
    }
  return jwt.encode(
      claims, priv_key, algorithm="ES256", headers={"kid": kid, "typ": "JWT"}
  )


async def _run_zero_secret_sandbox_child(result_file: Path) -> None:
  """Executes inside the sanitized zero-secret child process supervised by ax-task-runner."""
  from google.adk.runners import InMemoryRunner
  from google.genai import types as genai_types
  from mcp_security_agent.agent import create_security_agent
  from mcp_security_agent.ax_workspace import verify_zero_secret_sandbox
  from mcp_security_agent.config import AgentSettings, discover_user_identity

  guard_result = verify_zero_secret_sandbox()
  assert guard_result == {"zero_secret_sandbox": True, "verified": True}
  for forbidden in (
      "VT_APIKEY",
      "SOAR_APP_KEY",
      "SECOPS_SA_PATH",
      "GOOGLE_APPLICATION_CREDENTIALS",
      "GOOGLE_API_KEY",
      "GEMINI_API_KEY",
  ):
    assert os.environ.get(forbidden) is None, f"Leaked {forbidden}!"

  # Verify ax-task-runner materialized Workspace.spec.files and exported AX_METADATA_URL.
  agents_md = Path.cwd() / "AGENTS.md"
  assert agents_md.is_file(), "Expected ax-task-runner to materialize /workspace/AGENTS.md"
  assert os.environ.get("AX_METADATA_URL", "").startswith("http://127.0.0.1:")
  assert discover_user_identity() == "ax_sandbox_agent"

  settings = AgentSettings()
  assert settings.ax_zero_secret_sandbox is True
  assert settings.mcp_gateway_auth_header == "Bearer ate-egress-injected"
  assert settings.llm_gateway_url

  logger.info(
      "Zero-secret sandbox check + loopback AX_METADATA_URL discovery passed"
  )
  headers = {"Authorization": settings.mcp_gateway_auth_header}

  async def _call_gateway(
      name: str,
      url: str,
      tool_name: str,
      args: dict[str, Any],
      *,
      min_tools: int = 1,
  ) -> list[str]:
    async with AsyncExitStack() as stack:
      read_s, write_s, _ = await stack.enter_async_context(
          streamablehttp_client(url=url, headers=headers, timeout=45.0)
      )
      session = await stack.enter_async_context(ClientSession(read_s, write_s))
      await session.initialize()
      tools_resp = await session.list_tools()
      tool_names = [t.name for t in tools_resp.tools]
      assert len(tool_names) >= min_tools, (
          f"Expected >= {min_tools} tools on {name}, got {len(tool_names)}: {tool_names}"
      )
      assert tool_name in tool_names, f"{tool_name} missing from {name}"
      t0 = time.monotonic()
      call_resp = await session.call_tool(tool_name, args)
      elapsed = time.monotonic() - t0
      assert not call_resp.isError, f"{name}.{tool_name} returned error"
      text = "\n".join(
          getattr(part, "text", str(part)) for part in call_resp.content
      )
      logger.info(
          "[SANDBOX -> EGRESS -> %s] tools=%s call=%s latency=%.2fs bytes=%s",
          name.upper(),
          len(tool_names),
          tool_name,
          elapsed,
          len(text),
      )
      return tool_names

  if settings.secops_mcp_url:
    await _call_gateway(
        "secops",
        settings.secops_mcp_url,
        "get_security_alerts",
        {"hours_back": 720, "max_alerts": 3},
    )
  if settings.gti_mcp_url:
    await _call_gateway(
        "gti",
        settings.gti_mcp_url,
        "get_file_report",
        {"hash": WANNACRY_SHA256},
    )
  if settings.secops_soar_mcp_url:
    soar_tools = await _call_gateway(
        "secops-soar",
        settings.secops_soar_mcp_url,
        "list_cases",
        {},
        min_tools=18,
    )
    assert any(t.startswith("siemplify_") for t in soar_tools), (
        f"Expected Siemplify marketplace tools to be registered, got {soar_tools}"
    )
  if settings.scc_mcp_url:
    await _call_gateway(
        "scc",
        settings.scc_mcp_url,
        "search_findings",
        {"project_id": settings.google_cloud_project, "max_findings": 3},
    )

  allowed_tools = {
      "get_security_alerts",
      "get_file_report",
      "list_cases",
      "search_findings",
  }
  settings.default_prompt = (
      "You are a SOC analyst running inside a zero-secret AX sandbox. "
      "Invoke all available tools (`get_security_alerts` with hours_back=720 and max_alerts=2, "
      f"`get_file_report` for hash {WANNACRY_SHA256}, `list_cases`, and "
      f"`search_findings` with project_id='{settings.google_cloud_project}' and max_findings=2) "
      "and return a concise bulleted summary of the live findings. Do not use emojis."
  )
  agent = create_security_agent(settings)
  for toolset in agent.tools:
    toolset.tool_filter = list(allowed_tools)

  runner = InMemoryRunner(agent=agent, app_name="ax_zero_secret_live_e2e")
  session = await runner.session_service.create_session(
      app_name="ax_zero_secret_live_e2e", user_id="ax-sandbox-actor"
  )
  user_msg = genai_types.Content(
      role="user",
      parts=[
          genai_types.Part.from_text(
              text=(
                  "Run a live cross-platform posture and threat check across SIEM alerts, "
                  f"GTI hash {WANNACRY_SHA256}, SOAR cases, and SCC findings."
              )
          )
      ],
  )

  called_tools: list[str] = []
  final_texts: list[str] = []
  t_agent = time.monotonic()
  async for event in runner.run_async(
      user_id="ax-sandbox-actor",
      session_id=session.id,
      new_message=user_msg,
  ):
    for fc in event.get_function_calls() or []:
      called_tools.append(fc.name)
    if event.is_final_response() and event.content and event.content.parts:
      for part in event.content.parts:
        if getattr(part, "text", None):
          final_texts.append(part.text)

  await runner.close()
  logger.info(
      "[SANDBOX ADK AGENT -> VERTEX-LLM GATEWAY] Completed in %.2fs; invoked_tools=%s",
      time.monotonic() - t_agent,
      called_tools,
  )
  summary = "\n".join(final_texts).strip()
  assert summary, "Expected non-empty final ADK agent response"
  print(summary)
  result_file.write_text(
      json.dumps({"status": "ok", "invoked_tools": called_tools}),
      encoding="utf-8",
  )


async def _wait_http_ready(
    url: str, headers: dict[str, str], timeout_s: float = 40.0
) -> None:
  deadline = time.monotonic() + timeout_s
  last_err = ""
  async with httpx.AsyncClient(timeout=3.0) as client:
    while time.monotonic() < deadline:
      try:
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
          return
        last_err = f"status={resp.status_code}"
      except Exception as exc:
        last_err = f"{type(exc).__name__}: {exc}"
      await asyncio.sleep(0.3)
  raise RuntimeError(f"Timed out waiting for {url}: {last_err}")


async def _run_orchestrator() -> None:
  priv_key, kid, jwks_doc = _mint_es256_jwks()
  actor_uid = str(uuid.uuid4())
  atespace = "secops"
  actor_name = "secops-triage-agent"

  gcp_creds, detected_proj = google.auth.default(
      scopes=["https://www.googleapis.com/auth/cloud-platform"]
  )
  gcp_creds.refresh(GoogleAuthRequest())
  project_id = (
      os.environ.get("CHRONICLE_PROJECT_ID")
      or os.environ.get("GOOGLE_CLOUD_PROJECT")
      or detected_proj
  )
  if not project_id:
    raise RuntimeError("Set CHRONICLE_PROJECT_ID or GOOGLE_CLOUD_PROJECT.")

  with tempfile.TemporaryDirectory(prefix="ax_live_gateways_") as tmp_dir_str:
    tmp_dir = Path(tmp_dir_str)
    jwks_path = tmp_dir / "jwks.json"
    jwks_path.write_text(json.dumps(jwks_doc), encoding="utf-8")

    server_specs: dict[str, dict[str, Any]] = {}
    if os.environ.get("CHRONICLE_PROJECT_ID") and os.environ.get(
        "CHRONICLE_CUSTOMER_ID"
    ):
      secops_env = {
          "CHRONICLE_PROJECT_ID": os.environ["CHRONICLE_PROJECT_ID"],
          "CHRONICLE_CUSTOMER_ID": os.environ["CHRONICLE_CUSTOMER_ID"],
          "CHRONICLE_REGION": os.environ.get("CHRONICLE_REGION", "us"),
      }
      if os.environ.get("SECOPS_SA_PATH"):
        secops_env["SECOPS_SA_PATH"] = os.environ["SECOPS_SA_PATH"]
      elif os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        secops_env["GOOGLE_APPLICATION_CREDENTIALS"] = os.environ[
            "GOOGLE_APPLICATION_CREDENTIALS"
        ]
      server_specs["secops"] = {
          "port": _free_port(),
          "svc_name": "secops-mcp",
          "aud": "http://secops-mcp.secops-gateways.svc.cluster.local:8080",
          "host_header": "secops-mcp.secops-gateways.svc.cluster.local",
          "env": secops_env,
      }

    if os.environ.get("VT_APIKEY"):
      server_specs["gti"] = {
          "port": _free_port(),
          "svc_name": "gti-mcp",
          "aud": "http://gti-mcp.secops-gateways.svc.cluster.local:8080",
          "host_header": "gti-mcp.secops-gateways.svc.cluster.local",
          "env": {"VT_APIKEY": os.environ["VT_APIKEY"]},
      }

    if os.environ.get("SOAR_URL") and os.environ.get("SOAR_APP_KEY"):
      server_specs["secops-soar"] = {
          "port": _free_port(),
          "svc_name": "secops-soar-mcp",
          "aud": "http://secops-soar-mcp.secops-gateways.svc.cluster.local:8080",
          "host_header": "secops-soar-mcp.secops-gateways.svc.cluster.local",
          "env": {
              "SOAR_URL": os.environ["SOAR_URL"],
              "SOAR_APP_KEY": os.environ["SOAR_APP_KEY"],
              "SOAR_INTEGRATIONS": os.environ.get(
                  "SOAR_INTEGRATIONS", "Siemplify"
              ),
              "GATEWAY_SKIP_SOAR_BIND": "false",
          },
      }

    adc_env: dict[str, str] = {"GOOGLE_CLOUD_PROJECT": project_id}
    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
      adc_env["GOOGLE_APPLICATION_CREDENTIALS"] = os.environ[
          "GOOGLE_APPLICATION_CREDENTIALS"
      ]
    if os.environ.get("CLOUDSDK_CONFIG"):
      adc_env["CLOUDSDK_CONFIG"] = os.environ["CLOUDSDK_CONFIG"]

    server_specs["scc"] = {
        "port": _free_port(),
        "svc_name": "scc-mcp",
        "aud": "http://scc-mcp.secops-gateways.svc.cluster.local:8080",
        "host_header": "scc-mcp.secops-gateways.svc.cluster.local",
        "env": dict(adc_env),
    }
    server_specs["vertex-llm"] = {
        "port": _free_port(),
        "svc_name": "llm-gateway",
        "aud": "http://llm-gateway.secops-gateways.svc.cluster.local:8080",
        "host_header": "llm-gateway.secops-gateways.svc.cluster.local",
        "env": {
            **adc_env,
            "GOOGLE_CLOUD_LOCATION": os.environ.get(
                "GOOGLE_CLOUD_LOCATION", "global"
            ),
        },
    }

    procs: dict[str, subprocess.Popen[bytes]] = {}
    open_log_handles: list[BinaryIO] = []
    runner_proc: subprocess.Popen[bytes] | None = None
    try:
      for name, spec in server_specs.items():
        log_path = tmp_dir / f"{name}.log"
        gw_env = {
            "PATH": os.environ["PATH"],
            "HOME": os.environ["HOME"],
            "GATEWAY_SERVER": name,
            "GATEWAY_SERVICE_NAME": spec["svc_name"],
            "GATEWAY_NAMESPACE": "secops-gateways",
            "GATEWAY_HOST": "127.0.0.1",
            "GATEWAY_PORT": str(spec["port"]),
            "GATEWAY_REQUIRE_ACTOR_JWT": "true",
            "GATEWAY_JWKS_PATH": str(jwks_path),
            "GATEWAY_EXPECTED_ISSUER": ACTOR_JWT_ISSUER,
            "GATEWAY_EXPECTED_AUDIENCE": spec["aud"],
            "GATEWAY_ALLOWED_ATESPACES": atespace,
            "GATEWAY_ALLOWED_ACTORS": f"{atespace}/{actor_name}",
            "GOOGLE_API_USE_CLIENT_CERTIFICATE": "false",
            "GOOGLE_API_USE_MTLS_ENDPOINT": "never",
            "CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE": "false",
            **spec["env"],
        }
        fh = log_path.open("wb")
        open_log_handles.append(fh)
        procs[name] = subprocess.Popen(
            [
                sys.executable,
                "-P",
                "-m",
                "ax_mcp_gateway.gateway",
                "--server",
                name,
                "--host",
                "127.0.0.1",
                "--port",
                str(spec["port"]),
            ],
            env=gw_env,
            stdout=fh,
            stderr=subprocess.STDOUT,
        )

      for name, spec in server_specs.items():
        ready_url = f"http://127.0.0.1:{spec['port']}/readyz"
        await _wait_http_ready(
            ready_url, headers={"Host": f"10.24.8.19:{spec['port']}"}
        )
        logger.info("Gateway %s ready on 127.0.0.1:%s", name, spec["port"])

      first_mcp = next(
          spec for k, spec in server_specs.items() if k != "vertex-llm"
      )
      async with httpx.AsyncClient(timeout=10.0) as raw_client:
        r_unauth = await raw_client.post(
            f"http://127.0.0.1:{first_mcp['port']}/mcp",
            headers={
                "Host": f"{first_mcp['host_header']}:{first_mcp['port']}",
                "Authorization": "Bearer ate-egress-injected",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert r_unauth.status_code == 401
        worker_jwt = _sign_actor_jwt(
            priv_key,
            kid,
            atespace=atespace,
            actor_name=actor_name,
            actor_uid=actor_uid,
            audience=first_mcp["aud"],
            worker_token=True,
        )
        r_worker = await raw_client.post(
            f"http://127.0.0.1:{first_mcp['port']}/mcp",
            headers={
                "Host": f"{first_mcp['host_header']}:{first_mcp['port']}",
                "Authorization": f"Bearer {worker_jwt}",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert r_worker.status_code == 403

      egress_port = _free_port()
      upstream_http = httpx.AsyncClient(timeout=90.0)

      async def _proxy_gateway(request: Request) -> Response:
        srv_name = request.path_params["srv"]
        rest = request.path_params.get("rest", "")
        spec = server_specs[srv_name]
        fwd_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in {"host", "authorization", "content-length"}
        }
        fwd_headers["Host"] = f"{spec['host_header']}:{spec['port']}"
        # Match real Agent Substrate atenet-egress replaceHeaders semantics:
        # only replace Authorization if the outbound request already carries it.
        if "authorization" in {k.lower() for k in request.headers}:
          minted = _sign_actor_jwt(
              priv_key,
              kid,
              atespace=atespace,
              actor_name=actor_name,
              actor_uid=actor_uid,
              audience=spec["aud"],
          )
          fwd_headers["Authorization"] = f"Bearer {minted}"
        target_url = f"http://127.0.0.1:{spec['port']}/{rest}"
        if request.url.query:
          target_url = f"{target_url}?{request.url.query}"
        resp = await upstream_http.request(
            request.method,
            target_url,
            headers=fwd_headers,
            content=await request.body(),
        )
        resp_headers = {
            k: v
            for k, v in resp.headers.items()
            if k.lower()
            not in {"transfer-encoding", "content-encoding", "content-length"}
        }
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=resp_headers,
        )

      egress_app = Starlette(
          routes=[
              Route(
                  "/egress/{srv}/{rest:path}",
                  _proxy_gateway,
                  methods=["GET", "POST", "DELETE"],
              ),
          ]
      )
      egress_server = uvicorn.Server(
          uvicorn.Config(
              egress_app, host="127.0.0.1", port=egress_port, log_level="warning"
          )
      )
      egress_task = asyncio.create_task(egress_server.serve())
      while not egress_server.started:
        await asyncio.sleep(0.05)

      # Verify missing Authorization header passes through egress unreplaced and is rejected 401.
      async with httpx.AsyncClient(timeout=10.0) as egress_test_client:
        first_mcp_key = next(k for k in server_specs if k != "vertex-llm")
        r_no_hdr = await egress_test_client.post(
            f"http://127.0.0.1:{egress_port}/egress/{first_mcp_key}/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert r_no_hdr.status_code == 401

      mcp_gateway_names = [k for k in server_specs if k != "vertex-llm"]
      ax_workspace_yaml = json.dumps(
          {
              "apiVersion": "ax.io/v1alpha1",
              "kind": "Workspace",
              "metadata": {"name": "secops-gateway-ws", "atespace": atespace},
              "spec": {
                  "files": [
                      {
                          "path": "AGENTS.md",
                          "content": "# Zero-Secret SecOps Triage Workspace\n",
                      }
                  ],
                  "mcp": {
                      "servers": [
                          {
                              "name": srv,
                              "endpoint": f"http://127.0.0.1:{egress_port}/egress/{srv}/mcp",
                          }
                          for srv in mcp_gateway_names
                      ]
                  },
              },
          }
      )

      sandbox_home = tmp_dir / "sandbox_home"
      sandbox_home.mkdir()
      sandbox_ws = tmp_dir / "workspace"
      result_marker = tmp_dir / "sandbox_result.json"
      runner_probe_port = _free_port()
      runner_meta_port = _free_port()

      ax_task_yaml = json.dumps(
          {
              "apiVersion": "ax.io/v1alpha1",
              "kind": "Task",
              "metadata": {"name": actor_name, "atespace": atespace},
              "spec": {
                  "command": [
                      sys.executable,
                      "-P",
                      str(Path(__file__).resolve()),
                      "--sandbox-child",
                      str(result_marker),
                  ],
                  "workspace": {
                      "name": "secops-gateway-ws",
                      "path": str(sandbox_ws),
                  },
                  "env": [
                      {"name": "AX_ZERO_SECRET_SANDBOX", "value": "true"},
                      {
                          "name": "MCP_GATEWAY_AUTH_HEADER",
                          "value": "Bearer ate-egress-injected",
                      },
                      {
                          "name": "LLM_GATEWAY_URL",
                          "value": f"http://127.0.0.1:{egress_port}/egress/vertex-llm/vertex",
                      },
                      {"name": "GOOGLE_CLOUD_PROJECT", "value": project_id},
                      {
                          "name": "GOOGLE_CLOUD_LOCATION",
                          "value": os.environ.get(
                              "GOOGLE_CLOUD_LOCATION", "global"
                          ),
                      },
                      {"name": "GOOGLE_GENAI_USE_VERTEXAI", "value": "TRUE"},
                      {
                          "name": "GOOGLE_MODEL",
                          "value": os.environ.get(
                              "GOOGLE_MODEL", "gemini-3.8-flash"
                          ),
                      },
                  ],
              },
          }
      )

      runner_env = {
          "PATH": os.environ["PATH"],
          "HOME": str(sandbox_home),
          "AX_TASK_YAML": ax_task_yaml,
          "AX_WORKSPACE_YAML": ax_workspace_yaml,
      }
      runner_proc = subprocess.Popen(
          [
              sys.executable,
              "-P",
              "-m",
              "ax_task_runner",
              "--port",
              str(runner_probe_port),
              "--metadata-port",
              str(runner_meta_port),
              "--workspace-dir",
              str(sandbox_ws),
          ],
          cwd=str(sandbox_home),
          env=runner_env,
          stdout=subprocess.PIPE,
          stderr=subprocess.STDOUT,
      )

      await _wait_http_ready(
          f"http://127.0.0.1:{runner_probe_port}/readyz", headers={}
      )
      logger.info(
          "ax-task-runner /readyz=200 on port %s (metadata port %s)",
          runner_probe_port,
          runner_meta_port,
      )

      deadline = time.monotonic() + 120.0
      while time.monotonic() < deadline:
        if result_marker.is_file():
          break
        if runner_proc.poll() is not None:
          break
        await asyncio.sleep(0.3)

      runner_proc.send_signal(signal.SIGTERM)
      runner_out_b, _ = await asyncio.to_thread(runner_proc.communicate, 15.0)
      print(runner_out_b.decode("utf-8", errors="replace"))
      runner_proc = None

      if not result_marker.is_file():
        raise RuntimeError(
            "Zero-secret sandbox child supervised by ax-task-runner did not complete cleanly."
        )

      egress_server.should_exit = True
      await egress_task
      await upstream_http.aclose()
    finally:
      if runner_proc is not None and runner_proc.poll() is None:
        runner_proc.terminate()
        try:
          runner_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
          runner_proc.kill()
      for proc in procs.values():
        if proc.poll() is None:
          proc.terminate()
      for proc in procs.values():
        try:
          proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
          proc.kill()
      for fh in open_log_handles:
        try:
          fh.close()
        except OSError:
          pass


def main() -> None:
  logging.basicConfig(
      level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
  )
  if "--sandbox-child" in sys.argv:
    idx = sys.argv.index("--sandbox-child")
    marker = Path(sys.argv[idx + 1])
    asyncio.run(_run_zero_secret_sandbox_child(marker))
  else:
    asyncio.run(_run_orchestrator())


if __name__ == "__main__":
  main()
