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
"""End-to-end ASGI Streamable HTTP and actorJwt tests for ax_mcp_gateway."""

import json
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec, rsa
import httpx
import jwt
from jwt import algorithms as jwt_algorithms
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import FastMCP
import pytest

GATEWAY_SRC = Path(__file__).resolve().parents[1] / "src"
if str(GATEWAY_SRC) not in sys.path:
  sys.path.insert(0, str(GATEWAY_SRC))

from ax_mcp_gateway import (  # noqa: E402
    ActorJwtAuthError,
    ActorJwtConfig,
    ActorJwtVerifier,
    GatewayConfig,
    build_gateway_app,
    load_fastmcp_server,
)

ISSUER = "https://ateapi.ate-system.svc"
AUDIENCE = "http://gti-mcp.secops-gateways.svc.cluster.local:8080"


def _generate_es256_and_rs256_jwks() -> tuple[dict[str, Any], Any, Any]:
  ec_priv = ec.generate_private_key(ec.SECP256R1())
  ec_jwk = json.loads(jwt_algorithms.ECAlgorithm.to_jwk(ec_priv.public_key()))
  ec_jwk.update({"kid": "ec-key-1", "use": "sig", "alg": "ES256"})

  rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  rsa_jwk = json.loads(jwt_algorithms.RSAAlgorithm.to_jwk(rsa_priv.public_key()))
  rsa_jwk.update({"kid": "rsa-key-1", "use": "sig", "alg": "RS256"})

  return {"keys": [ec_jwk, rsa_jwk]}, ec_priv, rsa_priv


def _mint_actor_jwt(
    private_key: Any,
    *,
    kid: str = "ec-key-1",
    alg: str = "ES256",
    atespace: str = "secops",
    actor_name: str = "secops-triage-agent",
    actor_uid: str = "uid-12345",
    issuer: str = ISSUER,
    audiences: list[str] | None = None,
    exp_offset_sec: int = 900,
    claim_key: str = "actor.ate.dev",
    subject: str | None = None,
    extra_substrate_fields: dict[str, Any] | None = None,
) -> str:
  now = int(time.time())
  substrate_claims: dict[str, Any] = {
      "atespace": atespace,
      "actorName": actor_name,
      "actorUID": actor_uid,
  }
  if extra_substrate_fields:
    substrate_claims.update(extra_substrate_fields)

  payload: dict[str, Any] = {
      "iss": issuer,
      "sub": subject or f"actor/{atespace}/{actor_name}",
      "aud": audiences if audiences is not None else [AUDIENCE],
      "iat": now,
      "nbf": now,
      "exp": now + exp_offset_sec,
      "jti": "jti-abc-001",
      claim_key: substrate_claims,
  }
  return jwt.encode(payload, private_key, algorithm=alg, headers={"kid": kid})


class _AsgiLifespanRunner:
  """Runs an ASGI application's lifespan startup/shutdown for httpx.ASGITransport."""

  def __init__(self, app: Any) -> None:
    self.app = app
    self._startup_done = None
    self._shutdown_trigger = None
    self._task = None

  async def __aenter__(self) -> Any:
    import asyncio

    self._startup_done = asyncio.Event()
    self._shutdown_trigger = asyncio.Event()
    startup_error: list[str] = []

    async def receive() -> dict[str, Any]:
      if not self._startup_done.is_set():
        return {"type": "lifespan.startup"}
      await self._shutdown_trigger.wait()
      return {"type": "lifespan.shutdown"}

    async def send(message: dict[str, Any]) -> None:
      msg_type = message["type"]
      if msg_type == "lifespan.startup.complete":
        self._startup_done.set()
      elif msg_type == "lifespan.startup.failed":
        startup_error.append(message.get("message", "startup failed"))
        self._startup_done.set()

    self._task = asyncio.create_task(
        self.app({"type": "lifespan"}, receive, send)
    )
    await self._startup_done.wait()
    if startup_error:
      raise RuntimeError(startup_error[0])
    return self.app

  async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
    if self._shutdown_trigger is not None:
      self._shutdown_trigger.set()
    if self._task is not None:
      await self._task


def test_actor_jwt_verifier_es256_and_rs256_and_rejections(tmp_path: Path) -> None:
  jwks_doc, ec_priv, rsa_priv = _generate_es256_and_rs256_jwks()
  jwks_file = tmp_path / "jwks.json"
  jwks_file.write_text(json.dumps(jwks_doc), encoding="utf-8")

  verifier = ActorJwtVerifier(
      ActorJwtConfig(
          require_actor_jwt=True,
          expected_issuer=ISSUER,
          expected_audience=AUDIENCE,
          jwks_path=str(jwks_file),
          allowed_atespaces=frozenset({"secops"}),
      )
  )
  assert verifier.is_ready() is True

  # 1. Valid ES256 KindActor token
  es_token = _mint_actor_jwt(ec_priv, kid="ec-key-1", alg="ES256")
  ident_es = verifier.verify_authorization_header(f"Bearer {es_token}")
  assert ident_es.atespace == "secops"
  assert ident_es.actor_name == "secops-triage-agent"
  assert ident_es.actor_uid == "uid-12345"

  # 2. Valid RS256 KindActor token
  rs_token = _mint_actor_jwt(rsa_priv, kid="rsa-key-1", alg="RS256")
  ident_rs = verifier.verify_authorization_header(f"Bearer {rs_token}")
  assert ident_rs.subject == "actor/secops/secops-triage-agent"

  # 3. Missing header -> 401
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_authorization_header(None)
  assert exc_info.value.status_code == 401

  # 4. Expired token -> 401
  expired = _mint_actor_jwt(ec_priv, exp_offset_sec=-120)
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(expired)
  assert exc_info.value.status_code == 401

  # 5. Wrong audience -> 403
  bad_aud = _mint_actor_jwt(
      ec_priv, audiences=["http://scc-mcp.secops-gateways.svc.cluster.local:8080"]
  )
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(bad_aud)
  assert exc_info.value.status_code == 403

  # 6. Wrong issuer -> 403
  bad_iss = _mint_actor_jwt(ec_priv, issuer="https://untrusted.issuer")
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(bad_iss)
  assert exc_info.value.status_code == 403

  # 7. KindWorkerForActor token rejected -> 403
  worker_tok = _mint_actor_jwt(
      ec_priv,
      claim_key="worker-for-actor.ate.dev",
      subject="worker-for-actor/secops/secops-triage-agent",
  )
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(worker_tok)
  assert exc_info.value.status_code == 403

  # 8. KindActor carrying non-empty node rejected -> 403
  node_tok = _mint_actor_jwt(
      ec_priv, extra_substrate_fields={"node": "gke-worker-01"}
  )
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(node_tok)
  assert exc_info.value.status_code == 403

  # 9. Unauthorized atespace rejected -> 403
  other_ns = _mint_actor_jwt(ec_priv, atespace="untrusted-team")
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(other_ns)
  assert exc_info.value.status_code == 403

  # 10. Symmetric HS256 downgrade rejected -> 401
  hs_tok = jwt.encode(
      {"sub": "actor/secops/secops-triage-agent", "aud": [AUDIENCE], "exp": int(time.time()) + 600},
      "shared-secret-key-at-least-32-bytes-long",
      algorithm="HS256",
      headers={"kid": "ec-key-1"},
  )
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(hs_tok)
  assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_streamable_http_gateway_e2e_mcp_session_and_probes(
    tmp_path: Path,
) -> None:
  jwks_doc, ec_priv, _ = _generate_es256_and_rs256_jwks()
  jwks_file = tmp_path / "jwks.json"
  jwks_file.write_text(json.dumps(jwks_doc), encoding="utf-8")

  demo_mcp = FastMCP("demo-secops-gateway")

  @demo_mcp.tool()
  def lookup_ioc_verdict(indicator: str) -> dict[str, str]:
    """Returns deterministic IOC verdict for gateway testing."""
    return {"indicator": indicator, "verdict": "malicious"}

  cfg = GatewayConfig.from_env(
      server_name="gti",
      environ={
          "GATEWAY_SERVICE_NAME": "gti-mcp",
          "GATEWAY_NAMESPACE": "secops-gateways",
          "GATEWAY_PORT": "8080",
          "GATEWAY_REQUIRE_ACTOR_JWT": "true",
          "GATEWAY_EXPECTED_ISSUER": ISSUER,
          "GATEWAY_EXPECTED_AUDIENCE": AUDIENCE,
          "GATEWAY_JWKS_PATH": str(jwks_file),
          "GATEWAY_ALLOWED_ATESPACES": "secops",
      },
  )
  app = build_gateway_app(cfg, mcp_server=demo_mcp)

  async with _AsgiLifespanRunner(app):
    transport = httpx.ASGITransport(app=app)
    # 1. Kubelet probes on arbitrary Pod IP Host header succeed without JWT.
    async with httpx.AsyncClient(
        transport=transport, base_url="http://10.24.3.17:8080"
    ) as probe_client:
      health = await probe_client.get("/healthz")
      assert health.status_code == 200
      assert health.json()["status"] == "ok"

      ready = await probe_client.get("/readyz")
      assert ready.status_code == 200
      assert ready.json()["status"] == "ready"

      # Unauthenticated /mcp call is rejected with 401 before touching FastMCP.
      unauth = await probe_client.post("/mcp", json={"jsonrpc": "2.0"})
      assert unauth.status_code == 401

      # Raw placeholder token (simulating a direct pod bypass around atenet-egress) is rejected!
      bypass = await probe_client.post(
          "/mcp",
          headers={"Authorization": "Bearer ate-egress-injected"},
          json={"jsonrpc": "2.0"},
      )
      assert bypass.status_code == 401

    # 2. Valid actorJwt with unlisted Host header is rejected by FastMCP DNS rebinding protection.
    valid_jwt = _mint_actor_jwt(ec_priv)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://evil.attacker.internal:8080"
    ) as bad_host_client:
      rebinding_resp = await bad_host_client.post(
          "/mcp",
          headers={"Authorization": f"Bearer {valid_jwt}"},
          json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
      )
      assert rebinding_resp.status_code == 421

    # 3. Full MCP ClientSession over cluster-internal Service DNS Host + valid actorJwt!
    def _asgi_http_client_factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
      return httpx.AsyncClient(
          transport=httpx.ASGITransport(app=app),
          headers=headers,
          timeout=timeout,
          auth=auth,
          follow_redirects=True,
      )

    mcp_url = "http://gti-mcp.secops-gateways.svc.cluster.local:8080/mcp"
    async with streamablehttp_client(
        url=mcp_url,
        headers={"Authorization": f"Bearer {valid_jwt}"},
        httpx_client_factory=_asgi_http_client_factory,
    ) as (read_stream, write_stream, _):
      async with ClientSession(read_stream, write_stream) as session:
        await session.initialize()
        tools_res = await session.list_tools()
        tool_names = [t.name for t in tools_res.tools]
        assert "lookup_ioc_verdict" in tool_names

        call_res = await session.call_tool(
            "lookup_ioc_verdict", {"indicator": "example-bad.test"}
        )
        assert call_res.isError is False
        assert "malicious" in call_res.content[0].text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("server_name", "expected_tool_subset"),
    [
        ("gti", {"get_file_report", "get_domain_report"}),
        ("secops", {"search_security_events", "get_security_alerts"}),
        ("secops-soar", {"list_cases"}),
        ("scc", {"search_findings", "top_vulnerability_findings"}),
    ],
)
async def test_load_all_four_real_mcp_security_servers_over_streamable_http(
    tmp_path: Path,
    server_name: str,
    expected_tool_subset: set[str],
) -> None:
  """Verifies all four google/mcp-security servers mount and list tools over /mcp."""
  jwks_doc, ec_priv, _ = _generate_es256_and_rs256_jwks()
  jwks_file = tmp_path / "jwks.json"
  jwks_file.write_text(json.dumps(jwks_doc), encoding="utf-8")

  repo_root = Path(__file__).resolve().parents[3]
  audience = f"http://{server_name}-mcp.secops-gateways.svc.cluster.local:8080"

  # Avoid live GCP ADC metadata probes when importing scc_mcp in hermetic CI.
  with patch("google.auth.default", side_effect=RuntimeError("hermetic-test")):
    mcp_srv, extra_lifespan = load_fastmcp_server(
        server_name,
        skip_soar_bind_on_startup=True,
        repo_root=repo_root,
    )

  cfg = GatewayConfig.from_env(
      server_name=server_name,
      environ={
          "GATEWAY_SERVICE_NAME": f"{server_name}-mcp",
          "GATEWAY_NAMESPACE": "secops-gateways",
          "GATEWAY_PORT": "8080",
          "GATEWAY_REQUIRE_ACTOR_JWT": "true",
          "GATEWAY_EXPECTED_ISSUER": ISSUER,
          "GATEWAY_EXPECTED_AUDIENCE": audience,
          "GATEWAY_JWKS_PATH": str(jwks_file),
          "GATEWAY_ALLOWED_ATESPACES": "secops",
      },
  )
  app = build_gateway_app(
      cfg, mcp_server=mcp_srv, extra_lifespan=extra_lifespan, repo_root=repo_root
  )
  valid_jwt = _mint_actor_jwt(ec_priv, audiences=[audience])

  def _asgi_client_factory(
      headers: dict[str, str] | None = None,
      timeout: httpx.Timeout | None = None,
      auth: httpx.Auth | None = None,
  ) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        headers=headers,
        timeout=timeout,
        auth=auth,
        follow_redirects=True,
    )

  async with _AsgiLifespanRunner(app):
    async with streamablehttp_client(
        url=f"{audience}/mcp",
        headers={"Authorization": f"Bearer {valid_jwt}"},
        httpx_client_factory=_asgi_client_factory,
    ) as (read_stream, write_stream, _):
      async with ClientSession(read_stream, write_stream) as session:
        await session.initialize()
        tools_res = await session.list_tools()
        names = {t.name for t in tools_res.tools}
        assert expected_tool_subset.issubset(names), (
            f"Missing expected tools for {server_name}: "
            f"{expected_tool_subset - names}"
        )
