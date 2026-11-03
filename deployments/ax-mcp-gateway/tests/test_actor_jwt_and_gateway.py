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
"""End-to-end ASGI Streamable HTTP, Vertex LLM proxy, runner, and actorJwt tests."""

import datetime
import ipaddress
import json
from pathlib import Path
import ssl
import sys
import threading
import time
from typing import Any
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
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
    build_vertex_llm_proxy_app,
    load_fastmcp_server,
)
from ax_mcp_gateway.llm_proxy import build_inference_path_matcher  # noqa: E402

ISSUER = "https://idp.ate-system.svc"
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


def test_actor_jwt_verifier_es256_rs256_issuer_and_scoping_rejections(
    tmp_path: Path,
) -> None:
  jwks_doc, ec_priv, rsa_priv = _generate_es256_and_rs256_jwks()
  jwks_file = tmp_path / "jwks.json"
  jwks_file.write_text(json.dumps(jwks_doc), encoding="utf-8")

  # Mandatory expected_issuer when require_actor_jwt=True
  with pytest.raises(ValueError, match="expected_issuer"):
    ActorJwtVerifier(
        ActorJwtConfig(
            require_actor_jwt=True,
            expected_issuer=None,
            expected_audience=AUDIENCE,
            jwks_path=str(jwks_file),
        )
    )

  # Unqualified allowed_actors rejected when multiple or zero allowed_atespaces configured
  with pytest.raises(ValueError, match="Unqualified actor entry"):
    ActorJwtVerifier(
        ActorJwtConfig(
            require_actor_jwt=True,
            expected_issuer=ISSUER,
            expected_audience=AUDIENCE,
            jwks_path=str(jwks_file),
            allowed_atespaces=frozenset({"secops", "other"}),
            allowed_actors=frozenset({"secops-triage-agent"}),
        )
    )

  verifier = ActorJwtVerifier(
      ActorJwtConfig(
          require_actor_jwt=True,
          expected_issuer=ISSUER,
          expected_audience=AUDIENCE,
          jwks_path=str(jwks_file),
          allowed_atespaces=frozenset({"secops"}),
          allowed_actors=frozenset({"secops/secops-triage-agent"}),
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

  # 3. Different actor in same atespace rejected by qualified allowed_actors -> 403
  other_actor = _mint_actor_jwt(ec_priv, actor_name="other-agent")
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(other_actor)
  assert exc_info.value.status_code == 403

  # 4. Missing header -> 401
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_authorization_header(None)
  assert exc_info.value.status_code == 401

  # 5. Expired token -> 401
  expired = _mint_actor_jwt(ec_priv, exp_offset_sec=-120)
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(expired)
  assert exc_info.value.status_code == 401

  # 6. Wrong audience -> 403
  bad_aud = _mint_actor_jwt(
      ec_priv, audiences=["http://scc-mcp.secops-gateways.svc.cluster.local:8080"]
  )
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(bad_aud)
  assert exc_info.value.status_code == 403

  # 7. Wrong issuer -> 403
  bad_iss = _mint_actor_jwt(ec_priv, issuer="https://untrusted.issuer")
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(bad_iss)
  assert exc_info.value.status_code == 403

  # 8. KindWorkerForActor token rejected -> 403
  worker_tok = _mint_actor_jwt(
      ec_priv,
      claim_key="worker-for-actor.ate.dev",
      subject="worker-for-actor/secops/secops-triage-agent",
  )
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(worker_tok)
  assert exc_info.value.status_code == 403

  # 9. KindActor carrying non-empty node rejected -> 403
  node_tok = _mint_actor_jwt(
      ec_priv, extra_substrate_fields={"node": "gke-worker-01"}
  )
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(node_tok)
  assert exc_info.value.status_code == 403

  # 10. Symmetric HS256 downgrade rejected -> 401
  hs_tok = jwt.encode(
      {
          "iss": ISSUER,
          "sub": "actor/secops/secops-triage-agent",
          "aud": [AUDIENCE],
          "exp": int(time.time()) + 600,
      },
      "shared-secret-key-at-least-32-bytes-long",
      algorithm="HS256",
      headers={"kid": "ec-key-1"},
  )
  with pytest.raises(ActorJwtAuthError) as exc_info:
    verifier.verify_token(hs_tok)
  assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_async_jwks_cooldown_ca_bundle_and_corrupt_503_handling(
    tmp_path: Path,
) -> None:
  """Verifies async JWKS refresh cooldown on unknown kid, corrupt JWKS -> 503, and custom TLS CA."""
  jwks_doc, ec_priv, _ = _generate_es256_and_rs256_jwks()

  # 1. Corrupt JWKS file returns 503 (never unhandled 500) on ASGI middleware.
  corrupt_file = tmp_path / "corrupt_jwks.json"
  corrupt_file.write_text("{truncated-json", encoding="utf-8")
  corrupt_cfg = GatewayConfig.from_env(
      server_name="gti",
      environ={
          "GATEWAY_SERVICE_NAME": "gti-mcp",
          "GATEWAY_NAMESPACE": "secops-gateways",
          "GATEWAY_PORT": "8080",
          "GATEWAY_REQUIRE_ACTOR_JWT": "true",
          "GATEWAY_EXPECTED_ISSUER": ISSUER,
          "GATEWAY_EXPECTED_AUDIENCE": AUDIENCE,
          "GATEWAY_JWKS_PATH": str(corrupt_file),
          "GATEWAY_ALLOWED_ATESPACES": "secops",
      },
  )
  demo_mcp = FastMCP("corrupt-jwks-test")
  corrupt_app = build_gateway_app(corrupt_cfg, mcp_server=demo_mcp)
  tok = _mint_actor_jwt(ec_priv)
  async with _AsgiLifespanRunner(corrupt_app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=corrupt_app),
        base_url=AUDIENCE,
    ) as client:
      ready_resp = await client.get("/readyz")
      assert ready_resp.status_code == 503
      mcp_resp = await client.post(
          "/mcp",
          headers={"Authorization": f"Bearer {tok}"},
          json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
      )
      assert mcp_resp.status_code == 503

  # 2. Unknown kid storm triggers at most one JWKS reload inside cooldown window,
  #    and a transient upstream failure preserves unexpired cached keys.
  from http.server import BaseHTTPRequestHandler, HTTPServer

  ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  subject = issuer = x509.Name(
      [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
  )
  now_dt = datetime.datetime.now(datetime.timezone.utc)
  cert = (
      x509.CertificateBuilder()
      .subject_name(subject)
      .issuer_name(issuer)
      .public_key(ca_key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(now_dt - datetime.timedelta(minutes=5))
      .not_valid_after(now_dt + datetime.timedelta(hours=1))
      .add_extension(
          x509.SubjectAlternativeName(
              [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
          ),
          critical=False,
      )
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
      .sign(ca_key, hashes.SHA256())
  )
  cert_pem = tmp_path / "servicedns-ca.pem"
  key_pem = tmp_path / "servicedns-key.pem"
  cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
  key_pem.write_bytes(
      ca_key.private_bytes(
          serialization.Encoding.PEM,
          serialization.PrivateFormat.TraditionalOpenSSL,
          serialization.NoEncryption(),
      )
  )

  fetch_count = 0
  fail_upstream = False

  class _TlsJwksHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
      nonlocal fetch_count
      fetch_count += 1
      if fail_upstream:
        self.send_response(500)
        self.end_headers()
        return
      body = json.dumps(jwks_doc).encode("utf-8")
      self.send_response(200)
      self.send_header("Content-Type", "application/json")
      self.send_header("Content-Length", str(len(body)))
      self.end_headers()
      self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
      return

  httpd = HTTPServer(("127.0.0.1", 0), _TlsJwksHandler)
  srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  srv_ctx.load_cert_chain(certfile=str(cert_pem), keyfile=str(key_pem))
  httpd.socket = srv_ctx.wrap_socket(httpd.socket, server_side=True)
  port = httpd.server_address[1]
  srv_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
  srv_thread.start()
  try:
    url_verifier = ActorJwtVerifier(
        ActorJwtConfig(
            require_actor_jwt=True,
            expected_issuer=ISSUER,
            expected_audience=AUDIENCE,
            jwks_url=f"https://127.0.0.1:{port}/openid/v1/jwks",
            jwks_ca_file=str(cert_pem),
            jwks_cache_ttl_seconds=120.0,
            jwks_refresh_cooldown_seconds=30.0,
        )
    )
    assert await url_verifier.is_ready_async() is True
    assert fetch_count == 1

    # 10 unknown-kid requests within the 30s cooldown must NOT trigger extra fetches!
    unknown_kid_tok = _mint_actor_jwt(ec_priv, kid="unknown-kid-999")
    for _ in range(10):
      with pytest.raises(ActorJwtAuthError) as exc_info:
        await url_verifier.verify_token_async(unknown_kid_tok)
      assert exc_info.value.status_code == 401
    assert fetch_count == 1

    # Even if upstream returns 500 during a forced refresh after cooldown, unexpired cached keys still verify valid tokens.
    fail_upstream = True
    url_verifier._last_refresh_attempt_at = 0.0
    with pytest.raises(ActorJwtAuthError):
      await url_verifier.verify_token_async(unknown_kid_tok)
    assert fetch_count == 2
    valid_ident = await url_verifier.verify_token_async(tok)
    assert valid_ident.actor_name == "secops-triage-agent"
  finally:
    httpd.shutdown()
    httpd.server_close()


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
          "GATEWAY_HOST": "0.0.0.0",
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
  # Non-loopback bind omits localhost:* from allowed_hosts
  assert "localhost:*" not in cfg.allowed_hosts
  app = build_gateway_app(cfg, mcp_server=demo_mcp)

  async with _AsgiLifespanRunner(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://10.24.3.17:8080"
    ) as probe_client:
      health = await probe_client.get("/healthz")
      assert health.status_code == 200
      assert health.json()["status"] == "ok"

      ready = await probe_client.get("/readyz")
      assert ready.status_code == 200
      assert ready.json()["status"] == "ready"

      unauth = await probe_client.post("/mcp", json={"jsonrpc": "2.0"})
      assert unauth.status_code == 401

      bypass = await probe_client.post(
          "/mcp",
          headers={"Authorization": "Bearer ate-egress-injected"},
          json={"jsonrpc": "2.0"},
      )
      assert bypass.status_code == 401

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


def test_inference_path_matcher_is_pinned_to_one_project_location_and_rpcs() -> None:
  matcher = build_inference_path_matcher("my-secops-project", "global")
  base = "projects/my-secops-project/locations/global/publishers/google/models/gemini-3.8-flash"
  assert matcher.match(f"v1beta1/{base}:generateContent")
  assert matcher.match(f"v1/{base}:streamGenerateContent")
  assert matcher.match(f"v1/{base}:countTokens")

  rejected = [
      # Other projects / locations under the gateway SA
      "v1/projects/victim-project/locations/global/publishers/google/models/gemini-3.8-flash:generateContent",
      "v1/projects/my-secops-project/locations/us-central1/publishers/google/models/gemini-3.8-flash:generateContent",
      # Non-inference Vertex resources
      "v1/projects/my-secops-project/locations/global/customJobs",
      "v1/projects/my-secops-project/locations/global/batchPredictionJobs",
      "v1/projects/my-secops-project/locations/global/tuningJobs",
      "v1/projects/my-secops-project/locations/global/ragCorpora:import",
      "v1/projects/my-secops-project/locations/global/endpoints/123:predict",
      "v1/projects/my-secops-project/locations/global/endpoints/123:undeployModel",
      f"v1/{base}:predict",
      f"v1/{base}",
      # Traversal / metadata
      "v1/../computeMetadata/v1/instance/service-accounts/default/token",
      "computeMetadata/v1/instance/service-accounts/default/token",
      f"v2/{base}:generateContent",
  ]
  for path in rejected:
    assert matcher.match(path) is None, path

  with pytest.raises(ValueError, match="GOOGLE_CLOUD_PROJECT"):
    build_inference_path_matcher("", "global")
  with pytest.raises(ValueError, match="GOOGLE_CLOUD_PROJECT"):
    build_inference_path_matcher("Bad Project!", "global")


@pytest.mark.asyncio
async def test_vertex_llm_gateway_is_not_an_open_relay(tmp_path: Path) -> None:
  """actorJwt + Host allowlist + pinned inference paths + header scrubbing + body cap."""
  jwks_doc, ec_priv, _ = _generate_es256_and_rs256_jwks()
  jwks_file = tmp_path / "jwks.json"
  jwks_file.write_text(json.dumps(jwks_doc), encoding="utf-8")
  llm_aud = "http://llm-gateway.secops-gateways.svc.cluster.local:8080"
  model_path = (
      "/vertex/v1beta1/projects/my-secops-project/locations/global/"
      "publishers/google/models/gemini-3.8-flash:generateContent"
  )

  seen_upstream: list[tuple[str, dict[str, str]]] = []

  def _mock_upstream_handler(request: httpx.Request) -> httpx.Response:
    seen_upstream.append((str(request.url), dict(request.headers)))
    return httpx.Response(
        200,
        json={"candidates": [{"content": {"parts": [{"text": "clean"}]}}]},
    )

  mock_client = httpx.AsyncClient(
      transport=httpx.MockTransport(_mock_upstream_handler)
  )
  try:
    # Refuses to start without a pinned project.
    with pytest.raises(ValueError, match="GOOGLE_CLOUD_PROJECT"):
      build_vertex_llm_proxy_app(
          ("llm-gateway.secops-gateways.svc.cluster.local:8080",),
          environ={},
          http_client=mock_client,
          token_provider=lambda: "t",
      )

    inner_llm_app, llm_lifespan = build_vertex_llm_proxy_app(
        ("llm-gateway.secops-gateways.svc.cluster.local:8080",),
        project_id="my-secops-project",
        location="global",
        upstream_base_url="https://aiplatform.googleapis.com",
        token_provider=lambda: "out-of-sandbox-gcp-token",
        http_client=mock_client,
        max_body_bytes=4096,
    )
    cfg = GatewayConfig.from_env(
        server_name="vertex-llm",
        environ={
            "GATEWAY_HOST": "0.0.0.0",
            "GATEWAY_SERVICE_NAME": "llm-gateway",
            "GATEWAY_NAMESPACE": "secops-gateways",
            "GATEWAY_PORT": "8080",
            "GATEWAY_REQUIRE_ACTOR_JWT": "true",
            "GATEWAY_EXPECTED_ISSUER": ISSUER,
            "GATEWAY_EXPECTED_AUDIENCE": llm_aud,
            "GATEWAY_JWKS_PATH": str(jwks_file),
            "GATEWAY_ALLOWED_ATESPACES": "secops",
        },
    )
    app = build_gateway_app(
        cfg, inner_app=inner_llm_app, extra_lifespan=llm_lifespan
    )
    valid_jwt = _mint_actor_jwt(ec_priv, audiences=[llm_aud])
    auth = {"Authorization": f"Bearer {valid_jwt}"}

    async with _AsgiLifespanRunner(app):
      async with httpx.AsyncClient(
          transport=httpx.ASGITransport(app=app), base_url=llm_aud
      ) as client:
        # 1. Unauthenticated -> 401
        assert (await client.post(model_path, json={})).status_code == 401

        # 2. Authenticated but outside the inference allowlist -> 403 (never reaches upstream)
        for bad in (
            "/vertex/v1/projects/victim-project/locations/global/publishers/google/models/gemini-3.8-flash:generateContent",
            "/vertex/v1/projects/my-secops-project/locations/global/customJobs",
            "/vertex/v1/projects/my-secops-project/locations/global/batchPredictionJobs",
            "/vertex/v1/projects/my-secops-project/locations/global/ragCorpora:import",
            "/vertex/computeMetadata/v1/instance/service-accounts/default/token",
        ):
          r = await client.post(bad, headers=auth, json={})
          assert r.status_code == 403, bad
        assert seen_upstream == []

        # 3. GET is never proxied, even on an allowed path
        r_get = await client.get(model_path, headers=auth)
        assert r_get.status_code == 405
        assert seen_upstream == []

        # 4. Body cap -> 413
        r_big = await client.post(
            model_path, headers=auth, content=b"x" * 5000
        )
        assert r_big.status_code == 413
        assert seen_upstream == []

        # 5. Allowed request: caller-supplied billing/auth headers are dropped or overwritten
        r_ok = await client.post(
            model_path + "?alt=sse&key=attacker-api-key",
            headers={
                **auth,
                "x-goog-user-project": "victim-billing-project",
                "x-goog-api-key": "attacker-api-key",
                "x-goog-iam-authorization-token": "attacker",
                "cookie": "session=abc",
                "x-forwarded-for": "10.0.0.1",
                "x-goog-api-client": "google-genai-sdk/1.0",
            },
            json={"contents": []},
        )
        assert r_ok.status_code == 200
        assert r_ok.json()["candidates"][0]["content"]["parts"][0]["text"] == "clean"
        assert len(seen_upstream) == 1
        up_url, up_headers = seen_upstream[0]
        assert up_url == (
            "https://aiplatform.googleapis.com/v1beta1/projects/my-secops-project/"
            "locations/global/publishers/google/models/gemini-3.8-flash:generateContent?alt=sse"
        )
        assert up_headers["authorization"] == "Bearer out-of-sandbox-gcp-token"
        assert up_headers["x-goog-user-project"] == "my-secops-project"
        assert up_headers["x-goog-api-client"] == "google-genai-sdk/1.0"
        for leaked in (
            "x-goog-api-key",
            "x-goog-iam-authorization-token",
            "cookie",
            "x-forwarded-for",
        ):
          assert leaked not in up_headers
  finally:
    await mock_client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("server_name", "soar_integrations", "expected_tool_subset"),
    [
        ("gti", "", {"get_file_report", "get_domain_report"}),
        ("secops", "", {"search_security_events", "get_security_alerts"}),
        ("secops-soar", "CSV", {"list_cases", "csv_ping"}),
        ("scc", "", {"search_findings", "top_vulnerability_findings"}),
    ],
)
async def test_load_all_four_real_mcp_security_servers_over_streamable_http(
    tmp_path: Path,
    server_name: str,
    soar_integrations: str,
    expected_tool_subset: set[str],
) -> None:
  """Verifies all four google/mcp-security servers mount and list tools (including SOAR marketplace integrations)."""
  jwks_doc, ec_priv, _ = _generate_es256_and_rs256_jwks()
  jwks_file = tmp_path / "jwks.json"
  jwks_file.write_text(json.dumps(jwks_doc), encoding="utf-8")

  audience = f"http://{server_name}-mcp.secops-gateways.svc.cluster.local:8080"

  # Servers are imported strictly as installed packages (no sys.path mutation);
  # the secops-soar marketplace import must resolve via secops_soar_mcp.marketplace.<stem>.
  with patch("google.auth.default", side_effect=RuntimeError("hermetic-test")):
    mcp_srv, extra_lifespan = load_fastmcp_server(
        server_name,
        soar_integrations=soar_integrations,
        skip_soar_bind_on_startup=True,
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
  app = build_gateway_app(cfg, mcp_server=mcp_srv, extra_lifespan=extra_lifespan)
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


def test_secops_soar_register_tools_idempotent_installed_package_import() -> None:
  """Verifies secops_soar_mcp.server.register_tools loads marketplace modules via package prefix and is idempotent."""
  import importlib

  soar_srv = importlib.import_module("secops_soar_mcp.server")
  soar_srv.register_tools("CSV")
  count_once = len(soar_srv.mcp._tool_manager.list_tools())
  soar_srv.register_tools("CSV")
  count_twice = len(soar_srv.mcp._tool_manager.list_tools())
  assert count_once == count_twice
  tool_names = {t.name for t in soar_srv.mcp._tool_manager.list_tools()}
  assert "csv_ping" in tool_names


@pytest.mark.asyncio
async def test_jwks_outage_after_ttl_serves_stale_keys_and_keeps_readyz_green(
    tmp_path: Path,
) -> None:
  """A JWKS source failure after the cache TTL must not 503 the whole gateway fleet."""
  jwks_doc, ec_priv, _ = _generate_es256_and_rs256_jwks()
  jwks_file = tmp_path / "jwks.json"
  jwks_file.write_text(json.dumps(jwks_doc), encoding="utf-8")

  verifier = ActorJwtVerifier(
      ActorJwtConfig(
          require_actor_jwt=True,
          expected_issuer=ISSUER,
          expected_audience=AUDIENCE,
          jwks_path=str(jwks_file),
          jwks_cache_ttl_seconds=0.0,  # every call is a refresh attempt
          jwks_refresh_cooldown_seconds=0.0,
          jwks_max_stale_seconds=3600.0,
      )
  )
  tok = _mint_actor_jwt(ec_priv)
  assert (await verifier.verify_token_async(tok)).actor_name == "secops-triage-agent"

  # Simulate ate-idp-server outage: the JWKS source disappears / becomes corrupt.
  jwks_file.write_text("{corrupt", encoding="utf-8")
  assert (await verifier.verify_token_async(tok)).actor_name == "secops-triage-agent"
  assert await verifier.is_ready_async() is True
  jwks_file.unlink()
  assert (await verifier.verify_token_async(tok)).actor_name == "secops-triage-agent"
  assert await verifier.is_ready_async() is True

  # Beyond the stale window the gateway fails closed with 503.
  verifier._cache_loaded_at = time.monotonic() - 7200.0
  with pytest.raises(ActorJwtAuthError) as exc_info:
    await verifier.verify_token_async(tok)
  assert exc_info.value.status_code == 503
  assert await verifier.is_ready_async() is False

  # A gateway with NO prior successful load is not ready and rejects with 503.
  cold = ActorJwtVerifier(
      ActorJwtConfig(
          require_actor_jwt=True,
          expected_issuer=ISSUER,
          expected_audience=AUDIENCE,
          jwks_path=str(tmp_path / "missing.json"),
      )
  )
  assert await cold.is_ready_async() is False
  with pytest.raises(ActorJwtAuthError) as exc_info:
    await cold.verify_token_async(tok)
  assert exc_info.value.status_code == 503
