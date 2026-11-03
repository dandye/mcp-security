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
"""Out-of-sandbox Vertex AI Gemini inference proxy protected by actorJwt.

The proxy is a confused-deputy boundary: it attaches the gateway's own Google
Cloud credentials to requests originating from an untrusted sandbox. It is
therefore restricted to Gemini inference RPCs on one project and location, POST
only, a fixed request-header allowlist, a bounded body size, and a forced
`x-goog-user-project`.
"""

import asyncio
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
import logging
import os
import re
from typing import Any, Optional
from urllib.parse import parse_qsl

import google.auth
from google.auth.transport.requests import Request as GoogleAuthRequest
import httpx
from mcp.server.transport_security import (
    TransportSecurityMiddleware,
    TransportSecuritySettings,
)
from starlette.applications import Starlette
from starlette.requests import HTTPConnection, Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

ALLOWED_INFERENCE_METHODS: tuple[str, ...] = (
    "generateContent",
    "streamGenerateContent",
    "countTokens",
)
DEFAULT_MAX_BODY_BYTES = 32 * 1024 * 1024
DEFAULT_UPSTREAM_TIMEOUT_SECONDS = 300.0

_RESOURCE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# Only these request headers are forwarded from the sandbox to Vertex AI.
_FORWARDED_REQUEST_HEADERS = frozenset({
    "accept",
    "accept-encoding",
    "content-type",
    "user-agent",
    "x-goog-api-client",
    "x-server-timeout",
})
_ALLOWED_QUERY_KEYS = frozenset({"alt", "$alt", "prettyPrint", "$prettyPrint"})
_HOP_BY_HOP_RESPONSE_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
})


def resolve_vertex_upstream_base_url(
    environ: Optional[Mapping[str, str]] = None,
) -> str:
  """Resolves the upstream HTTPS Vertex AI endpoint from environment variables."""
  env = os.environ if environ is None else environ
  explicit = (env.get("VERTEX_UPSTREAM_BASE_URL") or "").strip().rstrip("/")
  if explicit:
    return explicit
  location = (env.get("GOOGLE_CLOUD_LOCATION") or "global").strip().lower()
  if not location or location == "global":
    return "https://aiplatform.googleapis.com"
  return f"https://{location}-aiplatform.googleapis.com"


def _require_label(value: Optional[str], name: str) -> str:
  cleaned = (value or "").strip().lower()
  if not cleaned or not _RESOURCE_LABEL_RE.match(cleaned):
    raise ValueError(
        f"vertex-llm gateway requires a valid {name} "
        "(lowercase letters, digits, '.', '-')."
    )
  return cleaned


def build_inference_path_matcher(
    project_id: str, location: str
) -> re.Pattern[str]:
  """Builds the strict path allowlist for Gemini inference on one project/location.

  Matches only
  `v1|v1beta1/projects/<project>/locations/<location>/publishers/google/models/<model>:<method>`
  where method is one of ALLOWED_INFERENCE_METHODS.
  """
  project = _require_label(project_id, "GOOGLE_CLOUD_PROJECT")
  loc = _require_label(location, "GOOGLE_CLOUD_LOCATION")
  methods = "|".join(re.escape(m) for m in ALLOWED_INFERENCE_METHODS)
  pattern = (
      r"^v1(?:beta1)?/projects/"
      + re.escape(project)
      + r"/locations/"
      + re.escape(loc)
      + r"/publishers/google/models/(?P<model>[A-Za-z0-9][A-Za-z0-9._-]{0,127}):(?P<method>"
      + methods
      + r")$"
  )
  return re.compile(pattern)


class _VertexCredentialsManager:
  """Caches and refreshes out-of-sandbox Google Cloud credentials off the event loop."""

  def __init__(self) -> None:
    self._creds: Optional[Any] = None
    self._lock = asyncio.Lock()

  async def get_access_token(self) -> str:
    # Fast path: a valid cached token needs no lock or thread hop.
    creds = self._creds
    if creds is not None and creds.valid and not creds.expired and creds.token:
      return str(creds.token)
    async with self._lock:
      token = await asyncio.to_thread(self._get_or_refresh_sync)
      if not token:
        raise RuntimeError("Vertex AI credentials returned an empty token.")
      return token

  def _get_or_refresh_sync(self) -> str:
    if self._creds is None:
      self._creds, _ = google.auth.default(
          scopes=["https://www.googleapis.com/auth/cloud-platform"]
      )
    if not self._creds.valid or self._creds.expired or not self._creds.token:
      self._creds.refresh(GoogleAuthRequest())
    return str(self._creds.token or "")


class _HostValidatedASGIApp:
  """Applies MCP TransportSecurityMiddleware Host/Origin checks to an ASGI app."""

  def __init__(self, app: ASGIApp, allowed_hosts: tuple[str, ...]) -> None:
    self.app = app
    self.security = TransportSecurityMiddleware(
        TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(allowed_hosts),
        )
    )

  async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] == "http":
      conn = HTTPConnection(scope)
      err_resp = await self.security.validate_request(conn, is_post=False)
      if err_resp is not None:
        await err_resp(scope, receive, send)
        return
    await self.app(scope, receive, send)


def _sanitize_query(raw_query: str) -> str:
  if not raw_query:
    return ""
  kept = [
      f"{k}={v}"
      for k, v in parse_qsl(raw_query, keep_blank_values=True)
      if k in _ALLOWED_QUERY_KEYS
  ]
  return "&".join(kept)


def build_vertex_llm_proxy_app(
    allowed_hosts: tuple[str, ...],
    *,
    project_id: Optional[str] = None,
    location: Optional[str] = None,
    upstream_base_url: Optional[str] = None,
    token_provider: Optional[Callable[[], Any]] = None,
    http_client: Optional[httpx.AsyncClient] = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    upstream_timeout_seconds: float = DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
    environ: Optional[Mapping[str, str]] = None,
) -> tuple[ASGIApp, Callable[[], AsyncIterator[None]]]:
  """Builds the cluster-internal `/vertex/{rest:path}` ASGI proxy and lifespan.

  Raises:
    ValueError: if GOOGLE_CLOUD_PROJECT or GOOGLE_CLOUD_LOCATION are missing or
      malformed. The proxy refuses to start without a pinned project/location.
  """
  env = os.environ if environ is None else environ
  resolved_project = _require_label(
      project_id or env.get("GOOGLE_CLOUD_PROJECT"), "GOOGLE_CLOUD_PROJECT"
  )
  resolved_location = _require_label(
      location or env.get("GOOGLE_CLOUD_LOCATION") or "global",
      "GOOGLE_CLOUD_LOCATION",
  )
  path_matcher = build_inference_path_matcher(resolved_project, resolved_location)
  resolved_upstream = (
      upstream_base_url.rstrip("/")
      if upstream_base_url
      else resolve_vertex_upstream_base_url(env)
  )
  creds_mgr = _VertexCredentialsManager()
  owned_client: Optional[httpx.AsyncClient] = None

  @asynccontextmanager
  async def _lifespan() -> AsyncIterator[None]:
    nonlocal owned_client
    if http_client is None:
      owned_client = httpx.AsyncClient(timeout=upstream_timeout_seconds)
    try:
      yield
    finally:
      if owned_client is not None:
        await owned_client.aclose()
        owned_client = None

  def _forbidden(detail: str) -> JSONResponse:
    return JSONResponse(
        {"error": "forbidden_path", "detail": detail}, status_code=403
    )

  async def _proxy_vertex(request: Request) -> Response:
    rest = request.path_params.get("rest", "").lstrip("/")
    if request.method != "POST":
      return JSONResponse(
          {"error": "method_not_allowed", "detail": "Only POST is permitted."},
          status_code=405,
      )
    match = path_matcher.match(rest)
    if ".." in rest or match is None:
      return _forbidden(
          "Only Gemini inference RPCs (generateContent, streamGenerateContent, "
          f"countTokens) on projects/{resolved_project}/locations/"
          f"{resolved_location}/publishers/google/models/* are permitted."
      )

    declared_len = request.headers.get("content-length")
    if declared_len is not None:
      try:
        if int(declared_len) > max_body_bytes:
          return JSONResponse(
              {"error": "payload_too_large", "detail": f"Body exceeds {max_body_bytes} bytes."},
              status_code=413,
          )
      except ValueError:
        return JSONResponse(
            {"error": "bad_request", "detail": "Invalid Content-Length."},
            status_code=400,
        )
    body = await request.body()
    if len(body) > max_body_bytes:
      return JSONResponse(
          {"error": "payload_too_large", "detail": f"Body exceeds {max_body_bytes} bytes."},
          status_code=413,
      )

    try:
      if token_provider is not None:
        maybe_coro = token_provider()
        access_token = (
            await maybe_coro
            if asyncio.iscoroutine(maybe_coro)
            else str(maybe_coro)
        )
      else:
        access_token = await creds_mgr.get_access_token()
    except Exception as exc:
      logger.error(
          "Failed to acquire out-of-sandbox Vertex AI token: %s",
          exc,
          exc_info=True,
      )
      return JSONResponse(
          {
              "error": "upstream_credentials_unavailable",
              "detail": "Out-of-sandbox Vertex AI credentials are unavailable.",
          },
          status_code=503,
      )

    client = http_client or owned_client
    if client is None:
      return JSONResponse(
          {"error": "not_ready", "detail": "HTTP client lifespan not started."},
          status_code=503,
      )

    target_url = f"{resolved_upstream}/{rest}"
    query = _sanitize_query(request.url.query)
    if query:
      target_url = f"{target_url}?{query}"

    fwd_headers: dict[str, str] = {
        k: v
        for k, v in request.headers.items()
        if k.lower() in _FORWARDED_REQUEST_HEADERS
    }
    fwd_headers["Authorization"] = f"Bearer {access_token}"
    # Billing/quota project is always the gateway's own project, never caller-chosen.
    fwd_headers["x-goog-user-project"] = resolved_project

    try:
      upstream_resp = await client.request(
          method="POST",
          url=target_url,
          headers=fwd_headers,
          content=body,
      )
    except httpx.HTTPError as exc:
      logger.error("Vertex AI upstream request failed: %s", exc)
      return JSONResponse(
          {"error": "bad_gateway", "detail": "Upstream Vertex AI request failed."},
          status_code=502,
      )

    logger.info(
        "vertex-llm proxied model=%s method=%s status=%s",
        match.group("model"),
        match.group("method"),
        upstream_resp.status_code,
    )
    resp_headers = {
        k: v
        for k, v in upstream_resp.headers.items()
        if k.lower() not in _HOP_BY_HOP_RESPONSE_HEADERS
    }
    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
    )

  starlette_app = Starlette(
      routes=[
          Route(
              "/vertex/{rest:path}",
              _proxy_vertex,
              methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
          )
      ]
  )
  return _HostValidatedASGIApp(starlette_app, allowed_hosts), _lifespan
