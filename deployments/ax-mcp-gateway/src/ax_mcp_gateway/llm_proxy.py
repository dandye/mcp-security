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
"""Out-of-sandbox Vertex AI Gemini HTTP reverse proxy protected by actorJwt."""

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
import logging
import os
import re
from typing import Any, Optional

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

_ALLOWED_VERTEX_PATH_RE = re.compile(r"^v1(?:beta1)?/[A-Za-z0-9._:/-]+$")
_HOP_BY_HOP_HEADERS = frozenset({
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
    environ: Optional[dict[str, str]] = None,
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


class _VertexCredentialsManager:
  """Caches and refreshes out-of-sandbox Google Cloud credentials off the event loop."""

  def __init__(self) -> None:
    self._creds: Optional[Any] = None
    self._lock = asyncio.Lock()

  async def get_auth_metadata(self) -> tuple[str, Optional[str]]:
    async with self._lock:
      token, quota_project = await asyncio.to_thread(self._get_or_refresh_sync)
      if not token:
        raise RuntimeError("Vertex AI credentials returned an empty token.")
      return token, quota_project

  def _get_or_refresh_sync(self) -> tuple[str, Optional[str]]:
    if self._creds is None:
      self._creds, _ = google.auth.default(
          scopes=["https://www.googleapis.com/auth/cloud-platform"]
      )
    if not self._creds.valid or self._creds.expired or not self._creds.token:
      self._creds.refresh(GoogleAuthRequest())
    quota_project = getattr(self._creds, "quota_project_id", None)
    if not quota_project and not hasattr(self._creds, "service_account_email"):
      quota_project = (os.environ.get("GOOGLE_CLOUD_PROJECT") or "").strip() or None
    return str(self._creds.token or ""), quota_project


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


def build_vertex_llm_proxy_app(
    allowed_hosts: tuple[str, ...],
    *,
    upstream_base_url: Optional[str] = None,
    token_provider: Optional[Callable[[], Any]] = None,
    http_client: Optional[httpx.AsyncClient] = None,
) -> tuple[ASGIApp, Callable[[], AsyncIterator[None]]]:
  """Builds the cluster-internal `/vertex/{rest:path}` ASGI proxy and lifespan."""
  resolved_upstream = (
      upstream_base_url.rstrip("/")
      if upstream_base_url
      else resolve_vertex_upstream_base_url()
  )
  creds_mgr = _VertexCredentialsManager()
  owned_client: Optional[httpx.AsyncClient] = None

  @asynccontextmanager
  async def _lifespan() -> AsyncIterator[None]:
    nonlocal owned_client
    if http_client is None:
      owned_client = httpx.AsyncClient(timeout=120.0)
    try:
      yield
    finally:
      if owned_client is not None:
        await owned_client.aclose()
        owned_client = None

  async def _proxy_vertex(request: Request) -> Response:
    rest = request.path_params.get("rest", "").lstrip("/")
    if ".." in rest or not _ALLOWED_VERTEX_PATH_RE.match(rest):
      return JSONResponse(
          {
              "error": "forbidden_path",
              "detail": "Only Vertex AI /v1/ and /v1beta1/ API paths are permitted.",
          },
          status_code=403,
      )

    quota_project: Optional[str] = None
    try:
      if token_provider is not None:
        maybe_coro = token_provider()
        access_token = (
            await maybe_coro
            if asyncio.iscoroutine(maybe_coro)
            else str(maybe_coro)
        )
      else:
        access_token, quota_project = await creds_mgr.get_auth_metadata()
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
    if request.url.query:
      target_url = f"{target_url}?{request.url.query}"

    fwd_headers: dict[str, str] = {}
    for k, v in request.headers.items():
      if k.lower() in {"host", "authorization", "content-length"}:
        continue
      fwd_headers[k] = v
    fwd_headers["Authorization"] = f"Bearer {access_token}"
    if quota_project and not any(
        k.lower() == "x-goog-user-project" for k in fwd_headers
    ):
      fwd_headers["x-goog-user-project"] = quota_project

    body = await request.body()
    try:
      upstream_resp = await client.request(
          method=request.method,
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

    resp_headers = {
        k: v
        for k, v in upstream_resp.headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS
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
              methods=["GET", "POST"],
          )
      ]
  )
  return _HostValidatedASGIApp(starlette_app, allowed_hosts), _lifespan
