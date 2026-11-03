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
"""Out-of-sandbox Streamable HTTP and Vertex LLM gateway launcher for google/mcp-security."""

import argparse
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import importlib
import logging
import os
from typing import Callable, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send
import uvicorn

from ax_mcp_gateway.actor_jwt import (
    ActorJwtConfig,
    ActorJwtMiddleware,
    ActorJwtVerifier,
)
from ax_mcp_gateway.llm_proxy import build_vertex_llm_proxy_app

logger = logging.getLogger(__name__)

SUPPORTED_SERVERS: tuple[str, ...] = (
    "secops",
    "gti",
    "secops-soar",
    "scc",
    "vertex-llm",
)

DEFAULT_LOCAL_ALLOWED_HOSTS: tuple[str, ...] = (
    "127.0.0.1:*",
    "localhost:*",
    "[::1]:*",
)

_LOOPBACK_BIND_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


@dataclass(frozen=True)
class GatewayConfig:
  """Runtime settings for hosting an out-of-sandbox MCP or Vertex LLM gateway."""

  server_name: str
  host: str = "0.0.0.0"
  port: int = 8080
  stateless_http: bool = True
  allowed_hosts: tuple[str, ...] = field(
      default_factory=lambda: DEFAULT_LOCAL_ALLOWED_HOSTS
  )
  soar_integrations: str = ""
  skip_soar_bind_on_startup: bool = False
  jwt_config: ActorJwtConfig = field(default_factory=ActorJwtConfig)

  @classmethod
  def from_env(
      cls,
      server_name: Optional[str] = None,
      environ: Optional[Mapping[str, str]] = None,
  ) -> "GatewayConfig":
    """Builds GatewayConfig from environment variables and optional CLI overrides."""
    env = os.environ if environ is None else environ
    resolved_server = (
        server_name or env.get("GATEWAY_SERVER") or ""
    ).strip().lower()
    if resolved_server not in SUPPORTED_SERVERS:
      raise ValueError(
          f"Unsupported server {resolved_server!r}; expected one of "
          f"{SUPPORTED_SERVERS}."
      )

    host = (env.get("GATEWAY_HOST") or "0.0.0.0").strip()
    port = int((env.get("GATEWAY_PORT") or env.get("PORT") or "8080").strip())

    raw_stateless = (env.get("GATEWAY_STATELESS_HTTP") or "true").strip().lower()
    stateless = raw_stateless in {"1", "true", "yes", "on"}

    extra_hosts = [
        item.strip()
        for item in (env.get("GATEWAY_ALLOWED_HOSTS") or "").split(",")
        if item.strip()
    ]
    default_svc = (
        "llm-gateway"
        if resolved_server == "vertex-llm"
        else f"{resolved_server}-mcp"
    )
    svc_name = (env.get("GATEWAY_SERVICE_NAME") or default_svc).strip()
    svc_ns = (env.get("GATEWAY_NAMESPACE") or "secops-gateways").strip()
    k8s_hosts = [
        f"{svc_name}:{port}",
        f"{svc_name}.{svc_ns}:{port}",
        f"{svc_name}.{svc_ns}.svc:{port}",
        f"{svc_name}.{svc_ns}.svc.cluster.local:{port}",
    ]
    if port == 80:
      k8s_hosts.extend([
          svc_name,
          f"{svc_name}.{svc_ns}",
          f"{svc_name}.{svc_ns}.svc",
          f"{svc_name}.{svc_ns}.svc.cluster.local",
      ])
    local_hosts = (
        list(DEFAULT_LOCAL_ALLOWED_HOSTS)
        if host.lower() in _LOOPBACK_BIND_HOSTS
        else []
    )
    merged_hosts = tuple(
        dict.fromkeys([*local_hosts, *k8s_hosts, *extra_hosts])
    )

    soar_integrations = (env.get("SOAR_INTEGRATIONS") or "").strip()
    skip_soar_bind = (
        env.get("GATEWAY_SKIP_SOAR_BIND", "false").strip().lower()
        in {"1", "true", "yes", "on"}
    )

    return cls(
        server_name=resolved_server,
        host=host,
        port=port,
        stateless_http=stateless,
        allowed_hosts=merged_hosts,
        soar_integrations=soar_integrations,
        skip_soar_bind_on_startup=skip_soar_bind,
        jwt_config=ActorJwtConfig.from_env(env),
    )


def load_fastmcp_server(
    server_name: str,
    *,
    soar_integrations: str = "",
    skip_soar_bind_on_startup: bool = False,
) -> tuple[FastMCP, Optional[Callable[[], AsyncIterator[None]]]]:
  """Imports and returns `(FastMCP, optional_extra_lifespan)` for an installed MCP server package.

  The target server package (`google-secops-mcp`, `gti-mcp`, `secops-soar-mcp`,
  or `scc-mcp`) must be installed in the current environment; no `sys.path`
  mutation is performed.
  """
  normalized = server_name.strip().lower()
  if normalized not in SUPPORTED_SERVERS or normalized == "vertex-llm":
    raise ValueError(
        f"Unsupported FastMCP server {server_name!r}; expected one of "
        f"{tuple(s for s in SUPPORTED_SERVERS if s != 'vertex-llm')}."
    )

  if normalized == "secops":
    module = importlib.import_module("secops_mcp.server")
    return module.server, None

  if normalized == "gti":
    module = importlib.import_module("gti_mcp.server")
    return module.server, None

  if normalized == "scc":
    module = importlib.import_module("scc_mcp")
    return module.mcp, None

  # secops-soar requires dynamic marketplace tool registration and async HTTP client bind/cleanup.
  soar_module = importlib.import_module("secops_soar_mcp.server")
  bindings_module = importlib.import_module("secops_soar_mcp.bindings")
  if soar_integrations:
    soar_module.register_tools(soar_integrations)

  @asynccontextmanager
  async def _soar_lifespan() -> AsyncIterator[None]:
    if not skip_soar_bind_on_startup:
      await bindings_module.bind()
    try:
      yield
    finally:
      await bindings_module.cleanup()

  return soar_module.mcp, _soar_lifespan


def configure_fastmcp_for_gateway(
    mcp_server: FastMCP, config: GatewayConfig
) -> ASGIApp:
  """Configures FastMCP settings for cluster-internal Streamable HTTP and builds its ASGI app."""
  mcp_server.settings.host = config.host
  mcp_server.settings.port = config.port
  mcp_server.settings.stateless_http = config.stateless_http
  mcp_server.settings.transport_security = TransportSecuritySettings(
      enable_dns_rebinding_protection=True,
      allowed_hosts=list(config.allowed_hosts),
  )
  # Reset any previously instantiated session manager if settings changed in tests.
  if getattr(mcp_server, "_session_manager", None) is not None:
    mcp_server._session_manager = None
  return mcp_server.streamable_http_app()


def build_gateway_app(
    config: GatewayConfig,
    *,
    mcp_server: Optional[FastMCP] = None,
    inner_app: Optional[ASGIApp] = None,
    extra_lifespan: Optional[Callable[[], AsyncIterator[None]]] = None,
) -> ASGIApp:
  """Builds the complete Out-of-Sandbox MCP or Vertex LLM Gateway ASGI application.

  Probe endpoints (`/healthz` and `/readyz`) are handled at the outer shell before
  `ActorJwtMiddleware` and `HostHeaderValidationMiddleware`, so kubelet probes arriving
  with `Host: <pod-ip>:8080` succeed while `/mcp` and `/vertex` enforce both `actorJwt`
  caller authentication and DNS-rebinding `Host` allowlists.
  """
  verifier = ActorJwtVerifier(config.jwt_config)
  if inner_app is not None:
    resolved_inner_app = inner_app
  elif config.server_name == "vertex-llm" and mcp_server is None:
    resolved_inner_app, extra_lifespan = build_vertex_llm_proxy_app(
        config.allowed_hosts
    )
  else:
    if mcp_server is None:
      mcp_server, extra_lifespan = load_fastmcp_server(
          config.server_name,
          soar_integrations=config.soar_integrations,
          skip_soar_bind_on_startup=config.skip_soar_bind_on_startup,
      )
    resolved_inner_app = configure_fastmcp_for_gateway(mcp_server, config)

  protected_app = ActorJwtMiddleware(resolved_inner_app, verifier=verifier)
  lifespan_ready = False

  @asynccontextmanager
  async def _combined_lifespan() -> AsyncIterator[None]:
    nonlocal lifespan_ready
    if extra_lifespan is not None and mcp_server is not None:
      async with extra_lifespan():
        async with mcp_server.session_manager.run():
          lifespan_ready = True
          try:
            yield
          finally:
            lifespan_ready = False
    elif extra_lifespan is not None:
      async with extra_lifespan():
        lifespan_ready = True
        try:
          yield
        finally:
          lifespan_ready = False
    elif mcp_server is not None:
      async with mcp_server.session_manager.run():
        lifespan_ready = True
        try:
          yield
        finally:
          lifespan_ready = False
    else:
      lifespan_ready = True
      try:
        yield
      finally:
        lifespan_ready = False

  async def _gateway_asgi(scope: Scope, receive: Receive, send: Send) -> None:
    scope_type = scope["type"]
    if scope_type == "lifespan":
      cm = _combined_lifespan()
      started = False
      while True:
        message = await receive()
        msg_type = message["type"]
        if msg_type == "lifespan.startup":
          try:
            await cm.__aenter__()
            started = True
          except Exception as exc:
            logger.error(
                "Gateway lifespan startup failed for %s: %s",
                config.server_name,
                exc,
                exc_info=True,
            )
            await send({"type": "lifespan.startup.failed", "message": str(exc)})
            return
          await send({"type": "lifespan.startup.complete"})
        elif msg_type == "lifespan.shutdown":
          if started:
            try:
              await cm.__aexit__(None, None, None)
            except Exception as exc:
              logger.error(
                  "Gateway lifespan shutdown failed for %s: %s",
                  config.server_name,
                  exc,
                  exc_info=True,
              )
              await send(
                  {"type": "lifespan.shutdown.failed", "message": str(exc)}
              )
              return
          await send({"type": "lifespan.shutdown.complete"})
          return

    if scope_type == "http":
      path = scope.get("path", "")
      method = scope.get("method", "GET").upper()
      if path == "/healthz" and method in {"GET", "HEAD"}:
        resp = JSONResponse(
            {"status": "ok", "server": config.server_name}, status_code=200
        )
        await resp(scope, receive, send)
        return
      if path == "/readyz" and method in {"GET", "HEAD"}:
        jwks_ok = await verifier.is_ready_async()
        if lifespan_ready and jwks_ok:
          resp = JSONResponse(
              {
                  "status": "ready",
                  "server": config.server_name,
                  "require_actor_jwt": config.jwt_config.require_actor_jwt,
              },
              status_code=200,
          )
        else:
          resp = JSONResponse(
              {
                  "status": "not_ready",
                  "server": config.server_name,
                  "lifespan_ready": lifespan_ready,
                  "jwks_ready": jwks_ok,
              },
              status_code=503,
          )
        await resp(scope, receive, send)
        return

    await protected_app(scope, receive, send)

  return _gateway_asgi


def _build_arg_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
      description=(
          "Run a google/mcp-security server or Vertex LLM proxy as an out-of-sandbox "
          "gateway with Agent Substrate actorJwt verification."
      )
  )
  parser.add_argument(
      "--server",
      choices=SUPPORTED_SERVERS,
      default=None,
      help="Target gateway package to expose (or set GATEWAY_SERVER).",
  )
  parser.add_argument(
      "--host",
      default=None,
      help="Bind interface (default: GATEWAY_HOST or 0.0.0.0).",
  )
  parser.add_argument(
      "--port",
      type=int,
      default=None,
      help="Listen port (default: GATEWAY_PORT, PORT, or 8080).",
  )
  parser.add_argument(
      "--log-level",
      default="info",
      choices=("debug", "info", "warning", "error", "critical"),
      help="Uvicorn log level.",
  )
  return parser


def main(argv: Optional[list[str]] = None) -> None:
  """CLI entry point for `mcp-security-gateway`."""
  logging.basicConfig(level=logging.INFO)
  args = _build_arg_parser().parse_args(argv)

  env_overrides = dict(os.environ)
  if args.host is not None:
    env_overrides["GATEWAY_HOST"] = args.host
  if args.port is not None:
    env_overrides["GATEWAY_PORT"] = str(args.port)

  config = GatewayConfig.from_env(
      server_name=args.server, environ=env_overrides
  )
  app = build_gateway_app(config)
  logger.info(
      "Starting out-of-sandbox gateway for %s on %s:%s (require_actor_jwt=%s)",
      config.server_name,
      config.host,
      config.port,
      config.jwt_config.require_actor_jwt,
  )
  uvicorn.run(app, host=config.host, port=config.port, log_level=args.log_level)


if __name__ == "__main__":
  main()
