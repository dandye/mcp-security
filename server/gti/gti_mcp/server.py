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
# Add lifespan support for startup/shutdown with strong typing
import argparse
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
import logging
import os
from typing import Any, Optional

from mcp.server.caching import CacheHint
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
import uvicorn
import vt

try:
  from mcp.server._otel import OpenTelemetryMiddleware
except ImportError:  # pragma: no cover
  OpenTelemetryMiddleware = None  # type: ignore[assignment,misc]

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("gti-mcp")

PROTOCOL_VERSION = "2026-07-28"
DEFAULT_MAX_REQUEST_BODY_SIZE = 4_194_304
DEFAULT_SESSION_IDLE_TIMEOUT = 1800
DEFAULT_MAX_SESSIONS = 10_000
DEFAULT_TOOLS_CACHE_TTL_MS = 300_000
DEFAULT_PROMPTS_CACHE_TTL_MS = 300_000
DEFAULT_RESOURCES_CACHE_TTL_MS = 60_000
_WILDCARD_BIND_HOSTS = frozenset({"0.0.0.0", "::", "[::]", "*", ""})


def _resolve_default_stateless_http() -> bool:
  """Resolve default stateless HTTP mode from MCP_STATELESS_HTTP or STATELESS."""
  raw = os.getenv("MCP_STATELESS_HTTP")
  if raw is not None and raw.strip():
    return raw.strip().lower() not in {"0", "false", "no", "off"}
  legacy = os.getenv("STATELESS")
  if legacy is not None and legacy.strip():
    return legacy.strip().lower() not in {"0", "false", "no", "off"}
  return True


# Backward-compatible module attribute reflecting default stateless HTTP mode.
stateless = _resolve_default_stateless_http()


def _resolve_tools_cache_ttl_ms(default: int = DEFAULT_TOOLS_CACHE_TTL_MS) -> int:
  """Resolve the tools/list SEP-2549 cache TTL in milliseconds."""
  raw_ttl = os.getenv("MCP_TOOLS_CACHE_TTL_MS")
  if raw_ttl is None or not raw_ttl.strip():
    return default
  try:
    parsed = int(raw_ttl.strip())
  except ValueError:
    logger.warning(
        "Invalid MCP_TOOLS_CACHE_TTL_MS value %r; using default %d ms",
        raw_ttl,
        default,
    )
    return default
  if parsed < 0:
    logger.warning(
        "Negative MCP_TOOLS_CACHE_TTL_MS value %d; using default %d ms",
        parsed,
        default,
    )
    return default
  return parsed


def _build_cache_hints() -> dict[str, CacheHint]:
  """Build SEP-2549 list freshness cache hints for GTI MCP."""
  return {
      "tools/list": CacheHint(
          ttl_ms=_resolve_tools_cache_ttl_ms(),
          scope="public",
      ),
      "prompts/list": CacheHint(
          ttl_ms=DEFAULT_PROMPTS_CACHE_TTL_MS,
          scope="public",
      ),
      "resources/list": CacheHint(
          ttl_ms=DEFAULT_RESOURCES_CACHE_TTL_MS,
          scope="private",
      ),
  }


def _deduplicate_otel_middleware(server_instance: MCPServer) -> None:
  """Keep a single outermost OpenTelemetryMiddleware on the low-level server."""
  if OpenTelemetryMiddleware is None:
    return
  lowlevel = getattr(server_instance, "_lowlevel_server", None)
  mw_list = getattr(lowlevel, "middleware", None)
  if not isinstance(mw_list, list):
    return
  seen_otel = False
  deduped: list[Any] = []
  for item in mw_list:
    if isinstance(item, OpenTelemetryMiddleware):
      if seen_otel:
        continue
      seen_otel = True
    deduped.append(item)
  mw_list[:] = deduped


def _register_health_routes(server_instance: MCPServer) -> None:
  """Register /healthz and /readyz custom routes idempotently."""
  existing_routes = getattr(server_instance, "_custom_starlette_routes", [])
  existing_paths = {getattr(route, "path", None) for route in existing_routes}

  async def _probe_response(_request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "server": server_instance.name,
            "protocol_version": PROTOCOL_VERSION,
        }
    )

  if "/healthz" not in existing_paths:
    server_instance.custom_route("/healthz", methods=["GET"])(_probe_response)
  if "/readyz" not in existing_paths:
    server_instance.custom_route("/readyz", methods=["GET"])(_probe_response)


def _vt_client_factory(unused_ctx) -> vt.Client:
  api_key = os.getenv("VT_APIKEY")
  if not api_key:
    raise ValueError("VT_APIKEY environment variable is required")
  return vt.Client(api_key, trust_env=True)

vt_client_factory = _vt_client_factory


@asynccontextmanager
async def vt_client(ctx: Context) -> AsyncIterator[vt.Client]:
  """Provides a vt.Client instance for the current request."""
  client = vt_client_factory(ctx)

  try:
    yield client
  finally:
    await client.close_async()

# Create a named server and specify dependencies, discovery metadata, SEP-2549 cache hints, and OTel
server = MCPServer(
    name="gti-mcp",
    title="Google Threat Intelligence MCP Server",
    version="0.2.0",
    description=(
        "MCP server for Google Threat Intelligence (GTI) and VirusTotal v3 "
        "IOC enrichment, threat actor/malware/campaign collections, sandbox "
        "behavior analysis, digital threat monitoring, and standard YARA "
        "file/payload livehunt and retrohunt rulesets."
    ),
    website_url="https://github.com/google/mcp-security",
    instructions=(
        "Use these tools to enrich indicators and pivot across Google Threat "
        "Intelligence collections. Check list_threat_profiles first when "
        "scoping organization-relevant threats, then use search_threats or "
        "get_collection_report and pivot via relationship tools "
        "(get_entities_related_to_a_collection, get_entities_related_to_a_file, "
        "get_entities_related_to_a_domain, get_entities_related_to_an_ip_address, "
        "get_entities_related_to_an_url). Ruleset and hunting tools in gti-mcp "
        "operate on standard YARA rules for binary/file payload matching, not "
        "YARA-L 2.0 Chronicle SIEM UDM event detection rules (use secops-mcp "
        "for YARA-L 2.0 SIEM rules)."
    ),
    dependencies=["vt-py"],
    cache_hints=_build_cache_hints(),
    middleware=[OpenTelemetryMiddleware()] if OpenTelemetryMiddleware is not None else None,
)
_deduplicate_otel_middleware(server)
_register_health_routes(server)

# Load tools.
from gti_mcp.tools import *


def _resolve_allowed_hosts(
    host: str = "127.0.0.1",
    allowed_hosts: Optional[list[str]] = None,
) -> list[str]:
  """Build the Host-header allowlist for DNS-rebinding protection."""
  candidates: list[str] = [
      "127.0.0.1:*",
      "127.0.0.1",
      "localhost:*",
      "localhost",
      "[::1]:*",
      "[::1]",
  ]
  normalized_host = host.strip()
  if normalized_host and normalized_host not in _WILDCARD_BIND_HOSTS:
    if ":" in normalized_host and not normalized_host.startswith("["):
      bracketed = f"[{normalized_host}]"
      candidates.extend([bracketed, f"{bracketed}:*"])
    else:
      candidates.append(normalized_host)
      if not normalized_host.endswith(":*") and ":" not in normalized_host.lstrip("["):
        candidates.append(f"{normalized_host}:*")
      elif normalized_host.startswith("[") and normalized_host.endswith("]"):
        candidates.append(f"{normalized_host}:*")

  env_hosts = os.getenv("MCP_ALLOWED_HOSTS", "")
  if env_hosts.strip():
    for entry in env_hosts.split(","):
      cleaned = entry.strip()
      if cleaned:
        candidates.append(cleaned)

  if allowed_hosts:
    for entry in allowed_hosts:
      cleaned = entry.strip()
      if cleaned:
        candidates.append(cleaned)

  deduped: list[str] = []
  seen: set[str] = set()
  for item in candidates:
    if item not in seen:
      seen.add(item)
      deduped.append(item)
  return deduped


def _resolve_allowed_origins(
    resolved_hosts: Sequence[str],
    allowed_origins: Optional[list[str]] = None,
) -> list[str]:
  """Build the Origin-header allowlist from resolved allowed_hosts and MCP_ALLOWED_ORIGINS."""
  candidates: list[str] = []
  for host_pattern in resolved_hosts:
    cleaned = host_pattern.strip()
    if not cleaned:
      continue
    candidates.append(f"http://{cleaned}")
    candidates.append(f"https://{cleaned}")
    if cleaned.endswith(":*"):
      base_host = cleaned[:-2]
      if base_host:
        candidates.append(f"http://{base_host}")
        candidates.append(f"https://{base_host}")

  env_origins = os.getenv("MCP_ALLOWED_ORIGINS", "")
  if env_origins.strip():
    for entry in env_origins.split(","):
      cleaned = entry.strip()
      if cleaned:
        candidates.append(cleaned)

  if allowed_origins:
    for entry in allowed_origins:
      cleaned = entry.strip()
      if cleaned:
        candidates.append(cleaned)

  deduped: list[str] = []
  seen: set[str] = set()
  for item in candidates:
    if item not in seen:
      seen.add(item)
      deduped.append(item)
  return deduped


def build_streamable_http_app(
    server_instance: MCPServer = server,
    *,
    host: str = "127.0.0.1",
    stateless_http: bool = True,
    allowed_hosts: Optional[list[str]] = None,
    allowed_origins: Optional[list[str]] = None,
) -> Starlette:
  """Build the bounded Streamable HTTP ASGI application with health probes."""
  _register_health_routes(server_instance)
  resolved_hosts = _resolve_allowed_hosts(host=host, allowed_hosts=allowed_hosts)
  resolved_origins = _resolve_allowed_origins(
      resolved_hosts,
      allowed_origins=allowed_origins,
  )
  transport_security = TransportSecuritySettings(
      enable_dns_rebinding_protection=True,
      allowed_hosts=resolved_hosts,
      allowed_origins=resolved_origins,
  )
  return server_instance.streamable_http_app(
      streamable_http_path="/mcp",
      stateless_http=stateless_http,
      max_request_body_size=DEFAULT_MAX_REQUEST_BODY_SIZE,
      session_idle_timeout=DEFAULT_SESSION_IDLE_TIMEOUT,
      max_sessions=DEFAULT_MAX_SESSIONS,
      transport_security=transport_security,
      host=host,
  )


def _normalize_transport(raw_transport: str) -> str:
  """Normalize CLI/environment transport aliases."""
  normalized = raw_transport.strip().lower()
  if normalized == "http":
    return "streamable-http"
  return normalized


def _first_nonempty_env(*names: str, default: str) -> str:
  """Return the first non-empty stripped environment variable value, or default."""
  for name in names:
    raw = os.getenv(name)
    if raw is not None and raw.strip():
      return raw.strip()
  return default


class _MCPArgumentParser(argparse.ArgumentParser):
  """ArgumentParser that validates MCP_* and GTI_MCP_* environment defaults on parse."""

  def parse_known_args(
      self,
      args: Optional[Sequence[str]] = None,
      namespace: Optional[argparse.Namespace] = None,
  ) -> tuple[argparse.Namespace, list[str]]:
    parsed_ns, remaining = super().parse_known_args(args, namespace)
    if getattr(parsed_ns, "transport", None) is None:
      raw_transport = _first_nonempty_env(
          "MCP_TRANSPORT",
          "GTI_MCP_TRANSPORT",
          default="stdio",
      )
      normalized_transport = _normalize_transport(raw_transport)
      if normalized_transport not in {"stdio", "streamable-http"}:
        self.error(
            f"invalid MCP_TRANSPORT value {raw_transport!r} "
            "(choose from 'stdio', 'streamable-http', 'http')"
        )
      parsed_ns.transport = normalized_transport
    else:
      parsed_ns.transport = _normalize_transport(parsed_ns.transport)

    if getattr(parsed_ns, "host", None) is None:
      parsed_ns.host = _first_nonempty_env(
          "MCP_HOST",
          "GTI_MCP_HOST",
          default="127.0.0.1",
      )

    if getattr(parsed_ns, "port", None) is None:
      raw_port = _first_nonempty_env(
          "MCP_PORT",
          "GTI_MCP_PORT",
          default="8000",
      )
      try:
        parsed_port = int(raw_port)
      except ValueError:
        self.error(f"invalid MCP_PORT integer value: {raw_port!r}")
      if not (1 <= parsed_port <= 65535):
        self.error(f"MCP_PORT must be between 1 and 65535, got {parsed_port}")
      parsed_ns.port = parsed_port
    elif not (1 <= parsed_ns.port <= 65535):
      self.error(f"--port must be between 1 and 65535, got {parsed_ns.port}")

    return parsed_ns, remaining


def build_arg_parser() -> argparse.ArgumentParser:
  """Construct the CLI argument parser for GTI MCP."""
  parser = _MCPArgumentParser(
      description="Google Threat Intelligence MCP Server",
      allow_abbrev=False,
  )
  parser.add_argument(
      "--transport",
      choices=("stdio", "streamable-http", "http"),
      default=None,
      help="MCP transport to serve (default: MCP_TRANSPORT or stdio).",
  )
  parser.add_argument(
      "--host",
      default=None,
      help="Bind host for streamable-http transport (default: MCP_HOST or 127.0.0.1).",
  )
  parser.add_argument(
      "--port",
      type=int,
      default=None,
      help="Bind port for streamable-http transport (default: MCP_PORT or 8000).",
  )
  parser.add_argument(
      "--stateless-http",
      action=argparse.BooleanOptionalAction,
      default=_resolve_default_stateless_http(),
      help="Serve stateless Streamable HTTP requests (default: MCP_STATELESS_HTTP or true).",
  )
  return parser


# Run the server
def main(argv: Optional[Sequence[str]] = None) -> None:
  args = build_arg_parser().parse_args(argv)
  transport = _normalize_transport(args.transport)
  if transport == "streamable-http":
    app = build_streamable_http_app(
        server,
        host=args.host,
        stateless_http=args.stateless_http,
    )
    logger.info(
        "Starting %s over streamable-http on %s:%d (stateless_http=%s)",
        server.name,
        args.host,
        args.port,
        args.stateless_http,
    )
    uvicorn.run(app, host=args.host, port=args.port)
  elif transport == "stdio":
    server.run(transport="stdio")
  else:  # pragma: no cover
    raise ValueError(f"Unsupported MCP transport: {transport!r}")


if __name__ == "__main__":
  main()
