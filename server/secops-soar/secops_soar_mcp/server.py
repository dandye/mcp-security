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
"""Main entry point for the SOAR MCP server."""

import argparse
import asyncio
from collections.abc import Sequence
import importlib
import importlib.util
import os
from pathlib import Path
from typing import Any, Optional

from logger_utils import get_logger, setup_logging
from mcp.server.caching import CacheHint
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from secops_soar_mcp import bindings
from secops_soar_mcp.case_management import (
    register_tools as register_tools_case_management,
)
from secops_soar_mcp.utils.utils import normalize_integration_name
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
import uvicorn

try:
    from mcp.server._otel import OpenTelemetryMiddleware
except ImportError:  # pragma: no cover
    OpenTelemetryMiddleware = None  # type: ignore[assignment,misc]

logger = get_logger(__name__)

PROTOCOL_VERSION = "2026-07-28"
DEFAULT_MAX_REQUEST_BODY_SIZE = 4_194_304
DEFAULT_SESSION_IDLE_TIMEOUT = 1800
DEFAULT_MAX_SESSIONS = 10_000
DEFAULT_TOOLS_CACHE_TTL_MS = 300_000
DEFAULT_PROMPTS_CACHE_TTL_MS = 300_000
DEFAULT_RESOURCES_CACHE_TTL_MS = 60_000
_WILDCARD_BIND_HOSTS = frozenset({"0.0.0.0", "::", "[::]", "*", ""})


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
    """Build SEP-2549 list freshness cache hints for SecOps SOAR MCP."""
    tools_scope = os.getenv("MCP_TOOLS_CACHE_SCOPE", "public").strip().lower()
    if tools_scope not in {"public", "private"}:
        tools_scope = "public"
    return {
        "tools/list": CacheHint(
            ttl_ms=_resolve_tools_cache_ttl_ms(),
            scope=tools_scope,  # type: ignore[arg-type]
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


mcp = MCPServer(
    name="secops-soar-mcp",
    title="Google Security Operations SOAR MCP Server",
    version="0.3.0",
    description=(
        "MCP server for Google Security Operations SOAR case lifecycle "
        "management, alert grouping, entity context, investigation comments, "
        "and third-party marketplace response integrations."
    ),
    website_url="https://github.com/google/mcp-security",
    instructions=(
        "Use these tools to manage Google Security Operations SOAR cases and "
        "orchestrate response actions. Begin incident review with list_cases "
        "and get_case_full_details, inspect linked alerts and raw telemetry "
        "via list_alerts_by_case and list_events_by_alert, pivot on entities "
        "with list_alert_group_identifiers_by_case, "
        "get_entities_by_alert_group_identifiers, and get_entity_details, "
        "record investigation audit trails with post_case_comment, and "
        "finalize disposition with close_case."
    ),
    cache_hints=_build_cache_hints(),
    middleware=[OpenTelemetryMiddleware()] if OpenTelemetryMiddleware is not None else None,
)
_deduplicate_otel_middleware(mcp)
_register_health_routes(mcp)

register_tools_case_management(mcp)


def _resolve_default_stateless_http() -> bool:
    """Resolve default stateless HTTP mode from MCP_STATELESS_HTTP (defaults True)."""
    raw = os.getenv("MCP_STATELESS_HTTP")
    if raw is None or not raw.strip():
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def _normalize_transport(raw_transport: str) -> str:
    """Normalize CLI/environment transport aliases."""
    normalized = raw_transport.strip().lower()
    if normalized == "http":
        return "streamable-http"
    return normalized


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for SecOps SOAR MCP."""
    default_transport = _normalize_transport(os.getenv("MCP_TRANSPORT", "stdio"))
    default_host = os.getenv("MCP_HOST", "127.0.0.1")
    default_port = int(os.getenv("MCP_PORT", "8000"))
    arg_parser = argparse.ArgumentParser(
        description="SecOps SOAR MCP Server",
        allow_abbrev=False,
    )
    arg_parser.add_argument(
        "--integrations",
        default=os.getenv("SOAR_INTEGRATIONS"),
        help=(
            "Comma-separated list of integration names to enable "
            "(e.g., CSV,SiemplifyThreatFuse). If not provided, no integrations are enabled."
        ),
    )
    arg_parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose (debug) logging"
    )
    arg_parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "http"),
        default=default_transport,
        help="MCP transport to serve (default: MCP_TRANSPORT or stdio).",
    )
    arg_parser.add_argument(
        "--host",
        default=default_host,
        help="Bind host for streamable-http transport (default: MCP_HOST or 127.0.0.1).",
    )
    arg_parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help="Bind port for streamable-http transport (default: MCP_PORT or 8000).",
    )
    arg_parser.add_argument(
        "--stateless-http",
        action=argparse.BooleanOptionalAction,
        default=_resolve_default_stateless_http(),
        help="Serve stateless Streamable HTTP requests (default: MCP_STATELESS_HTTP or true).",
    )
    return arg_parser


parser = build_arg_parser()


def get_enabled_integrations_set(integrations_arg: str) -> set:
    """Get the set of enabled integrations from the command line arguments.

    Args:
        args: Parsed command line arguments."""
    enabled_integrations_set = set()
    if integrations_arg:
        integration_list = [
            normalize_integration_name(name)
            for name in integrations_arg.split(",")
            if name.strip()
        ]
        if integration_list:
            enabled_integrations_set = set(integration_list)
            logger.info(
                "Found --integrations flag. Enabling only: %s", enabled_integrations_set
            )
            return enabled_integrations_set
        else:
            logger.warning(
                "Received --integrations flag but the list was empty after parsing. No integrations are enabled."
            )
    else:
        logger.info("No --integrations flag provided. No integrations are enabled.")
    return set()


def register_tools(integrations_arg: str):
    """Register tools for the MCP server.

    Args:
        args: Parsed command line arguments."""
    enabled_integrations_set = get_enabled_integrations_set(integrations_arg)

    logger.info("Starting dynamic tool registration...")
    try:
        script_dir = Path(__file__).parent.resolve()

        marketplace_dir = script_dir / "marketplace"

        if marketplace_dir.is_dir():
            logger.debug("Scanning for tools in: %s", marketplace_dir)

            init_file = marketplace_dir / "__init__.py"
            if not init_file.exists():
                logger.warning(
                    "Marketplace directory '%s' is missing __init__.py. Tool registration might fail.",
                    marketplace_dir,
                )

            for py_file in marketplace_dir.glob("*.py"):
                if py_file.name == "__init__.py" or not py_file.is_file():
                    continue

                module_stem = (
                    py_file.stem
                )  # The filename without .py (e.g., "csv")
                if module_stem not in enabled_integrations_set:
                    continue
                primary_import_path = f"secops_soar_mcp.marketplace.{module_stem}"
                fallback_import_path = f"marketplace.{module_stem}"
                module_import_path = primary_import_path

                try:
                    logger.debug(
                        "  Attempting to import module: %s", primary_import_path
                    )
                    try:
                        module = importlib.import_module(primary_import_path)
                    except ModuleNotFoundError as primary_err:
                        module_import_path = fallback_import_path
                        try:
                            module = importlib.import_module(fallback_import_path)
                        except ModuleNotFoundError:
                            if "." in module_stem:
                                safe_stem = module_stem.replace(".", "_")
                                spec = importlib.util.spec_from_file_location(
                                    f"secops_soar_mcp.marketplace.{safe_stem}",
                                    py_file,
                                )
                                if spec is not None and spec.loader is not None:
                                    module = importlib.util.module_from_spec(spec)
                                    spec.loader.exec_module(module)
                                else:
                                    module_import_path = primary_import_path
                                    raise primary_err from None
                            else:
                                module_import_path = primary_import_path
                                raise primary_err from None

                    if hasattr(module, "register_tools") and callable(
                        getattr(module, "register_tools")
                    ):
                        logger.info(
                            "    Found register_tools in %s. Registering...",
                            module_stem,
                        )
                        register_function = getattr(module, "register_tools")
                        register_function(mcp)
                        logger.debug(
                            "    Successfully called register_tools for %s.",
                            module_stem,
                        )
                    else:
                        logger.warning(
                            "    Module %s found, but it has no callable 'register_tools' function.",
                            module_stem,
                        )

                except ImportError as e:
                    logger.error(
                        "  * Failed to import module %s. Error: %s",
                        module_import_path,
                        e,
                        exc_info=True,
                    )
                except Exception as e:
                    logger.error(
                        "  * Failed during registration call for module %s. Error: %s",
                        module_import_path,
                        e,
                        exc_info=True,
                    )

            logger.info("Finished scanning marketplace directory.")
        else:
            logger.warning(
                "Marketplace directory not found at %s. No tools dynamically registered.",
                marketplace_dir,
            )

    except Exception as e:
        logger.error(
            "An unexpected error occurred during tool registration setup: %s",
            e,
            exc_info=True,
        )


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


def build_streamable_http_app(
    server_instance: MCPServer = mcp,
    *,
    host: str = "127.0.0.1",
    stateless_http: bool = True,
    allowed_hosts: Optional[list[str]] = None,
) -> Starlette:
    """Build the bounded Streamable HTTP ASGI application with health probes."""
    _register_health_routes(server_instance)
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_resolve_allowed_hosts(host=host, allowed_hosts=allowed_hosts),
        allowed_origins=[
            "http://127.0.0.1:*",
            "http://localhost:*",
            "http://[::1]:*",
        ],
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


async def main(argv: Optional[Sequence[str]] = None):
    """Main function."""
    args = build_arg_parser().parse_args(argv)
    setup_logging(args.verbose)
    transport = _normalize_transport(args.transport)
    logger.info("Starting SecOps SOAR MCP server (transport=%s)", transport)
    try:
        await bindings.bind()
        register_tools(args.integrations)
        if transport == "streamable-http":
            app = build_streamable_http_app(
                mcp,
                host=args.host,
                stateless_http=args.stateless_http,
            )
            logger.info(
                "Starting %s over streamable-http on %s:%d (stateless_http=%s)",
                mcp.name,
                args.host,
                args.port,
                args.stateless_http,
            )
            config = uvicorn.Config(app, host=args.host, port=args.port)
            await uvicorn.Server(config).serve()
        else:
            await mcp.run_stdio_async()
    except Exception as e:
        logger.error("Error: %s", e)
    finally:
        await bindings.cleanup()


def run_main(argv: Optional[Sequence[str]] = None):
    """Entry point function that properly awaits the async main function."""
    return asyncio.run(main(argv))


if __name__ == "__main__":
    run_main()
