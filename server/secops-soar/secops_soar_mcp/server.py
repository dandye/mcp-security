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
from mcp.server.auth.provider import TokenVerifier
from mcp.server.caching import CacheHint
from mcp.server.mcpserver import DEFAULT_RESOURCE_SECURITY, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from secops_soar_mcp import bindings
from secops_soar_mcp.case_management import (
    register_tools as register_tools_case_management,
)
from secops_soar_mcp.phase5 import (
    build_request_state_security,
    build_root_oauth_well_known_routes,
    extract_resource_host_patterns,
    resolve_oauth_configuration,
    sync_apps_state,
)
from secops_soar_mcp.prompts import register_prompts as register_soar_prompts
from secops_soar_mcp.resources import register_resources as register_soar_resources
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
    resource_security=DEFAULT_RESOURCE_SECURITY,
    request_state_security=build_request_state_security(),
    middleware=[OpenTelemetryMiddleware()] if OpenTelemetryMiddleware is not None else None,
)
_deduplicate_otel_middleware(mcp)
_register_health_routes(mcp)

register_tools_case_management(mcp)
register_soar_resources(mcp)
register_soar_prompts(mcp)


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


def _first_nonempty_env(*names: str, default: str) -> str:
    """Return the first non-empty stripped environment variable value, or default."""
    for name in names:
        raw = os.getenv(name)
        if raw is not None and raw.strip():
            return raw.strip()
    return default


class _MCPArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that validates MCP_* environment defaults on parse."""

    def parse_known_args(
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
    ) -> tuple[argparse.Namespace, list[str]]:
        parsed_ns, remaining = super().parse_known_args(args, namespace)
        if getattr(parsed_ns, "transport", None) is None:
            raw_transport = _first_nonempty_env("MCP_TRANSPORT", default="stdio")
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
            parsed_ns.host = _first_nonempty_env("MCP_HOST", default="127.0.0.1")

        if getattr(parsed_ns, "port", None) is None:
            raw_port = _first_nonempty_env("MCP_PORT", default="8000")
            try:
                parsed_port = int(raw_port)
            except ValueError:
                self.error(f"invalid MCP_PORT integer value: {raw_port!r}")
            if not (1 <= parsed_port <= 65535):
                self.error(f"MCP_PORT must be between 1 and 65535, got {parsed_port}")
            parsed_ns.port = parsed_port
        elif not (1 <= parsed_ns.port <= 65535):
            self.error(f"--port must be between 1 and 65535, got {parsed_ns.port}")

        if getattr(parsed_ns, "unattended_policy", None) is None:
            raw_policy = os.getenv("MCP_UNATTENDED_DESTRUCTIVE_POLICY", "").strip().lower()
            if raw_policy:
                if raw_policy not in {"allow", "deny"}:
                    self.error(
                        f"invalid MCP_UNATTENDED_DESTRUCTIVE_POLICY value {raw_policy!r} "
                        "(choose from 'allow', 'deny')"
                    )
                parsed_ns.unattended_policy = raw_policy

        return parsed_ns, remaining


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for SecOps SOAR MCP."""
    raw_integrations = os.getenv("SOAR_INTEGRATIONS")
    default_integrations = (
        raw_integrations.strip()
        if raw_integrations is not None and raw_integrations.strip()
        else None
    )
    arg_parser = _MCPArgumentParser(
        description="SecOps SOAR MCP Server",
        allow_abbrev=False,
    )
    arg_parser.add_argument(
        "--integrations",
        default=default_integrations,
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
        default=None,
        help="MCP transport to serve (default: MCP_TRANSPORT or stdio).",
    )
    arg_parser.add_argument(
        "--host",
        default=None,
        help="Bind host for streamable-http transport (default: MCP_HOST or 127.0.0.1).",
    )
    arg_parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port for streamable-http transport (default: MCP_PORT or 8000).",
    )
    arg_parser.add_argument(
        "--stateless-http",
        action=argparse.BooleanOptionalAction,
        default=_resolve_default_stateless_http(),
        help="Serve stateless Streamable HTTP requests (default: MCP_STATELESS_HTTP or true).",
    )
    arg_parser.add_argument(
        "--elicit-destructive",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Require user elicitation before destructive operations (default: MCP_ELICIT_DESTRUCTIVE or false).",
    )
    arg_parser.add_argument(
        "--unattended-policy",
        choices=("allow", "deny"),
        default=None,
        help="Policy when client lacks elicitation capability (default: allow on stdio, deny on streamable-http).",
    )
    arg_parser.add_argument(
        "--oauth-issuer-url",
        default=None,
        help="OAuth 2.1 / OIDC issuer URL for streamable-http Resource Server mode (MCP_OAUTH_ISSUER_URL).",
    )
    arg_parser.add_argument(
        "--resource-server-url",
        default=None,
        help="Canonical RFC 8707 Resource Server URL for audience validation (MCP_RESOURCE_SERVER_URL).",
    )
    arg_parser.add_argument(
        "--required-scopes",
        default=None,
        help="Comma-separated OAuth 2.1 scopes required on streamable-http requests (MCP_REQUIRED_SCOPES).",
    )
    arg_parser.add_argument(
        "--disable-apps",
        action="store_true",
        default=False,
        help="Disable interactive MCP Apps UI resources and tool metadata (sets MCP_ENABLE_APPS=false).",
    )
    return arg_parser


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
    server_instance: MCPServer = mcp,
    *,
    host: str = "127.0.0.1",
    stateless_http: bool = True,
    allowed_hosts: Optional[list[str]] = None,
    allowed_origins: Optional[list[str]] = None,
    oauth_issuer_url: Optional[str] = None,
    resource_server_url: Optional[str] = None,
    required_scopes: Optional[Sequence[str] | str] = None,
    token_verifier: Optional[TokenVerifier] = None,
) -> Starlette:
    """Build the bounded Streamable HTTP ASGI application with health probes and optional OAuth 2.1 RS."""
    sync_apps_state(server_instance)
    _register_health_routes(server_instance)
    extra_hosts = list(allowed_hosts or [])
    extra_hosts.extend(extract_resource_host_patterns(resource_server_url))
    resolved_hosts = _resolve_allowed_hosts(
        host=host,
        allowed_hosts=extra_hosts or None,
    )
    resolved_origins = _resolve_allowed_origins(
        resolved_hosts,
        allowed_origins=allowed_origins,
    )
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=resolved_hosts,
        allowed_origins=resolved_origins,
    )
    auth_settings, resolved_verifier = resolve_oauth_configuration(
        oauth_issuer_url=oauth_issuer_url,
        resource_server_url=resource_server_url,
        required_scopes=required_scopes,
        token_verifier=token_verifier,
    )
    if auth_settings is not None and resolved_verifier is not None:
        custom_routes = list(getattr(server_instance, "_custom_starlette_routes", []))
        existing_paths = {getattr(r, "path", None) for r in custom_routes}
        for wk_route in build_root_oauth_well_known_routes(
            auth_settings, server_name=server_instance.name
        ):
            if wk_route.path not in existing_paths:
                custom_routes.append(wk_route)
        return server_instance._lowlevel_server.streamable_http_app(
            streamable_http_path="/mcp",
            stateless_http=stateless_http,
            max_request_body_size=DEFAULT_MAX_REQUEST_BODY_SIZE,
            session_idle_timeout=DEFAULT_SESSION_IDLE_TIMEOUT,
            max_sessions=DEFAULT_MAX_SESSIONS,
            transport_security=transport_security,
            host=host,
            auth=auth_settings,
            token_verifier=resolved_verifier,
            custom_starlette_routes=custom_routes,
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
    if args.elicit_destructive is not None:
        os.environ["MCP_ELICIT_DESTRUCTIVE"] = "true" if args.elicit_destructive else "false"
    if args.unattended_policy is not None:
        os.environ["MCP_UNATTENDED_DESTRUCTIVE_POLICY"] = args.unattended_policy
    if getattr(args, "disable_apps", False):
        os.environ["MCP_ENABLE_APPS"] = "false"
    setup_logging(args.verbose)
    transport = _normalize_transport(args.transport)
    os.environ["MCP_TRANSPORT"] = transport
    sync_apps_state(mcp)
    logger.info("Starting SecOps SOAR MCP server (transport=%s)", transport)
    try:
        await bindings.bind()
        register_tools(args.integrations)
        if transport == "streamable-http":
            app = build_streamable_http_app(
                mcp,
                host=args.host,
                stateless_http=args.stateless_http,
                oauth_issuer_url=args.oauth_issuer_url,
                resource_server_url=args.resource_server_url,
                required_scopes=args.required_scopes,
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
        elif transport == "stdio":
            await mcp.run_stdio_async()
        else:  # pragma: no cover
            raise ValueError(f"Unsupported MCP transport: {transport!r}")
    except Exception as e:
        logger.error("Error: %s", e)
    finally:
        await bindings.cleanup()


def run_main(argv: Optional[Sequence[str]] = None):
    """Entry point function that properly awaits the async main function."""
    return asyncio.run(main(argv))


if __name__ == "__main__":
    run_main()
