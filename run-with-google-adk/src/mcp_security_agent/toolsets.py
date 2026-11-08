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
"""Multi-transport MCP toolsets builder for Google ADK v2.13+."""

import asyncio
import base64
import json
import logging
from pathlib import Path
import sys
import threading
import time
from typing import Any, Dict, FrozenSet, List, Optional
from urllib.parse import urlparse

from mcp_security_agent.config import AgentSettings

logger = logging.getLogger(__name__)

CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

BLOAT_ONEMCP_FEED_TOOLS: FrozenSet[str] = frozenset(
    {
        "create_feed",
        "update_feed",
        "run_parser",
        "list_feeds",
        "get_feed",
        "disable_feed",
        "enable_feed",
    }
)

try:
    from google.adk.tools.mcp_tool.mcp_toolset import McpToolset as _BaseMcpToolset
except ImportError:
    _BaseMcpToolset = object  # type: ignore[assignment,misc]

try:
    from google.adk.tools.load_mcp_resource_tool import (
        LoadMcpResourceTool as _BaseLoadMcpResourceTool,
    )
except ImportError:
    _BaseLoadMcpResourceTool = object  # type: ignore[assignment,misc]


def filter_non_bloat_feed_tools(tool: Any, readonly_context: Any = None) -> bool:
    """Excludes heavy feed-management schemas on remote Chronicle OneMCP endpoints."""
    _ = readonly_context
    return getattr(tool, "name", "") not in BLOAT_ONEMCP_FEED_TOOLS


def inject_w3c_trace_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Injects W3C traceparent and tracestate headers when an OpenTelemetry span is active."""
    try:
        from opentelemetry import propagate, trace

        span = trace.get_current_span()
        if span is not None and span.get_span_context().is_valid:
            propagate.inject(headers)
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("Skipping OpenTelemetry trace header injection: %s", exc)
    return headers


def is_destructive_mcp_tool(tool: Any) -> bool:
    """Returns True when an MCP tool carries ToolAnnotations with destructive_hint=True."""
    raw = getattr(tool, "raw_mcp_tool", None) or getattr(tool, "_mcp_tool", None) or tool
    annotations = getattr(raw, "annotations", None)
    if annotations is None:
        return False
    if isinstance(annotations, dict):
        if (
            annotations.get("read_only_hint") is True
            or annotations.get("readOnlyHint") is True
        ):
            return False
        return bool(
            annotations.get("destructive_hint") is True
            or annotations.get("destructiveHint") is True
        )
    if (
        getattr(annotations, "read_only_hint", None) is True
        or getattr(annotations, "readOnlyHint", None) is True
    ):
        return False
    destructive = getattr(annotations, "destructive_hint", None)
    if destructive is None:
        destructive = getattr(annotations, "destructiveHint", None)
    return destructive is True


def _is_chronicle_onemcp_url(url: str, chronicle_remote_url: Optional[str] = None) -> bool:
    """Returns True if url targets a hosted Chronicle OneMCP endpoint."""
    if chronicle_remote_url and url.strip() == chronicle_remote_url.strip():
        return True
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return host.endswith(".googleapis.com") and "chronicle" in host


class McpElicitationHandler:
    """Picklable MCP elicitation callback honoring operator confirmation policies."""

    def __init__(self, policy: str = "prompt", server_name: str = "mcp") -> None:
        self.policy = (policy or "prompt").strip().lower()
        self.server_name = server_name

    async def __call__(self, context: Any, params: Any) -> Any:
        _ = context
        from mcp.types import ElicitResult

        message = getattr(params, "message", "Confirm requested MCP server action?")
        logger.info("MCP elicitation requested by %s: %s", self.server_name, message)

        if self.policy == "accept":
            return ElicitResult(action="accept", content={"confirm": True})
        if self.policy == "cancel":
            return ElicitResult(action="cancel")
        if self.policy == "decline":
            return ElicitResult(action="decline")

        stdin = getattr(sys, "stdin", None)
        if stdin is not None and hasattr(stdin, "isatty") and stdin.isatty():
            prompt_text = f"[MCP Confirmation - {self.server_name}] {message} Type 'yes' to confirm: "
            try:
                answer = await asyncio.to_thread(input, prompt_text)
            except (EOFError, KeyboardInterrupt):
                return ElicitResult(action="cancel")
            if answer.strip().lower() in ("y", "yes", "true", "confirm", "approve"):
                return ElicitResult(action="accept", content={"confirm": True})
            return ElicitResult(action="decline")

        logger.warning(
            "Declining interactive MCP elicitation from %s because no TTY is attached.",
            self.server_name,
        )
        return ElicitResult(action="decline")


def _extract_jwt_expiry_monotonic(token: str, default_ttl_seconds: float = 300.0) -> float:
    """Computes a monotonic cache deadline from an unverified JWT exp claim (with 60s skew)."""
    parts = token.split(".")
    if len(parts) == 3:
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        try:
            raw = base64.urlsafe_b64decode((payload_b64 + padding).encode("ascii"))
            claims = json.loads(raw.decode("utf-8"))
            exp = claims.get("exp")
            if isinstance(exp, (int, float)):
                remaining = float(exp) - time.time() - 60.0
                return time.monotonic() + max(0.0, remaining)
        except Exception:
            pass
    return time.monotonic() + default_ttl_seconds


class GcpRemoteHeaderProvider:
    """Picklable per-request async header provider for remote Streamable HTTP MCP servers."""

    def __init__(
        self,
        *,
        remote_url: str,
        server_slug: str,
        auth_mode: str = "oauth",
        use_gcp_auth: Optional[bool] = None,
        static_bearer_token: Optional[str] = None,
        quota_project: Optional[str] = None,
        sa_path: Optional[str] = None,
        impersonate_service_account: Optional[str] = None,
        vt_apikey: Optional[str] = None,
    ) -> None:
        self.remote_url = remote_url
        self.server_slug = server_slug
        self.auth_mode = (auth_mode or "oauth").strip().lower()
        self.use_gcp_auth = use_gcp_auth
        self.static_bearer_token = (
            static_bearer_token.strip()
            if static_bearer_token and static_bearer_token.strip()
            else None
        )
        self.quota_project = (
            quota_project.strip() if quota_project and quota_project.strip() else None
        )
        self.sa_path = sa_path.strip() if sa_path and sa_path.strip() else None
        self.impersonate_service_account = (
            impersonate_service_account.strip()
            if impersonate_service_account and impersonate_service_account.strip()
            else None
        )
        self.vt_apikey = vt_apikey.strip() if vt_apikey and vt_apikey.strip() else None
        self._creds: Any = None
        self._auth_request: Any = None
        self._cached_id_token: Optional[str] = None
        self._cached_id_token_expires_at: float = 0.0
        self._lock = threading.RLock()

    def __getstate__(self) -> Dict[str, Any]:
        state = self.__dict__.copy()
        state["_creds"] = None
        state["_auth_request"] = None
        state["_cached_id_token"] = None
        state["_cached_id_token_expires_at"] = 0.0
        state.pop("_lock", None)
        return state

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        self._lock = threading.RLock()

    def _should_use_gcp_auth(self) -> bool:
        if self.auth_mode == "none":
            return False
        if self.use_gcp_auth is not None:
            return bool(self.use_gcp_auth)
        host = (urlparse(self.remote_url).hostname or "").lower()
        return host.endswith(".googleapis.com") or host.endswith(".run.app")

    def _target_audience(self) -> str:
        parsed = urlparse(self.remote_url)
        return (
            f"{parsed.scheme}://{parsed.netloc}"
            if parsed.scheme and parsed.netloc
            else self.remote_url
        )

    def _get_valid_cached_token(self) -> Optional[str]:
        with self._lock:
            if (
                self._creds is not None
                and getattr(self._creds, "valid", False)
                and not getattr(self._creds, "expired", False)
            ):
                token = getattr(self._creds, "token", None)
                if token:
                    return str(token)
            if self._cached_id_token and time.monotonic() < self._cached_id_token_expires_at:
                return self._cached_id_token
            return None

    def _refresh_gcp_bearer_token(self) -> Optional[str]:
        import google.auth
        from google.auth import impersonated_credentials
        from google.auth.transport.requests import Request as GoogleAuthRequest
        from google.oauth2 import id_token, service_account

        with self._lock:
            cached = self._get_valid_cached_token()
            if cached:
                return cached

            if self._auth_request is None:
                self._auth_request = GoogleAuthRequest()
            req = self._auth_request

            if self.auth_mode == "id_token":
                audience = self._target_audience()
                if self._creds is None:
                    if self.impersonate_service_account:
                        if self.sa_path:
                            base_creds = service_account.Credentials.from_service_account_file(
                                self.sa_path,
                                scopes=[CLOUD_PLATFORM_SCOPE],
                            )
                        else:
                            base_creds, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
                        target_creds = impersonated_credentials.Credentials(
                            source_credentials=base_creds,
                            target_principal=self.impersonate_service_account,
                            target_scopes=[CLOUD_PLATFORM_SCOPE],
                            lifetime=3600,
                        )
                        self._creds = impersonated_credentials.IDTokenCredentials(
                            target_credentials=target_creds,
                            target_audience=audience,
                            include_email=True,
                        )
                    elif self.sa_path:
                        self._creds = service_account.IDTokenCredentials.from_service_account_file(
                            self.sa_path,
                            target_audience=audience,
                        )
                    else:
                        try:
                            self._creds = id_token.fetch_id_token_credentials(
                                audience, request=req
                            )
                        except Exception:
                            fetched = id_token.fetch_id_token(req, audience)
                            if fetched:
                                self._cached_id_token = str(fetched)
                                self._cached_id_token_expires_at = _extract_jwt_expiry_monotonic(
                                    self._cached_id_token
                                )
                                return self._cached_id_token
                            return None

                if not getattr(self._creds, "valid", False) or getattr(
                    self._creds, "expired", False
                ):
                    self._creds.refresh(req)
                token = getattr(self._creds, "token", None)
                return str(token) if token else None

            if self._creds is None:
                if self.sa_path:
                    base_creds = service_account.Credentials.from_service_account_file(
                        self.sa_path,
                        scopes=[CLOUD_PLATFORM_SCOPE],
                    )
                else:
                    base_creds, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])

                if self.impersonate_service_account:
                    self._creds = impersonated_credentials.Credentials(
                        source_credentials=base_creds,
                        target_principal=self.impersonate_service_account,
                        target_scopes=[CLOUD_PLATFORM_SCOPE],
                        lifetime=3600,
                    )
                else:
                    self._creds = base_creds

            if not getattr(self._creds, "valid", False) or getattr(
                self._creds, "expired", False
            ):
                self._creds.refresh(req)

            token = getattr(self._creds, "token", None)
            return str(token) if token else None

    def _finalize_headers(
        self, headers: Dict[str, str], bearer_token: Optional[str]
    ) -> Dict[str, str]:
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        if self.quota_project and (
            self._should_use_gcp_auth()
            or (urlparse(self.remote_url).hostname or "").lower().endswith(".googleapis.com")
        ):
            headers["x-goog-user-project"] = self.quota_project

        if self.server_slug == "gti" and self.vt_apikey:
            headers.setdefault("x-apikey", self.vt_apikey)

        return headers

    def get_headers_sync(self, readonly_context: Any = None) -> Dict[str, str]:
        """Synchronous helper returning headers using cached or refreshed GCP credentials."""
        _ = readonly_context
        headers: Dict[str, str] = {}
        inject_w3c_trace_headers(headers)

        token: Optional[str] = None
        if self.static_bearer_token:
            token = self.static_bearer_token
        elif self._should_use_gcp_auth():
            try:
                token = self._get_valid_cached_token()
                if token is None:
                    token = self._refresh_gcp_bearer_token()
            except Exception as exc:
                logger.warning(
                    "Failed to refresh Google Cloud credentials for remote %s MCP (%s): %s",
                    self.server_slug,
                    self.remote_url,
                    exc,
                )

        return self._finalize_headers(headers, token)

    async def __call__(self, readonly_context: Any = None) -> Dict[str, str]:
        _ = readonly_context
        headers: Dict[str, str] = {}
        inject_w3c_trace_headers(headers)

        token: Optional[str] = None
        if self.static_bearer_token:
            token = self.static_bearer_token
        elif self._should_use_gcp_auth():
            try:
                token = self._get_valid_cached_token()
                if token is None:
                    token = await asyncio.to_thread(self._refresh_gcp_bearer_token)
            except Exception as exc:
                logger.warning(
                    "Failed to refresh Google Cloud credentials for remote %s MCP (%s): %s",
                    self.server_slug,
                    self.remote_url,
                    exc,
                )

        return self._finalize_headers(headers, token)


class PrefixedLoadMcpResourceTool(_BaseLoadMcpResourceTool):  # type: ignore[misc]
    """LoadMcpResourceTool subclass keeping dynamic system instructions aligned with self.name."""

    async def run_async(self, *, args: Dict[str, Any], tool_context: Any) -> Any:
        result = await super().run_async(args=args, tool_context=tool_context)
        if (
            isinstance(result, dict)
            and self.name != "load_mcp_resource"
            and isinstance(result.get("status"), str)
        ):
            updated = dict(result)
            updated["status"] = updated["status"].replace("load_mcp_resource", self.name)
            return updated
        return result

    async def _append_resources_to_llm_request(
        self, *, tool_context: Any, llm_request: Any
    ) -> None:
        dyn = getattr(llm_request, "_dynamic_instructions", None)
        before_len = len(dyn) if isinstance(dyn, list) else 0
        await super()._append_resources_to_llm_request(
            tool_context=tool_context, llm_request=llm_request
        )
        if self.name != "load_mcp_resource" and isinstance(dyn, list):
            for idx in range(before_len, len(dyn)):
                if isinstance(dyn[idx], str):
                    dyn[idx] = dyn[idx].replace("load_mcp_resource", self.name)


class SecurityMcpToolset(_BaseMcpToolset):  # type: ignore[misc]
    """McpToolset subclass enforcing ToolAnnotations.destructive_hint confirmation policies."""

    def __init__(
        self,
        *,
        confirm_destructive_tools: bool = False,
        resource_tool_prefix: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._confirm_destructive_tools = bool(confirm_destructive_tools)
        self._resource_tool_prefix = resource_tool_prefix

    async def get_tools(self, readonly_context: Any = None) -> List[Any]:
        tools = list(await super().get_tools(readonly_context))
        for idx, tool in enumerate(tools):
            if (
                _BaseLoadMcpResourceTool is not object
                and isinstance(tool, _BaseLoadMcpResourceTool)
                and not isinstance(tool, PrefixedLoadMcpResourceTool)
            ):
                upgraded = PrefixedLoadMcpResourceTool(tool._mcp_toolset)
                upgraded.name = tool.name
                upgraded.description = tool.description
                tools[idx] = upgraded
                tool = upgraded
            if (
                self._resource_tool_prefix
                and not self.tool_name_prefix
                and getattr(tool, "name", None) == "load_mcp_resource"
            ):
                tool.name = f"{self._resource_tool_prefix}_load_mcp_resource"
                tool.description = (
                    f"Loads MCP resources from the {self._resource_tool_prefix} server. "
                    "Call when you need access to resources from this server."
                )
            if self._confirm_destructive_tools and is_destructive_mcp_tool(tool):
                tool._require_confirmation = True
        return tools


def build_mcp_toolsets(settings: AgentSettings) -> List[Any]:
    """Builds and returns all configured MCP toolsets using ADK v2.13+ stdio and Streamable HTTP transports.

    Args:
        settings: Initialized AgentSettings instance.

    Returns:
        List of initialized MCP toolset objects for the ADK agent.
    """
    toolsets: List[Any] = []

    pkg_dir = Path(__file__).resolve().parents[2]  # run-with-google-adk
    repo_root = pkg_dir.parent
    server_dir = repo_root / "server"

    try:
        from google.adk.tools.mcp_tool import mcp_toolset as _adk_mcp_mod

        McpToolset = _adk_mcp_mod.McpToolset
        StdioConnectionParams = _adk_mcp_mod.StdioConnectionParams
        StdioServerParameters = _adk_mcp_mod.StdioServerParameters
        StreamableHTTPConnectionParams = _adk_mcp_mod.StreamableHTTPConnectionParams
    except ImportError:
        logger.warning(
            "google.adk.tools.mcp_tool not available; returning empty toolset list."
        )
        return toolsets

    def _build_stdio_env() -> Dict[str, str]:
        """Constructs sanitized environment dictionary for child MCP stdio subprocesses."""
        import os

        env = dict(os.environ)
        # Strip parent virtualenv and PYTHONPATH so child uv / server environments never collide
        env.pop("VIRTUAL_ENV", None)
        env.pop("PYTHONPATH", None)

        # Propagate local ADC and CloudSDK config
        if settings.google_application_credentials:
            env["GOOGLE_APPLICATION_CREDENTIALS"] = settings.google_application_credentials
            if "CLOUDSDK_CONFIG" not in env:
                env["CLOUDSDK_CONFIG"] = str(Path(settings.google_application_credentials).parent)

        # Propagate credentials & impersonation
        if settings.secops_sa_path:
            env["SECOPS_SA_PATH"] = settings.secops_sa_path
        if settings.secops_impersonate_service_account:
            env["SECOPS_IMPERSONATE_SERVICE_ACCOUNT"] = settings.secops_impersonate_service_account

        # Propagate GCP Project (for SCC, Vertex AI, and general Cloud SDK)
        gcp_project = (
            settings.google_cloud_project
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCP_PROJECT_ID")
            or settings.chronicle_project_id
        )
        if gcp_project:
            env["GOOGLE_CLOUD_PROJECT"] = gcp_project

        # Propagate SecOps SIEM Project (independent from SCC/GCP project)
        chronicle_project = settings.chronicle_project_id or gcp_project
        if chronicle_project:
            env["CHRONICLE_PROJECT_ID"] = chronicle_project

        if settings.chronicle_customer_id:
            env["CHRONICLE_CUSTOMER_ID"] = settings.chronicle_customer_id
        if settings.chronicle_region:
            env["CHRONICLE_REGION"] = settings.chronicle_region

        # Propagate GTI / SOAR params if set
        if settings.vt_apikey:
            env["VT_APIKEY"] = settings.vt_apikey
        if settings.soar_url:
            env["SOAR_URL"] = settings.soar_url
        if settings.soar_app_key:
            env["SOAR_APP_KEY"] = settings.soar_app_key

        # Cloudtop mTLS bypass
        env.setdefault("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
        env.setdefault("GOOGLE_API_USE_MTLS_ENDPOINT", "never")
        env.setdefault("CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE", "false")

        return env

    stdio_env = _build_stdio_env()

    def _get_stdio_cmd_args(
        server_path: Path, script_relpath: str
    ) -> tuple[str, list[str], Dict[str, str]]:
        import shutil

        env = dict(stdio_env)
        env.pop("VIRTUAL_ENV", None)
        env.pop("PYTHONPATH", None)

        if shutil.which("uv"):
            return "uv", ["--directory", str(server_path), "run", script_relpath], env

        logger.warning(
            "uv executable not found in PATH; falling back to sys.executable (%s) for %s",
            sys.executable,
            server_path.name,
        )
        env["PYTHONPATH"] = str(server_path)
        script_full = str(server_path / script_relpath)
        return sys.executable, [script_full], env

    active_count = sum(
        1
        for flag in (
            settings.load_secops_mcp,
            settings.load_scc_mcp,
            settings.load_gti_mcp,
            settings.load_secops_soar_mcp,
        )
        if flag
    )

    def _resolve_prefix(slug: str) -> Optional[str]:
        if not settings.mcp_tool_name_prefix_enabled:
            return None
        raw = settings.mcp_tool_prefix_map.get(slug, slug).strip().rstrip("_")
        return raw or None

    def _instantiate_toolset(
        *,
        slug: str,
        conn: Any,
        header_provider: Any = None,
        tool_filter: Any = None,
    ) -> Any:
        prefix = _resolve_prefix(slug)
        kwargs: Dict[str, Any] = {
            "connection_params": conn,
            "tool_filter": tool_filter,
            "tool_name_prefix": prefix,
            "tool_list_cache_ttl_seconds": settings.mcp_tool_list_cache_ttl_seconds,
            "header_provider": header_provider,
            "use_mcp_resources": settings.mcp_use_resources,
            "elicitation_callback": McpElicitationHandler(
                policy=settings.elicitation_policy,
                server_name=slug,
            ),
        }
        if McpToolset is _BaseMcpToolset:
            resource_prefix = slug if (active_count > 1 and not prefix) else None
            return SecurityMcpToolset(
                confirm_destructive_tools=settings.confirm_destructive_tools,
                resource_tool_prefix=resource_prefix,
                **kwargs,
            )
        return McpToolset(**kwargs)

    def _build_remote_toolset(
        *,
        slug: str,
        remote_url: str,
        quota_project: Optional[str],
        tool_filter: Any = None,
    ) -> Any:
        conn = StreamableHTTPConnectionParams(
            url=remote_url,
            timeout=settings.http_timeout_seconds,
            sse_read_timeout=settings.sse_read_timeout_seconds,
            terminate_on_close=True,
        )
        header_provider = GcpRemoteHeaderProvider(
            remote_url=remote_url,
            server_slug=slug,
            auth_mode=settings.mcp_remote_auth_mode,
            use_gcp_auth=settings.mcp_remote_use_gcp_auth,
            static_bearer_token=settings.mcp_bearer_token,
            quota_project=quota_project,
            sa_path=settings.secops_sa_path,
            impersonate_service_account=settings.secops_impersonate_service_account,
            vt_apikey=settings.vt_apikey if slug == "gti" else None,
        )
        return _instantiate_toolset(
            slug=slug,
            conn=conn,
            header_provider=header_provider,
            tool_filter=tool_filter,
        )

    # 1. Google SecOps SIEM MCP
    if settings.load_secops_mcp:
        secops_remote_url = settings.effective_secops_mcp_url
        if secops_remote_url:
            logger.info("Configuring SecOps SIEM MCP via Streamable HTTP URL: %s", secops_remote_url)
            secops_filter = (
                filter_non_bloat_feed_tools
                if (
                    settings.filter_bloat_feed_tools
                    and _is_chronicle_onemcp_url(secops_remote_url, settings.chronicle_remote_mcp_url)
                )
                else None
            )
            toolsets.append(
                _build_remote_toolset(
                    slug="secops",
                    remote_url=secops_remote_url,
                    quota_project=settings.chronicle_project_id or settings.google_cloud_project,
                    tool_filter=secops_filter,
                )
            )
        else:
            secops_dir = server_dir / "secops"
            logger.info("Configuring SecOps SIEM MCP via Stdio subprocess at %s", secops_dir)
            cmd, args, env = _get_stdio_cmd_args(secops_dir, "secops_mcp/server.py")
            conn = StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=cmd,
                    args=args,
                    env=env,
                ),
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(_instantiate_toolset(slug="secops", conn=conn))

    # 2. Security Command Center (SCC) MCP
    if settings.load_scc_mcp:
        if settings.scc_mcp_url and settings.scc_mcp_url.strip():
            scc_remote_url = settings.scc_mcp_url.strip()
            logger.info("Configuring SCC MCP via Streamable HTTP URL: %s", scc_remote_url)
            toolsets.append(
                _build_remote_toolset(
                    slug="scc",
                    remote_url=scc_remote_url,
                    quota_project=settings.google_cloud_project,
                )
            )
        else:
            scc_dir = server_dir / "scc"
            logger.info("Configuring SCC MCP via Stdio subprocess at %s", scc_dir)
            cmd, args, env = _get_stdio_cmd_args(scc_dir, "scc_mcp.py")
            conn = StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=cmd,
                    args=args,
                    env=env,
                ),
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(_instantiate_toolset(slug="scc", conn=conn))

    # 3. Google Threat Intelligence (GTI) MCP
    if settings.load_gti_mcp:
        if settings.gti_mcp_url and settings.gti_mcp_url.strip():
            gti_remote_url = settings.gti_mcp_url.strip()
            logger.info("Configuring GTI MCP via Streamable HTTP URL: %s", gti_remote_url)
            toolsets.append(
                _build_remote_toolset(
                    slug="gti",
                    remote_url=gti_remote_url,
                    quota_project=settings.google_cloud_project,
                )
            )
        else:
            gti_dir = server_dir / "gti"
            logger.info("Configuring GTI MCP via Stdio subprocess at %s", gti_dir)
            cmd, args, env = _get_stdio_cmd_args(gti_dir, "gti_mcp/server.py")
            conn = StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=cmd,
                    args=args,
                    env=env,
                ),
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(_instantiate_toolset(slug="gti", conn=conn))

    # 4. SecOps SOAR MCP
    if settings.load_secops_soar_mcp:
        if settings.secops_soar_mcp_url and settings.secops_soar_mcp_url.strip():
            soar_remote_url = settings.secops_soar_mcp_url.strip()
            logger.info("Configuring SecOps SOAR MCP via Streamable HTTP URL: %s", soar_remote_url)
            toolsets.append(
                _build_remote_toolset(
                    slug="soar",
                    remote_url=soar_remote_url,
                    quota_project=settings.google_cloud_project,
                )
            )
        else:
            soar_dir = server_dir / "secops-soar"
            logger.info("Configuring SecOps SOAR MCP via Stdio subprocess at %s", soar_dir)
            cmd, args, env = _get_stdio_cmd_args(soar_dir, "secops_soar_mcp/server.py")
            conn = StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=cmd,
                    args=args,
                    env=env,
                ),
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(_instantiate_toolset(slug="soar", conn=conn))

    return toolsets
