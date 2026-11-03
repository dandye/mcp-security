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
"""Multi-transport MCP toolsets builder for Google ADK."""

import logging
from pathlib import Path
from typing import Any, List, Optional
from mcp_security_agent.ax_workspace import is_valid_http_endpoint
from mcp_security_agent.config import AgentSettings

logger = logging.getLogger(__name__)


def build_mcp_toolsets(settings: AgentSettings) -> List[Any]:
    """Builds and returns all configured MCP toolsets using native ADK transports.

    Args:
        settings: Initialized AgentSettings instance.

    Returns:
        List of initialized MCP toolset objects for the ADK agent.
    """
    toolsets = []

    # Locate repo server directory relative to this package
    pkg_dir = Path(__file__).resolve().parents[2]  # run-with-google-adk
    repo_root = pkg_dir.parent
    server_dir = repo_root / "server"

    try:
        from google.adk.tools.mcp_tool.mcp_toolset import (
            McpToolset,
            StdioConnectionParams,
            StdioServerParameters,
            StreamableHTTPConnectionParams,
        )
    except ImportError:
        logger.warning("google.adk.tools.mcp_tool not available; using mock/fallback toolset representation.")
        return toolsets

    def _build_remote_http_toolset(url: str) -> Any:
        cleaned_url = url.strip()
        if not is_valid_http_endpoint(cleaned_url):
            raise ValueError(
                f"Invalid MCP gateway URL {cleaned_url!r}; expected an http:// or https:// URL."
            )
        headers: dict[str, str] = {}
        if settings.mcp_gateway_auth_header and settings.mcp_gateway_auth_header.strip():
            headers["Authorization"] = settings.mcp_gateway_auth_header.strip()
        conn = StreamableHTTPConnectionParams(
            url=cleaned_url,
            headers=headers or None,
            timeout=settings.http_timeout_seconds,
        )
        return McpToolset(connection_params=conn)

    stdio_env_cache: Optional[dict[str, str]] = None

    def _get_stdio_env() -> dict[str, str]:
        """Constructs environment dictionary lazily for Stdio subprocesses."""
        nonlocal stdio_env_cache
        if stdio_env_cache is not None:
            return stdio_env_cache
        import os
        env = dict(os.environ)

        if settings.google_application_credentials:
            env["GOOGLE_APPLICATION_CREDENTIALS"] = settings.google_application_credentials
            if "CLOUDSDK_CONFIG" not in env:
                env["CLOUDSDK_CONFIG"] = str(Path(settings.google_application_credentials).parent)

        if settings.secops_sa_path:
            env["SECOPS_SA_PATH"] = settings.secops_sa_path
        if settings.secops_impersonate_service_account:
            env["SECOPS_IMPERSONATE_SERVICE_ACCOUNT"] = settings.secops_impersonate_service_account

        gcp_project = (
            settings.google_cloud_project
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GCP_PROJECT_ID")
            or settings.chronicle_project_id
        )
        if gcp_project:
            env["GOOGLE_CLOUD_PROJECT"] = gcp_project

        chronicle_project = (
            settings.chronicle_project_id
            or gcp_project
        )
        if chronicle_project:
            env["CHRONICLE_PROJECT_ID"] = chronicle_project

        if settings.chronicle_customer_id:
            env["CHRONICLE_CUSTOMER_ID"] = settings.chronicle_customer_id
        if settings.chronicle_region:
            env["CHRONICLE_REGION"] = settings.chronicle_region

        if settings.vt_apikey:
            env["VT_APIKEY"] = settings.vt_apikey
        if settings.soar_url:
            env["SOAR_URL"] = settings.soar_url
        if settings.soar_app_key:
            env["SOAR_APP_KEY"] = settings.soar_app_key

        env.setdefault("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
        env.setdefault("GOOGLE_API_USE_MTLS_ENDPOINT", "never")
        env.setdefault("CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE", "false")

        stdio_env_cache = env
        return env

    def _get_stdio_cmd_args(server_path: Path, script_relpath: str) -> tuple[str, list[str], dict[str, str]]:
        import shutil
        import sys
        import os

        if settings.ax_zero_secret_sandbox:
            raise ValueError(
                f"Zero-secret sandbox violation: cannot spawn local stdio MCP server "
                f"for {server_path.name!r} when AX_ZERO_SECRET_SANDBOX=true. "
                "Configure a Streamable HTTP out-of-sandbox gateway URL instead."
            )

        env = dict(_get_stdio_env())
        if shutil.which("uv"):
            return "uv", ["--directory", str(server_path), "run", script_relpath], env

        logger.warning(
            "uv executable not found in PATH; falling back to sys.executable (%s) for %s",
            sys.executable,
            server_path.name,
        )
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{server_path}{os.pathsep}{existing_pp}" if existing_pp else str(server_path)
        script_full = str(server_path / script_relpath)
        return sys.executable, [script_full], env

    server_specs = (
        ("SecOps SIEM", settings.load_secops_mcp, settings.secops_mcp_url, "secops", "secops_mcp/server.py"),
        ("SCC", settings.load_scc_mcp, settings.scc_mcp_url, "scc", "scc_mcp.py"),
        ("GTI", settings.load_gti_mcp, settings.gti_mcp_url, "gti", "gti_mcp/server.py"),
        ("SecOps SOAR", settings.load_secops_soar_mcp, settings.secops_soar_mcp_url, "secops-soar", "secops_soar_mcp/server.py"),
    )

    for label, enabled, remote_url, dir_name, script_rel in server_specs:
        if not enabled:
            continue
        if remote_url and remote_url.strip():
            logger.info("Configuring %s MCP via Streamable HTTP gateway: %s", label, remote_url)
            toolsets.append(_build_remote_http_toolset(remote_url))
        else:
            target_dir = server_dir / dir_name
            cmd, args, env = _get_stdio_cmd_args(target_dir, script_rel)
            logger.info("Configuring %s MCP via Stdio subprocess at %s", label, target_dir)
            conn = StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=cmd,
                    args=args,
                    env=env,
                ),
                timeout=settings.stdio_timeout_seconds,
            )
            toolsets.append(McpToolset(connection_params=conn))

    return toolsets
