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
"""Centralized configuration and settings for MCP Security Agent."""

import functools
import os
from pathlib import Path
from typing import Optional
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from mcp_security_agent.ax_workspace import (
    DEFAULT_GATEWAY_AUTH_PLACEHOLDER,
    discover_ax_workspace_mcp_endpoints,
    is_ax_zero_secret_sandbox,
    verify_zero_secret_sandbox,
)

_pkg_dir = Path(__file__).resolve().parents[2]
_env_files = (
    str(_pkg_dir.parent / ".env"),
    str(_pkg_dir / ".env"),
    ".env",
)


def _is_configured(val: Optional[str]) -> bool:
    """Checks if a configuration string is set and non-empty."""
    return bool(val and val.strip())


def _discover_local_adc() -> Optional[str]:
    """Finds local .gcloud/application_default_credentials.json if present."""
    if is_ax_zero_secret_sandbox():
        return None
    candidates = [
        Path.cwd() / ".gcloud" / "application_default_credentials.json",
        _pkg_dir / ".gcloud" / "application_default_credentials.json",
        _pkg_dir.parent / ".gcloud" / "application_default_credentials.json",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


@functools.lru_cache(maxsize=1)
def discover_user_identity() -> str:
    """Discovers the active user identity from ADC, gcloud config, or system environment.

    Returns:
        The detected username or service account email, falling back to 'secops_user'.
    """
    import json
    import getpass
    import shutil
    import subprocess

    # 1. Explicit user override from environment
    explicit = os.getenv("SECOPS_USER") or os.getenv("AGENT_USER")
    if explicit and explicit.strip():
        return explicit.strip()

    # In zero-secret AX sandboxes, never probe local ADC files, google.auth, or gcloud.
    if is_ax_zero_secret_sandbox():
        return "ax_sandbox_agent"

    # 2. Impersonated service account
    impersonate_sa = os.getenv("SECOPS_IMPERSONATE_SERVICE_ACCOUNT")
    if impersonate_sa and impersonate_sa.strip():
        return impersonate_sa.strip()

    # 3. Discovered ADC file (check for account or client_email)
    adc_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or _discover_local_adc()
    if not adc_path:
        cloudsdk_config = os.getenv("CLOUDSDK_CONFIG")
        if cloudsdk_config:
            p = Path(cloudsdk_config) / "application_default_credentials.json"
            if p.is_file():
                adc_path = str(p)
    if not adc_path:
        p = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
        if p.is_file():
            adc_path = str(p)

    if adc_path and Path(adc_path).is_file():
        try:
            with open(adc_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                acct = data.get("account") or data.get("client_email")
                if acct and isinstance(acct, str) and acct.strip():
                    return acct.strip()
        except Exception:
            pass

    # 4. google.auth.default() credentials inspection
    try:
        import google.auth
        creds, _ = google.auth.default()
        sa_email = getattr(creds, "service_account_email", None)
        if sa_email and isinstance(sa_email, str) and sa_email.strip() and sa_email != "default":
            return sa_email.strip()
        acct = getattr(creds, "account", None)
        if acct and isinstance(acct, str) and acct.strip():
            return acct.strip()
    except Exception:
        pass

    # 5. gcloud active account
    if shutil.which("gcloud"):
        try:
            res = subprocess.run(
                ["gcloud", "config", "get-value", "account"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if res.returncode == 0:
                acct = res.stdout.strip()
                if acct and acct != "(unset)":
                    return acct
        except Exception:
            pass

    # 6. System username (LDAP / OS user)
    system_user = os.getenv("USER") or os.getenv("USERNAME")
    if not system_user:
        try:
            system_user = getpass.getuser()
        except Exception:
            system_user = None
    if system_user and system_user.strip():
        return system_user.strip()

    return "secops_user"


class AgentSettings(BaseSettings):
    """Configuration settings loaded from environment variables or .env file."""
    model_config = SettingsConfigDict(
        env_file=_env_files,
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # Google Cloud & LLM Settings
    google_cloud_project: Optional[str] = Field(default=None, alias="GOOGLE_CLOUD_PROJECT")
    google_cloud_location: str = Field(default="us-central1", alias="GOOGLE_CLOUD_LOCATION")
    use_vertex_ai: bool = Field(default=False, alias="GOOGLE_GENAI_USE_VERTEXAI")
    google_api_key: Optional[str] = Field(default=None, alias="GOOGLE_API_KEY")
    google_model: str = Field(default="gemini-2.5-flash", alias="GOOGLE_MODEL")

    # MCP Server Enablement Flags (Optional; auto-detected from credentials or remote URLs if None)
    load_secops_mcp: Optional[bool] = Field(default=None, alias="LOAD_SECOPS_MCP")
    load_scc_mcp: Optional[bool] = Field(default=None, alias="LOAD_SCC_MCP")
    load_gti_mcp: Optional[bool] = Field(default=None, alias="LOAD_GTI_MCP")
    load_secops_soar_mcp: Optional[bool] = Field(default=None, alias="LOAD_SECOPS_SOAR_MCP")

    # Remote MCP URLs (for Streamable HTTP out-of-sandbox gateways or remote endpoints)
    secops_mcp_url: Optional[str] = Field(default=None, alias="SECOPS_MCP_URL")
    scc_mcp_url: Optional[str] = Field(default=None, alias="SCC_MCP_URL")
    gti_mcp_url: Optional[str] = Field(default=None, alias="GTI_MCP_URL")
    secops_soar_mcp_url: Optional[str] = Field(default=None, alias="SECOPS_SOAR_MCP_URL")
    mcp_gateway_auth_header: Optional[str] = Field(default=None, alias="MCP_GATEWAY_AUTH_HEADER")
    llm_gateway_url: Optional[str] = Field(default=None, alias="LLM_GATEWAY_URL")
    ax_zero_secret_sandbox: bool = Field(default=False, alias="AX_ZERO_SECRET_SANDBOX")
    http_timeout_seconds: float = Field(default=30.0, alias="HTTP_MCP_TIMEOUT")

    # Credentials & Impersonation
    secops_sa_path: Optional[str] = Field(default=None, alias="SECOPS_SA_PATH")
    google_application_credentials: Optional[str] = Field(
        default_factory=lambda: _discover_local_adc(), alias="GOOGLE_APPLICATION_CREDENTIALS"
    )
    secops_impersonate_service_account: Optional[str] = Field(default=None, alias="SECOPS_IMPERSONATE_SERVICE_ACCOUNT")

    def __init__(self, **values):
        kw_zero_secret = self.parse_bool_env(
            values.get("ax_zero_secret_sandbox", values.get("AX_ZERO_SECRET_SANDBOX"))
        )
        env_zero_secret = is_ax_zero_secret_sandbox()
        if kw_zero_secret or env_zero_secret:
            # Verify sandbox environment BEFORE loading .env files or querying AX_METADATA_URL,
            # and disable untrusted .env file ingestion inside zero-secret sandboxes.
            if env_zero_secret:
                verify_zero_secret_sandbox()
            values["_env_file"] = None
        super().__init__(**values)
        self.bootstrap_environment()

    @model_validator(mode="after")
    def resolve_tool_enablement(self) -> "AgentSettings":
        """Auto-detects AX Workspace MCP endpoints and enforces zero-secret field invariants."""
        if self.ax_zero_secret_sandbox:
            leaked_fields = [
                field_label
                for field_label, field_val in (
                    ("VT_APIKEY", self.vt_apikey),
                    ("SOAR_APP_KEY", self.soar_app_key),
                    ("SECOPS_SA_PATH", self.secops_sa_path),
                    ("GOOGLE_API_KEY", self.google_api_key),
                    ("GOOGLE_APPLICATION_CREDENTIALS", self.google_application_credentials),
                )
                if _is_configured(field_val)
            ]
            if leaked_fields:
                joined = ", ".join(f"settings:{name}" for name in leaked_fields)
                raise ValueError(
                    "Zero-secret sandbox violation (AX_ZERO_SECRET_SANDBOX=true): "
                    f"secret fields must not be populated ({joined})."
                )
            if _is_configured(self.mcp_gateway_auth_header) and (
                self.mcp_gateway_auth_header.strip() != DEFAULT_GATEWAY_AUTH_PLACEHOLDER
            ):
                raise ValueError(
                    "Zero-secret sandbox violation (AX_ZERO_SECRET_SANDBOX=true): "
                    "MCP_GATEWAY_AUTH_HEADER must equal the non-secret egress placeholder."
                )

        ax_endpoints = discover_ax_workspace_mcp_endpoints()
        if not _is_configured(self.secops_mcp_url) and "secops" in ax_endpoints:
            self.secops_mcp_url = ax_endpoints["secops"]
        if not _is_configured(self.scc_mcp_url) and "scc" in ax_endpoints:
            self.scc_mcp_url = ax_endpoints["scc"]
        if not _is_configured(self.gti_mcp_url) and "gti" in ax_endpoints:
            self.gti_mcp_url = ax_endpoints["gti"]
        if not _is_configured(self.secops_soar_mcp_url) and "secops_soar" in ax_endpoints:
            self.secops_soar_mcp_url = ax_endpoints["secops_soar"]

        if self.ax_zero_secret_sandbox and not _is_configured(self.mcp_gateway_auth_header):
            self.mcp_gateway_auth_header = DEFAULT_GATEWAY_AUTH_PLACEHOLDER

        if self.load_gti_mcp is None:
            self.load_gti_mcp = _is_configured(self.gti_mcp_url) or _is_configured(self.vt_apikey)

        if self.load_secops_soar_mcp is None:
            self.load_secops_soar_mcp = _is_configured(self.secops_soar_mcp_url) or (
                _is_configured(self.soar_url) and _is_configured(self.soar_app_key)
            )

        if self.load_secops_mcp is None:
            self.load_secops_mcp = _is_configured(self.secops_mcp_url) or (
                _is_configured(self.chronicle_project_id) and _is_configured(self.chronicle_customer_id)
            )

        if self.load_scc_mcp is None:
            self.load_scc_mcp = _is_configured(self.scc_mcp_url)

        return self

    def bootstrap_environment(self) -> None:
        """Configures environment variables for Google Cloud authentication and Cloudtop compatibility."""
        if self.ax_zero_secret_sandbox:
            verify_zero_secret_sandbox()
            if "GOOGLE_API_USE_CLIENT_CERTIFICATE" not in os.environ:
                os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "false"
            if "GOOGLE_API_USE_MTLS_ENDPOINT" not in os.environ:
                os.environ["GOOGLE_API_USE_MTLS_ENDPOINT"] = "never"
            if "CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE" not in os.environ:
                os.environ["CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE"] = "false"
            target_project = self.google_cloud_project or os.environ.get("GCP_PROJECT_ID")
            if target_project and not os.environ.get("GOOGLE_CLOUD_PROJECT"):
                os.environ["GOOGLE_CLOUD_PROJECT"] = target_project
            os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE"
            return

        if self.google_application_credentials and not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.google_application_credentials
            if not os.environ.get("CLOUDSDK_CONFIG"):
                os.environ["CLOUDSDK_CONFIG"] = str(Path(self.google_application_credentials).parent)

        if "GOOGLE_API_USE_CLIENT_CERTIFICATE" not in os.environ:
            os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "false"
        if "GOOGLE_API_USE_MTLS_ENDPOINT" not in os.environ:
            os.environ["GOOGLE_API_USE_MTLS_ENDPOINT"] = "never"
        if "CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE" not in os.environ:
            os.environ["CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE"] = "false"

        if self.google_api_key and not os.environ.get("GOOGLE_API_KEY"):
            os.environ["GOOGLE_API_KEY"] = self.google_api_key

        target_project = self.google_cloud_project or os.environ.get("GCP_PROJECT_ID")
        if target_project and not os.environ.get("GOOGLE_CLOUD_PROJECT"):
            os.environ["GOOGLE_CLOUD_PROJECT"] = target_project

        if self.use_vertex_ai or (target_project and not self.google_api_key and not os.environ.get("GOOGLE_API_KEY")):
            os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE"

    # Chronicle SIEM Params
    chronicle_project_id: Optional[str] = Field(default=None, alias="CHRONICLE_PROJECT_ID")
    chronicle_customer_id: Optional[str] = Field(default=None, alias="CHRONICLE_CUSTOMER_ID")
    chronicle_region: str = Field(default="us", alias="CHRONICLE_REGION")

    # GTI & SOAR Params
    vt_apikey: Optional[str] = Field(default=None, alias="VT_APIKEY")
    soar_url: Optional[str] = Field(default=None, alias="SOAR_URL")
    soar_app_key: Optional[str] = Field(default=None, alias="SOAR_APP_KEY")

    # Runtime & Logging Settings
    minimal_logging: bool = Field(default=False, alias="MINIMAL_LOGGING")
    stdio_timeout_seconds: float = Field(default=60.0, alias="STDIO_PARAM_TIMEOUT")
    default_prompt: Optional[str] = Field(default=None, alias="DEFAULT_PROMPT")

    @field_validator(
        "load_secops_mcp", "load_scc_mcp", "load_gti_mcp", "load_secops_soar_mcp",
        mode="before"
    )
    @classmethod
    def parse_optional_bool_env(cls, value: object) -> Optional[bool]:
        if value is None:
            return None
        if isinstance(value, str):
            val_clean = value.strip().upper()
            if not val_clean:
                return None
            return val_clean in ("Y", "YES", "TRUE", "1")
        return bool(value)

    @field_validator(
        "use_vertex_ai", "minimal_logging", "ax_zero_secret_sandbox",
        mode="before"
    )
    @classmethod
    def parse_bool_env(cls, value: object) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            val_clean = value.strip().upper()
            if not val_clean:
                return False
            return val_clean in ("Y", "YES", "TRUE", "1")
        return bool(value)
