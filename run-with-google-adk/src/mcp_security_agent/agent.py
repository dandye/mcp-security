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
"""ADK v2.x Agent definition and factory for MCP Security Agent."""

import logging
import threading
from typing import Optional, Any
from mcp_security_agent.ax_workspace import is_valid_http_endpoint
from mcp_security_agent.config import AgentSettings
from mcp_security_agent.toolsets import build_mcp_toolsets
from mcp_security_agent.callbacks import bmc_trim_llm_request

logger = logging.getLogger(__name__)

SOC_AGENT_SYSTEM_PROMPT = """You are an expert Autonomous Security Operations Center (SOC) Analyst and Threat Intelligence Assistant.
Your mission is to investigate security alerts, hunt for threats in UDM logs, analyze IoCs with Google Threat Intelligence, triage Cloud Security Command Center (SCC) findings, and execute SOAR remediation playbooks.

Guidelines:
1. Always ground your investigations in factual telemetry retrieved from MCP tools.
2. Formulate clear UDM queries, correlate suspicious IP/domain/hash artifacts, and provide actionable remediation steps.
3. Structure your analysis with clear headings: Executive Summary, Investigation Findings, Artifact Analysis, and Recommended Remediation.
"""


def _build_zero_secret_llm(settings: AgentSettings) -> Any:
    """Builds an ADK Gemini model for AX zero-secret sandboxes.

    Only used when `AX_ZERO_SECRET_SANDBOX=true`. Requests go to the out-of-sandbox
    `LLM_GATEWAY_URL` carrying placeholder credentials that Agent Substrate
    `atenet-egress` replaces on the wire with a short-lived actorJwt.
    """
    from google.adk.models.google_llm import Gemini
    from google.auth.credentials import Credentials as BaseGoogleCredentials

    llm_url = (settings.llm_gateway_url or "").strip()
    if not llm_url or not is_valid_http_endpoint(llm_url):
        raise ValueError(
            "Zero-secret sandbox mode (AX_ZERO_SECRET_SANDBOX=true) requires "
            "LLM_GATEWAY_URL to point to an out-of-sandbox HTTP(S) Vertex AI gateway."
        )
    if not settings.google_cloud_project or not settings.google_cloud_project.strip():
        raise ValueError(
            "Zero-secret sandbox mode (AX_ZERO_SECRET_SANDBOX=true) requires "
            "GOOGLE_CLOUD_PROJECT (non-secret project identifier) for Vertex AI routing."
        )

    raw_header = (settings.mcp_gateway_auth_header or "Bearer ate-egress-injected").strip()
    parts = raw_header.split(None, 1)
    token = parts[1].strip() if len(parts) == 2 and parts[0].lower() == "bearer" else raw_header

    class _EgressPlaceholderCredentials(BaseGoogleCredentials):
        def __init__(self, placeholder_token: str) -> None:
            super().__init__()
            self.token = placeholder_token

        @property
        def valid(self) -> bool:
            return True

        @property
        def expired(self) -> bool:
            return False

        def refresh(self, request: Any) -> None:
            return None

    client_kwargs: dict[str, Any] = {
        "vertexai": True,
        "credentials": _EgressPlaceholderCredentials(token),
    }
    if settings.google_cloud_project:
        client_kwargs["project"] = settings.google_cloud_project.strip()
    if settings.google_cloud_location:
        client_kwargs["location"] = settings.google_cloud_location.strip()

    return Gemini(
        model=settings.google_model,
        base_url=llm_url,
        client_kwargs=client_kwargs,
    )


def _build_base_url_llm(settings: AgentSettings) -> Any:
    """Builds an ADK Gemini model that targets a custom `LLM_GATEWAY_URL` with normal ADC.

    Used outside zero-secret mode (for example, an authenticating corporate proxy in
    front of Vertex AI). Credentials are resolved by google-genai as usual.
    """
    from google.adk.models.google_llm import Gemini

    llm_url = (settings.llm_gateway_url or "").strip()
    if not is_valid_http_endpoint(llm_url):
        raise ValueError("LLM_GATEWAY_URL must be an http:// or https:// URL.")
    return Gemini(model=settings.google_model, base_url=llm_url)


def _resolve_model(settings: AgentSettings) -> Any:
    if settings.ax_zero_secret_sandbox:
        return _build_zero_secret_llm(settings)
    if settings.llm_gateway_url and settings.llm_gateway_url.strip():
        return _build_base_url_llm(settings)
    return settings.google_model


def create_security_agent(settings: Optional[AgentSettings] = None) -> Any:
    """Initializes and returns the configured SOC Security Agent.

    Args:
        settings: Optional AgentSettings instance (defaults to loading from environment).

    Returns:
        Configured LlmAgent instance.
    """
    if settings is None:
        settings = AgentSettings()

    toolsets = build_mcp_toolsets(settings)

    try:
        from google.adk.agents.llm_agent import LlmAgent
    except ImportError:
        logger.warning("google.adk.agents.llm_agent not available; returning dummy agent.")
        return None

    resolved_model: Any = _resolve_model(settings)

    agent = LlmAgent(
        name="SecurityOperationsAgent",
        model=resolved_model,
        instruction=settings.default_prompt or SOC_AGENT_SYSTEM_PROMPT,
        tools=toolsets,
        before_model_callback=bmc_trim_llm_request,
    )
    return agent


# Lazy root_agent instantiation for standard ADK CLI discovery (adk run, adk web)
_root_agent: Optional[Any] = None
_root_agent_lock = threading.Lock()


def __getattr__(name: str) -> Any:
    global _root_agent
    if name == "root_agent":
        if _root_agent is None:
            with _root_agent_lock:
                if _root_agent is None:
                    _root_agent = create_security_agent()
        return _root_agent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return ["create_security_agent", "root_agent", "SOC_AGENT_SYSTEM_PROMPT"]
