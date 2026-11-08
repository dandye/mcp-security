"""Unit tests for mcp_security_agent.config."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

# Add src directory to path
src_dir = str(Path(__file__).resolve().parents[1] / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from mcp_security_agent.config import (
    AgentSettings,
    DEFAULT_GEMINI_MODEL,
    FAST_GEMINI_MODEL,
)


def test_default_settings(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(os.environ, {}, clear=True):
        settings = AgentSettings(_env_file=None)
        assert settings.google_model == DEFAULT_GEMINI_MODEL
        assert settings.google_model == "gemini-3.1-pro-preview"
        assert settings.google_cloud_location == "global"
        assert settings.stdio_timeout_seconds == 60.0
        assert settings.minimal_logging is False
        assert settings.load_secops_mcp is False
        assert settings.load_scc_mcp is False
        assert settings.load_gti_mcp is False
        assert settings.load_secops_soar_mcp is False
        assert settings.mcp_tool_name_prefix_enabled is False
        assert settings.mcp_use_resources is True
        assert settings.mcp_tool_list_cache_ttl_seconds == 300.0
        assert settings.confirm_destructive_tools is False
        assert settings.elicitation_policy == "prompt"
        assert settings.max_tool_output_schema_bytes == 4096


def test_env_override_settings(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(
        os.environ,
        {
            "GOOGLE_MODEL": FAST_GEMINI_MODEL,
            "GOOGLE_CLOUD_LOCATION": "us-central1",
            "LOAD_SECOPS_MCP": "Y",
            "LOAD_SCC_MCP": "True",
            "SECOPS_IMPERSONATE_SERVICE_ACCOUNT": "test-sa@proj.iam.gserviceaccount.com",
            "STDIO_PARAM_TIMEOUT": "120.5",
            "MCP_TOOL_NAME_PREFIX_ENABLED": "true",
            "MCP_USE_RESOURCES": "false",
            "MCP_TOOL_LIST_CACHE_TTL_SECONDS": "0",
            "ADK_CONFIRM_DESTRUCTIVE_TOOLS": "Y",
            "ADK_ELICITATION_POLICY": "accept",
        },
        clear=True,
    ):
        settings = AgentSettings(_env_file=None)
        assert settings.google_model == "gemini-3-flash-preview"
        assert settings.google_cloud_location == "us-central1"
        assert settings.load_secops_mcp is True
        assert settings.load_scc_mcp is True
        assert settings.secops_impersonate_service_account == "test-sa@proj.iam.gserviceaccount.com"
        assert settings.stdio_timeout_seconds == 120.5
        assert settings.mcp_tool_name_prefix_enabled is True
        assert settings.mcp_use_resources is False
        assert settings.mcp_tool_list_cache_ttl_seconds is None
        assert settings.confirm_destructive_tools is True
        assert settings.elicitation_policy == "accept"


def test_tool_auto_detection_from_credentials(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(
        os.environ,
        {
            "VT_APIKEY": "valid_virustotal_api_key_12345",
            "SOAR_URL": "https://tenant.siemplify-soar.com",
            "SOAR_APP_KEY": "valid_soar_key_67890",
            "CHRONICLE_PROJECT_ID": "my-chronicle-project",
            "CHRONICLE_CUSTOMER_ID": "a1b2c3d4-e5f6-4321-abcd-ef1234567890",
        },
        clear=True,
    ):
        settings = AgentSettings(_env_file=None)
        assert settings.load_gti_mcp is True
        assert settings.load_secops_soar_mcp is True
        assert settings.load_secops_mcp is True
        assert settings.load_scc_mcp is False


def test_tool_auto_detection_from_remote_urls(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(
        os.environ,
        {
            "CHRONICLE_REMOTE_MCP_URL": "https://us-chronicle.googleapis.com/mcp",
            "GTI_MCP_URL": "http://127.0.0.1:8081/mcp",
            "SOAR_MCP_URL": "http://127.0.0.1:8082/mcp",
            "SCC_MCP_URL": "http://127.0.0.1:8083/mcp",
        },
        clear=True,
    ):
        settings = AgentSettings(_env_file=None)
        assert settings.load_secops_mcp is True
        assert settings.effective_secops_mcp_url == "https://us-chronicle.googleapis.com/mcp"
        assert settings.load_gti_mcp is True
        assert settings.load_secops_soar_mcp is True
        assert settings.soar_mcp_url == "http://127.0.0.1:8082/mcp"
        assert settings.secops_soar_mcp_url == "http://127.0.0.1:8082/mcp"
        assert settings.load_scc_mcp is True


def test_tool_auto_detection_empty_or_whitespace_values(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(
        os.environ,
        {
            "VT_APIKEY": "   ",
            "SOAR_URL": "",
            "SOAR_APP_KEY": "  ",
            "CHRONICLE_PROJECT_ID": "",
            "CHRONICLE_CUSTOMER_ID": "",
        },
        clear=True,
    ):
        settings = AgentSettings(_env_file=None)
        assert settings.load_gti_mcp is False
        assert settings.load_secops_soar_mcp is False
        assert settings.load_secops_mcp is False


def test_tool_explicit_override_overrules_credentials_and_urls(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(
        os.environ,
        {
            "VT_APIKEY": "valid_virustotal_api_key_12345",
            "GTI_MCP_URL": "http://127.0.0.1:8081/mcp",
            "LOAD_GTI_MCP": "N",
            "SOAR_URL": "https://tenant.siemplify-soar.com",
            "SOAR_APP_KEY": "valid_soar_key_67890",
            "SOAR_MCP_URL": "http://127.0.0.1:8082/mcp",
            "LOAD_SECOPS_SOAR_MCP": "False",
            "CHRONICLE_PROJECT_ID": "my-chronicle-project",
            "CHRONICLE_CUSTOMER_ID": "a1b2c3d4-e5f6-4321-abcd-ef1234567890",
            "SECOPS_MCP_URL": "http://127.0.0.1:8080/mcp",
            "LOAD_SECOPS_MCP": "0",
            "SCC_MCP_URL": "http://127.0.0.1:8083/mcp",
            "LOAD_SCC_MCP": "N",
        },
        clear=True,
    ):
        settings = AgentSettings(_env_file=None)
        assert settings.load_gti_mcp is False
        assert settings.load_secops_soar_mcp is False
        assert settings.load_secops_mcp is False
        assert settings.load_scc_mcp is False


def test_bootstrap_environment_with_api_key_preserves_gemini_api(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(
        os.environ,
        {"GOOGLE_API_KEY": "AIzaSyTestKey123", "GOOGLE_CLOUD_PROJECT": "my-gcp-proj"},
        clear=True,
    ):
        settings = AgentSettings(_env_file=None)
        assert settings.google_api_key == "AIzaSyTestKey123"
        assert os.environ.get("GOOGLE_GENAI_USE_VERTEXAI") is None
        assert os.environ.get("GOOGLE_API_KEY") == "AIzaSyTestKey123"


def test_bootstrap_environment_vertex_ai_global_default(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(os.environ, {"GOOGLE_CLOUD_PROJECT": "my-gcp-proj"}, clear=True):
        settings = AgentSettings(_env_file=None)
        assert settings.google_cloud_location == "global"
        assert os.environ.get("GOOGLE_GENAI_USE_VERTEXAI") == "TRUE"
        assert os.environ.get("GOOGLE_CLOUD_PROJECT") == "my-gcp-proj"
        assert os.environ.get("GOOGLE_CLOUD_LOCATION") == "global"


def test_env_files_precedence_order():
    from mcp_security_agent.config import _env_files

    # Local .env must come after parent .env so pydantic-settings gives it higher precedence
    assert _env_files[-1] == ".env"


def test_discover_user_identity():
    from mcp_security_agent.config import discover_user_identity

    # 1. Explicit user
    discover_user_identity.cache_clear()
    with patch.dict(os.environ, {"SECOPS_USER": "analyst_alice"}, clear=True):
        assert discover_user_identity() == "analyst_alice"

    # 2. Impersonated SA
    discover_user_identity.cache_clear()
    with patch.dict(
        os.environ,
        {"SECOPS_IMPERSONATE_SERVICE_ACCOUNT": "sa@proj.iam.gserviceaccount.com"},
        clear=True,
    ):
        assert discover_user_identity() == "sa@proj.iam.gserviceaccount.com"

    # 3. gcloud active account
    discover_user_identity.cache_clear()
    mock_res = type(
        "SubprocessResult", (), {"returncode": 0, "stdout": "gcloud_user@example.com\n"}
    )
    with (
        patch.dict(os.environ, {}, clear=True),
        patch("shutil.which", return_value="/bin/gcloud"),
        patch("subprocess.run", return_value=mock_res),
    ):
        assert discover_user_identity() == "gcloud_user@example.com"

    # 4. System user (when gcloud returns unset or not found)
    discover_user_identity.cache_clear()
    with (
        patch.dict(os.environ, {"USER": "test_dev"}, clear=True),
        patch("shutil.which", return_value=None),
        patch("google.auth.default", side_effect=Exception("no auth")),
    ):
        assert discover_user_identity() == "test_dev"

    # 5. Generic fallback
    discover_user_identity.cache_clear()
    with (
        patch.dict(os.environ, {}, clear=True),
        patch("shutil.which", return_value=None),
        patch("google.auth.default", side_effect=Exception("no auth")),
        patch("getpass.getuser", side_effect=Exception("no user")),
    ):
        assert discover_user_identity() == "secops_user"
