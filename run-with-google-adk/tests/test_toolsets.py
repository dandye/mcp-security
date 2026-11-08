"""Unit tests for mcp_security_agent.toolsets."""

import asyncio
import os
import pickle
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from mcp.types import Tool, ToolAnnotations

# Add src directory to path
src_dir = str(Path(__file__).resolve().parents[1] / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from mcp_security_agent.config import AgentSettings
from mcp_security_agent.toolsets import (
    GcpRemoteHeaderProvider,
    McpElicitationHandler,
    PrefixedLoadMcpResourceTool,
    SecurityMcpToolset,
    build_mcp_toolsets,
    filter_non_bloat_feed_tools,
    is_destructive_mcp_tool,
)


def test_build_toolsets_none_enabled(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(os.environ, {}, clear=True):
        settings = AgentSettings(_env_file=None)
        toolsets = build_mcp_toolsets(settings)
        assert toolsets == []


def test_build_toolsets_stdio_secops_and_scc(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    captured = []

    def fake_toolset(**kwargs):
        captured.append(kwargs)
        return f"Toolset({kwargs['connection_params']})"

    with patch.dict(os.environ, {}, clear=True):
        with (
            patch(
                "google.adk.tools.mcp_tool.mcp_toolset.McpToolset",
                side_effect=fake_toolset,
            ),
            patch("google.adk.tools.mcp_tool.mcp_toolset.StdioConnectionParams") as mock_params,
        ):
            settings = AgentSettings(_env_file=None, LOAD_SECOPS_MCP="Y", LOAD_SCC_MCP="Y")
            toolsets = build_mcp_toolsets(settings)
            assert len(toolsets) == 2
            assert mock_params.call_count == 2
            assert captured[0]["use_mcp_resources"] is True
            assert captured[0]["tool_list_cache_ttl_seconds"] == 300.0
            assert captured[0]["tool_name_prefix"] is None
            assert isinstance(captured[0]["elicitation_callback"], McpElicitationHandler)


def test_build_toolsets_stdio_env_propagation_and_venv_isolation(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(
        os.environ,
        {
            "VIRTUAL_ENV": "/parent/adk/.venv",
            "PYTHONPATH": "/google/src/cloud/shadow/calendar",
        },
        clear=True,
    ):
        with (
            patch(
                "google.adk.tools.mcp_tool.mcp_toolset.McpToolset",
                side_effect=lambda **kw: f"Toolset({kw['connection_params']})",
            ),
            patch("google.adk.tools.mcp_tool.mcp_toolset.StdioConnectionParams") as mock_params,
            patch("shutil.which", return_value="/usr/bin/uv"),
        ):
            settings = AgentSettings(
                _env_file=None,
                LOAD_SECOPS_MCP="Y",
                CHRONICLE_PROJECT_ID="chronicle-tenant-project",
                GOOGLE_CLOUD_PROJECT="gcp-scc-project",
                CHRONICLE_CUSTOMER_ID="a1b2c3d4-e5f6-4321-abcd-ef1234567890",
                CHRONICLE_REGION="europe",
                SECOPS_SA_PATH="/path/to/secops_sa.json",
                SECOPS_IMPERSONATE_SERVICE_ACCOUNT="sa@chronicle.iam.gserviceaccount.com",
                VT_APIKEY="vt-key-999",
                SOAR_URL="https://soar.domain.com",
                SOAR_APP_KEY="soar-app-key-888",
            )
            toolsets = build_mcp_toolsets(settings)
            assert len(toolsets) == 3
            assert mock_params.call_count == 3
            call_kwargs = mock_params.call_args.kwargs
            server_params = call_kwargs["server_params"]
            env = server_params.env
            assert "VIRTUAL_ENV" not in env
            assert "PYTHONPATH" not in env
            assert env["CHRONICLE_PROJECT_ID"] == "chronicle-tenant-project"
            assert env["GOOGLE_CLOUD_PROJECT"] == "gcp-scc-project"
            assert env["CHRONICLE_CUSTOMER_ID"] == "a1b2c3d4-e5f6-4321-abcd-ef1234567890"
            assert env["CHRONICLE_REGION"] == "europe"
            assert env["SECOPS_SA_PATH"] == "/path/to/secops_sa.json"
            assert env["SECOPS_IMPERSONATE_SERVICE_ACCOUNT"] == "sa@chronicle.iam.gserviceaccount.com"
            assert env["VT_APIKEY"] == "vt-key-999"
            assert env["SOAR_URL"] == "https://soar.domain.com"
            assert env["SOAR_APP_KEY"] == "soar-app-key-888"
            assert env["GOOGLE_API_USE_CLIENT_CERTIFICATE"] == "false"
            assert env["GOOGLE_API_USE_MTLS_ENDPOINT"] == "never"


def test_build_toolsets_uv_fallback_to_sys_executable(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with (
        patch.dict(
            os.environ,
            {
                "VIRTUAL_ENV": "/parent/adk/.venv",
                "PYTHONPATH": "/leaked/parent/path",
            },
            clear=True,
        ),
        patch("shutil.which", return_value=None),
    ):
        with (
            patch(
                "google.adk.tools.mcp_tool.mcp_toolset.McpToolset",
                side_effect=lambda **kw: f"Toolset({kw['connection_params']})",
            ),
            patch("google.adk.tools.mcp_tool.mcp_toolset.StdioConnectionParams") as mock_params,
        ):
            settings = AgentSettings(_env_file=None, LOAD_SECOPS_MCP="Y")
            toolsets = build_mcp_toolsets(settings)
            assert len(toolsets) == 1
            call_kwargs = mock_params.call_args.kwargs
            server_params = call_kwargs["server_params"]
            assert server_params.command == sys.executable
            assert "secops_mcp/server.py" in server_params.args[0]
            assert "VIRTUAL_ENV" not in server_params.env
            assert "PYTHONPATH" in server_params.env
            assert "/leaked/parent/path" not in server_params.env["PYTHONPATH"]


def test_build_toolsets_streamable_http_all_four_servers_and_prefixes(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    from google.adk.tools.mcp_tool.mcp_toolset import StreamableHTTPConnectionParams

    with patch.dict(
        os.environ,
        {
            "CHRONICLE_REMOTE_MCP_URL": "https://us-chronicle.googleapis.com/mcp",
            "CHRONICLE_PROJECT_ID": "secops-tenant-proj",
            "SCC_MCP_URL": "https://scc-mcp.a.run.app/mcp",
            "GTI_MCP_URL": "https://www.virustotal.com/api/v3/agentspace/mcp/",
            "VT_APIKEY": "vt-secret-key",
            "SOAR_MCP_URL": "http://127.0.0.1:8082/mcp",
            "GOOGLE_CLOUD_PROJECT": "soc-agent-proj",
            "MCP_TOOL_NAME_PREFIX_ENABLED": "Y",
            "ADK_CONFIRM_DESTRUCTIVE_TOOLS": "Y",
        },
        clear=True,
    ):
        settings = AgentSettings(_env_file=None)
        toolsets = build_mcp_toolsets(settings)
        assert len(toolsets) == 4
        for ts in toolsets:
            assert isinstance(ts, SecurityMcpToolset)
            assert isinstance(ts._connection_params, StreamableHTTPConnectionParams)
            assert ts._use_mcp_resources is True
            assert ts._tool_list_cache_ttl_seconds == 300.0
            assert ts._confirm_destructive_tools is True

        prefixes = [ts.tool_name_prefix for ts in toolsets]
        assert prefixes == ["secops", "scc", "gti", "soar"]

        # Verify Chronicle OneMCP bloat feed tool filter is attached only to OneMCP toolset
        secops_ts = toolsets[0]
        assert secops_ts.tool_filter is filter_non_bloat_feed_tools
        assert filter_non_bloat_feed_tools(type("T", (), {"name": "create_feed"})()) is False
        assert filter_non_bloat_feed_tools(type("T", (), {"name": "update_feed"})()) is False
        assert filter_non_bloat_feed_tools(type("T", (), {"name": "search_security_events"})()) is True


def test_gcp_remote_header_provider_auth_otel_and_pickling():
    synthetic_token = "oauth2_access_" + "token_value_123"
    mock_creds = MagicMock()
    mock_creds.valid = False
    mock_creds.expired = True

    def refresh_side_effect(_req):
        mock_creds.valid = True
        mock_creds.expired = False
        mock_creds.token = synthetic_token

    mock_creds.refresh.side_effect = refresh_side_effect

    provider = GcpRemoteHeaderProvider(
        remote_url="https://us-chronicle.googleapis.com/mcp",
        server_slug="secops",
        auth_mode="oauth",
        quota_project="secops-quota-proj",
    )

    async def run_oauth_checks():
        with (
            patch("google.auth.default", return_value=(mock_creds, "secops-quota-proj")) as mock_default,
            patch("opentelemetry.trace.get_current_span") as mock_get_span,
            patch("opentelemetry.propagate.inject") as mock_inject,
        ):
            mock_span = MagicMock()
            mock_span.get_span_context.return_value.is_valid = True
            mock_get_span.return_value = mock_span
            mock_inject.side_effect = lambda h: h.update(
                {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
            )

            headers1 = await provider()
            headers2 = await provider()
            assert headers1["Authorization"] == f"Bearer {synthetic_token}"
            assert headers2["Authorization"] == f"Bearer {synthetic_token}"
            assert headers1["x-goog-user-project"] == "secops-quota-proj"
            assert headers1["traceparent"].startswith("00-")
            # Cached credentials reused on second call without network refresh
            mock_default.assert_called_once()
            mock_creds.refresh.assert_called_once()

    asyncio.run(run_oauth_checks())

    # Verify pickle drops live _creds and _auth_request cleanly and restores _lock
    restored = pickle.loads(pickle.dumps(provider))
    assert restored._creds is None
    assert restored._auth_request is None
    assert restored.quota_project == "secops-quota-proj"

    # Verify GTI remote header provider injects x-apikey without GCP OAuth on virustotal.com
    gti_provider = GcpRemoteHeaderProvider(
        remote_url="https://www.virustotal.com/api/v3/agentspace/mcp/",
        server_slug="gti",
        vt_apikey="vt-api-key-abc",
    )
    gti_headers = asyncio.run(gti_provider())
    assert gti_headers["x-apikey"] == "vt-api-key-abc"
    assert "Authorization" not in gti_headers
    assert gti_provider.get_headers_sync()["x-apikey"] == "vt-api-key-abc"


def test_gcp_remote_header_provider_id_token_sa_path_impersonation_and_cache():
    # 1. id_token + sa_path uses service_account.IDTokenCredentials and caches token
    sa_id_creds = MagicMock()
    sa_id_creds.valid = False
    sa_id_creds.expired = True

    def sa_refresh(_req):
        sa_id_creds.valid = True
        sa_id_creds.expired = False
        sa_id_creds.token = "oidc_sa_id_token_xyz"

    sa_id_creds.refresh.side_effect = sa_refresh

    sa_provider = GcpRemoteHeaderProvider(
        remote_url="https://scc-mcp.a.run.app/mcp",
        server_slug="scc",
        auth_mode="id_token",
        sa_path="/tmp/fake-sa.json",
    )

    async def run_sa_id_token():
        with patch(
            "google.oauth2.service_account.IDTokenCredentials.from_service_account_file",
            return_value=sa_id_creds,
        ) as mock_from_sa:
            h1 = await sa_provider()
            h2 = await sa_provider()
            assert h1["Authorization"] == "Bearer oidc_sa_id_token_xyz"
            assert h2["Authorization"] == "Bearer oidc_sa_id_token_xyz"
            mock_from_sa.assert_called_once_with(
                "/tmp/fake-sa.json",
                target_audience="https://scc-mcp.a.run.app",
            )
            sa_id_creds.refresh.assert_called_once()

    asyncio.run(run_sa_id_token())

    # 2. id_token + impersonate_service_account mints OIDC IDTokenCredentials (not OAuth access token)
    base_adc_creds = MagicMock()
    imp_target_creds = MagicMock()
    imp_id_creds = MagicMock()
    imp_id_creds.valid = False
    imp_id_creds.expired = True

    def imp_refresh(_req):
        imp_id_creds.valid = True
        imp_id_creds.expired = False
        imp_id_creds.token = "oidc_impersonated_id_token_789"

    imp_id_creds.refresh.side_effect = imp_refresh

    imp_provider = GcpRemoteHeaderProvider(
        remote_url="https://secops-mcp.a.run.app/mcp",
        server_slug="secops",
        auth_mode="id_token",
        impersonate_service_account="soc-caller@proj.iam.gserviceaccount.com",
    )

    async def run_impersonated_id_token():
        with (
            patch("google.auth.default", return_value=(base_adc_creds, "proj")),
            patch(
                "google.auth.impersonated_credentials.Credentials",
                return_value=imp_target_creds,
            ) as mock_imp_creds,
            patch(
                "google.auth.impersonated_credentials.IDTokenCredentials",
                return_value=imp_id_creds,
            ) as mock_imp_id_creds,
        ):
            h1 = await imp_provider()
            h2 = await imp_provider()
            assert h1["Authorization"] == "Bearer oidc_impersonated_id_token_789"
            assert h2["Authorization"] == "Bearer oidc_impersonated_id_token_789"
            mock_imp_creds.assert_called_once()
            mock_imp_id_creds.assert_called_once_with(
                target_credentials=imp_target_creds,
                target_audience="https://secops-mcp.a.run.app",
                include_email=True,
            )
            imp_id_creds.refresh.assert_called_once()

    asyncio.run(run_impersonated_id_token())

    # 3. Default id_token fallback to fetch_id_token caches returned JWT without re-fetching
    fallback_provider = GcpRemoteHeaderProvider(
        remote_url="https://soar-mcp.a.run.app/mcp",
        server_slug="soar",
        auth_mode="id_token",
    )

    async def run_default_id_token_fallback():
        with (
            patch(
                "google.oauth2.id_token.fetch_id_token_credentials",
                side_effect=RuntimeError("authorized_user ADC"),
            ),
            patch(
                "google.oauth2.id_token.fetch_id_token",
                return_value="oidc_fallback_token_321",
            ) as mock_fetch_id_tok,
        ):
            h1 = await fallback_provider()
            h2 = await fallback_provider()
            assert h1["Authorization"] == "Bearer oidc_fallback_token_321"
            assert h2["Authorization"] == "Bearer oidc_fallback_token_321"
            mock_fetch_id_tok.assert_called_once()

    asyncio.run(run_default_id_token_fallback())


def test_security_mcp_toolset_destructive_confirmation_and_resource_prefix():
    from google.adk.models.llm_request import LlmRequest
    from google.adk.tools.load_mcp_resource_tool import LoadMcpResourceTool
    from google.adk.tools.mcp_tool.mcp_toolset import McpToolset, StreamableHTTPConnectionParams
    from google.adk.tools.mcp_tool.mcp_tool import McpTool

    ro_raw = Tool(
        name="list_security_rules",
        description="List detection rules",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
    )
    dest_raw = Tool(
        name="delete_rule",
        description="Delete detection rule",
        inputSchema={"type": "object", "properties": {"rule_id": {"type": "string"}}},
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True),
    )
    mut_safe_raw = Tool(
        name="add_case_comment",
        description="Post comment",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False),
    )

    assert is_destructive_mcp_tool(ro_raw) is False
    assert is_destructive_mcp_tool(dest_raw) is True
    assert is_destructive_mcp_tool(mut_safe_raw) is False

    toolset = SecurityMcpToolset(
        confirm_destructive_tools=True,
        resource_tool_prefix="secops",
        connection_params=StreamableHTTPConnectionParams(url="http://127.0.0.1:8080/mcp"),
        use_mcp_resources=True,
        tool_name_prefix=None,
    )

    # Verify SecurityMcpToolset pickles cleanly
    unpickled = pickle.loads(pickle.dumps(toolset))
    assert unpickled._confirm_destructive_tools is True
    assert unpickled._resource_tool_prefix == "secops"

    ro_tool = McpTool(mcp_tool=ro_raw, mcp_session_manager=toolset._mcp_session_manager)
    dest_tool = McpTool(mcp_tool=dest_raw, mcp_session_manager=toolset._mcp_session_manager)
    resource_tool = LoadMcpResourceTool(toolset)

    async def run_check():
        with (
            patch.object(
                McpToolset,
                "get_tools",
                return_value=[ro_tool, dest_tool, resource_tool],
            ),
            patch.object(
                SecurityMcpToolset,
                "list_resources",
                return_value=["secops://udm/field-reference"],
            ),
        ):
            tools = await toolset.get_tools()
            assert tools[0]._require_confirmation is False
            assert tools[1]._require_confirmation is True
            assert isinstance(tools[2], PrefixedLoadMcpResourceTool)
            assert tools[2].name == "secops_load_mcp_resource"

            llm_req = LlmRequest()
            await tools[2].process_llm_request(tool_context=MagicMock(), llm_request=llm_req)
            joined_dyn = "\n".join(llm_req._dynamic_instructions)
            assert "secops_load_mcp_resource" in joined_dyn
            assert "`load_mcp_resource`" not in joined_dyn

            run_res = await tools[2].run_async(
                args={"resource_names": ["secops://udm/field-reference"]},
                tool_context=MagicMock(),
            )
            assert "secops_load_mcp_resource" in run_res["status"]

    asyncio.run(run_check())


def test_security_mcp_toolset_prefix_produces_single_underscore():
    from google.adk.tools.mcp_tool.mcp_toolset import McpToolset, StreamableHTTPConnectionParams
    from google.adk.tools.mcp_tool.mcp_tool import McpTool

    raw_tool = Tool(
        name="search_threats",
        description="Search GTI threats",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    toolset = SecurityMcpToolset(
        confirm_destructive_tools=False,
        connection_params=StreamableHTTPConnectionParams(url="http://127.0.0.1:8081/mcp"),
        tool_name_prefix="gti",
        use_mcp_resources=False,
    )
    wrapped = McpTool(mcp_tool=raw_tool, mcp_session_manager=toolset._mcp_session_manager)

    async def run_prefix_check():
        with patch.object(McpToolset, "get_tools", return_value=[wrapped]):
            prefixed = await toolset.get_tools_with_prefix()
            assert len(prefixed) == 1
            assert prefixed[0].name == "gti_search_threats"

    asyncio.run(run_prefix_check())


def test_mcp_elicitation_handler_policies():
    params = type("ElicitParams", (), {"message": "Delete rule ru_a1b2c3d4-e5f6-4321-abcd-ef1234567890?"})()

    async def run_checks():
        accept_res = await McpElicitationHandler(policy="accept", server_name="secops")(None, params)
        assert accept_res.action == "accept"
        assert accept_res.content == {"confirm": True}

        decline_res = await McpElicitationHandler(policy="decline", server_name="secops")(None, params)
        assert decline_res.action == "decline"

        cancel_res = await McpElicitationHandler(policy="cancel", server_name="secops")(None, params)
        assert cancel_res.action == "cancel"

        fake_non_tty = MagicMock()
        fake_non_tty.isatty.return_value = False
        with patch.object(sys, "stdin", fake_non_tty):
            non_tty_res = await McpElicitationHandler(policy="prompt", server_name="secops")(None, params)
            assert non_tty_res.action == "decline"

        fake_tty = MagicMock()
        fake_tty.isatty.return_value = True
        with patch.object(sys, "stdin", fake_tty), patch("builtins.input", return_value="yes"):
            tty_yes = await McpElicitationHandler(policy="prompt", server_name="secops")(None, params)
            assert tty_yes.action == "accept"
            assert tty_yes.content == {"confirm": True}

        with patch.object(sys, "stdin", fake_tty), patch("builtins.input", return_value="no"):
            tty_no = await McpElicitationHandler(policy="prompt", server_name="secops")(None, params)
            assert tty_no.action == "decline"

    asyncio.run(run_checks())
