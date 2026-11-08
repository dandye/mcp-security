"""Unit tests for mcp_security_agent.cli."""

import os
from pathlib import Path
import re
import sys
import unicodedata
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

# Add src directory to path
src_dir = str(Path(__file__).resolve().parents[1] / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from mcp_security_agent.cli import app

runner = CliRunner()


def _assert_zero_emojis(text: str, *, strict_ascii: bool = False) -> None:
    for ch in text:
        code = ord(ch)
        if strict_ascii:
            assert code < 128, f"Found non-ASCII character {ch!r} (U+{code:04X}) in CLI output"
        assert not (
            code > 0x1F000
            or (0x2600 <= code <= 0x27BF)
            or (
                code > 0x2000
                and not (0x2500 <= code <= 0x257F)
                and unicodedata.category(ch) == "So"
            )
        ), f"Found forbidden emoji/symbol {ch!r} (U+{code:04X}) in CLI output"


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Autonomous Security Operations Center" in result.stdout
    _assert_zero_emojis(result.output)


def test_cli_info(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(
        os.environ,
        {
            "GOOGLE_CLOUD_PROJECT": "soc-info-proj",
            "CHRONICLE_REMOTE_MCP_URL": "https://us-chronicle.googleapis.com/mcp",
            "LOAD_SCC_MCP": "Y",
            "MCP_TOOL_NAME_PREFIX_ENABLED": "true",
            "ADK_ELICITATION_POLICY": "decline",
        },
        clear=True,
    ):
        result = runner.invoke(app, ["info"])
        assert result.exit_code == 0
        assert "MCP Security Agent v0.3.0" in result.stdout
        assert "Model:" in result.stdout
        assert "Location:" in result.stdout
        assert "Project (project_id):" in result.stdout
        assert "soc-info-proj" in result.stdout
        assert "ADC:" in result.stdout
        assert "tool_name_prefix_enabled" in result.stdout
        assert "use_mcp_resources" in result.stdout
        assert "elicitation_policy" in result.stdout
        assert "decline" in result.stdout
        assert "SecOps SIEM MCP: Enabled (streamable-http)" in result.stdout
        assert "SCC MCP: Enabled (stdio)" in result.stdout
        assert "GTI MCP: Disabled (disabled)" in result.stdout
        _assert_zero_emojis(result.output)


def test_cli_chat_query():
    async def fake_single_turn(**kwargs):
        assert kwargs["query"] == "list 1 page of rules"
        return 0

    with patch("mcp_security_agent.cli.run_single_turn_query", side_effect=fake_single_turn):
        result = runner.invoke(app, ["chat", "list 1 page of rules"])
        assert result.exit_code == 0
        _assert_zero_emojis(result.output)


def test_cli_chat_tool_flags():
    import mcp_security_agent.agent as agent_mod

    async def fake_single_turn(**kwargs):
        return 0

    with patch.dict(os.environ, {}, clear=True):
        with patch("mcp_security_agent.cli.run_single_turn_query", side_effect=fake_single_turn):
            result = runner.invoke(app, ["chat", "--secops", "--no-scc", "test query"])
            assert result.exit_code == 0
            assert "Active MCP Toolsets:" in result.stdout
            assert "SecOps SIEM" in result.stdout
            assert len(agent_mod.root_agent.tools) == 1
            assert sys.modules["mcp_security_agent"].root_agent == agent_mod.root_agent

            result_no_secops = runner.invoke(
                app, ["chat", "--no-secops", "--no-scc", "test query"]
            )
            assert result_no_secops.exit_code == 0
            assert "No MCP tools are currently enabled" in result_no_secops.stdout
            assert len(agent_mod.root_agent.tools) == 0


def test_cli_chat_config_and_confirmation_flags():
    import mcp_security_agent.agent as agent_mod

    captured_kwargs = {}

    async def fake_single_turn(**kwargs):
        captured_kwargs.update(kwargs)
        return 0

    with patch.dict(os.environ, {}, clear=True):
        with patch("mcp_security_agent.cli.run_single_turn_query", side_effect=fake_single_turn):
            result = runner.invoke(
                app,
                [
                    "chat",
                    "--vertex",
                    "--model",
                    "gemini-3.1-pro-preview",
                    "--location",
                    "global",
                    "--project",
                    "test-project-123",
                    "--customer-id",
                    "a1b2c3d4-e5f6-4321-abcd-ef1234567890",
                    "--confirm-destructive",
                    "--prefix-tools",
                    "--session-id",
                    "sess-custom-42",
                    "--secops",
                    "test query",
                ],
            )
            assert result.exit_code == 0
            assert captured_kwargs["session_id"] == "sess-custom-42"
            assert os.environ["GOOGLE_GENAI_USE_VERTEXAI"] == "TRUE"
            assert os.environ["GOOGLE_MODEL"] == "gemini-3.1-pro-preview"
            assert os.environ["GOOGLE_CLOUD_LOCATION"] == "global"
            assert os.environ["GOOGLE_CLOUD_PROJECT"] == "test-project-123"
            assert os.environ["CHRONICLE_PROJECT_ID"] == "test-project-123"
            assert os.environ["CHRONICLE_CUSTOMER_ID"] == "a1b2c3d4-e5f6-4321-abcd-ef1234567890"
            assert os.environ["ADK_CONFIRM_DESTRUCTIVE_TOOLS"] == "Y"
            assert os.environ["MCP_TOOL_NAME_PREFIX_ENABLED"] == "Y"
            assert agent_mod.root_agent.model == "gemini-3.1-pro-preview"
            assert agent_mod.root_agent.tools[0].tool_name_prefix == "secops"
            assert agent_mod.root_agent.tools[0]._confirm_destructive_tools is True


def test_cli_single_turn_confirm_destructive_interactive_approve_and_reject(monkeypatch):
    from google.adk.events import Event
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)

    def make_bundle():
        session_svc = InMemorySessionService()
        recorded_calls = []

        class FakeCliRunner:
            async def run_async(self, **kwargs):
                recorded_calls.append(kwargs)
                sess = await session_svc.get_session(
                    app_name="mcp_security_agent",
                    user_id=kwargs["user_id"],
                    session_id=kwargs["session_id"],
                )
                await session_svc.append_event(
                    sess,
                    Event(author="user", invocation_id="inv-cli-1", content=kwargs["new_message"]),
                )
                parts = kwargs["new_message"].parts or []
                fr = parts[0].function_response if parts else None
                if fr is None:
                    confirm_fc = types.FunctionCall(
                        id="cli-confirm-1",
                        name="adk_request_confirmation",
                        args={
                            "originalFunctionCall": {
                                "id": "orig-1",
                                "name": "delete_security_rule",
                                "args": {"rule_id": "ru_a1b2c3d4-e5f6-4321-abcd-ef1234567890"},
                            }
                        },
                    )
                    ev = Event(
                        author="SecurityOperationsAgent",
                        invocation_id="inv-cli-1",
                        long_running_tool_ids={"cli-confirm-1"},
                        content=types.Content(
                            role="model",
                            parts=[types.Part(function_call=confirm_fc)],
                        ),
                    )
                    await session_svc.append_event(sess, ev)
                    yield ev
                else:
                    outcome = (
                        "Confirmed and deleted rule."
                        if fr.response.get("confirmed")
                        else "Deletion rejected by operator."
                    )
                    ev = Event(
                        author="SecurityOperationsAgent",
                        invocation_id=kwargs.get("invocation_id") or "inv-cli-1",
                        content=types.Content(
                            role="model",
                            parts=[types.Part(text=outcome)],
                        ),
                    )
                    await session_svc.append_event(sess, ev)
                    yield ev

            async def close(self):
                return None

        return FakeCliRunner(), session_svc, recorded_calls

    # 1. Interactive approval ("y\n") resumes in the same CLI invocation
    fake_runner_yes, svc_yes, calls_yes = make_bundle()
    with (
        patch.dict(os.environ, {}, clear=True),
        patch(
            "mcp_security_agent.cli._create_cli_runner_bundle",
            return_value=(fake_runner_yes, svc_yes, "mcp_security_agent", "test_user"),
        ),
    ):
        res_yes = runner.invoke(
            app,
            ["chat", "--confirm-destructive", "Delete rule ru_a1b2c3d4-e5f6-4321-abcd-ef1234567890"],
            input="y\n",
        )
        assert res_yes.exit_code == 0
        assert "[Confirm] Approve execution of delete_security_rule? [y/N]:" in res_yes.output
        assert "Confirmed and deleted rule." in res_yes.output
        assert len(calls_yes) == 2
        fr_yes = calls_yes[1]["new_message"].parts[0].function_response
        assert fr_yes.id == "cli-confirm-1"
        assert fr_yes.name == "adk_request_confirmation"
        assert fr_yes.response == {"confirmed": True}
        _assert_zero_emojis(res_yes.output, strict_ascii=True)

    # 2. Interactive rejection ("n\n") resumes with confirmed=False in the same invocation
    fake_runner_no, svc_no, calls_no = make_bundle()
    with (
        patch.dict(os.environ, {}, clear=True),
        patch(
            "mcp_security_agent.cli._create_cli_runner_bundle",
            return_value=(fake_runner_no, svc_no, "mcp_security_agent", "test_user"),
        ),
    ):
        res_no = runner.invoke(
            app,
            ["chat", "--confirm-destructive", "Delete rule ru_a1b2c3d4-e5f6-4321-abcd-ef1234567890"],
            input="n\n",
        )
        assert res_no.exit_code == 0
        assert "[Confirm] Approve execution of delete_security_rule? [y/N]:" in res_no.output
        assert "Deletion rejected by operator." in res_no.output
        assert len(calls_no) == 2
        fr_no = calls_no[1]["new_message"].parts[0].function_response
        assert fr_no.id == "cli-confirm-1"
        assert fr_no.name == "adk_request_confirmation"
        assert fr_no.response == {"confirmed": False}
        _assert_zero_emojis(res_no.output, strict_ascii=True)


def test_cli_single_turn_non_interactive_pause_and_session_id_resume(monkeypatch):
    from google.adk.events import Event
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)

    shared_session_svc = InMemorySessionService()
    recorded_calls = []

    class PersistentSessionRunner:
        async def run_async(self, **kwargs):
            recorded_calls.append(kwargs)
            sess = await shared_session_svc.get_session(
                app_name="mcp_security_agent",
                user_id=kwargs["user_id"],
                session_id=kwargs["session_id"],
            )
            await shared_session_svc.append_event(
                sess,
                Event(author="user", invocation_id="inv-resume-1", content=kwargs["new_message"]),
            )
            parts = kwargs["new_message"].parts or []
            fr = parts[0].function_response if parts else None
            if fr is None:
                confirm_fc = types.FunctionCall(
                    id="cli-pause-1",
                    name="adk_request_confirmation",
                    args={
                        "originalFunctionCall": {
                            "id": "orig-pause-1",
                            "name": "close_case",
                            "args": {"case_id": "42"},
                        }
                    },
                )
                ev = Event(
                    author="SecurityOperationsAgent",
                    invocation_id="inv-resume-1",
                    long_running_tool_ids={"cli-pause-1"},
                    content=types.Content(
                        role="model",
                        parts=[types.Part(function_call=confirm_fc)],
                    ),
                )
                await shared_session_svc.append_event(sess, ev)
                yield ev
            else:
                ev = Event(
                    author="SecurityOperationsAgent",
                    invocation_id=kwargs.get("invocation_id") or "inv-resume-1",
                    content=types.Content(
                        role="model",
                        parts=[types.Part(text="Case 42 closed after resume.")],
                    ),
                )
                await shared_session_svc.append_event(sess, ev)
                yield ev

        async def close(self):
            return None

    with (
        patch.dict(os.environ, {}, clear=True),
        patch(
            "mcp_security_agent.cli._create_cli_runner_bundle",
            side_effect=lambda _agent, _src: (
                PersistentSessionRunner(),
                shared_session_svc,
                "mcp_security_agent",
                "test_user",
            ),
        ),
    ):
        paused_res = runner.invoke(
            app,
            ["chat", "--confirm-destructive", "Close case 42"],
        )
        assert paused_res.exit_code == 2
        assert "[Paused] Destructive tool 'close_case' requires operator confirmation." in paused_res.output
        assert "--session-id " in paused_res.output
        _assert_zero_emojis(paused_res.output, strict_ascii=True)

        match = re.search(r"--session-id\s+([^\s]+)", paused_res.output)
        assert match is not None
        paused_session_id = match.group(1)

        resumed_res = runner.invoke(
            app,
            ["chat", "--session-id", paused_session_id, "yes"],
        )
        assert resumed_res.exit_code == 0
        assert "Case 42 closed after resume." in resumed_res.output
        assert len(recorded_calls) == 2
        fr = recorded_calls[1]["new_message"].parts[0].function_response
        assert fr.id == "cli-pause-1"
        assert fr.name == "adk_request_confirmation"
        assert fr.response == {"confirmed": True}
        _assert_zero_emojis(resumed_res.output, strict_ascii=True)


def test_cli_serve_command():
    mock_uvicorn = MagicMock()
    with patch.dict(os.environ, {"PORT": "9090"}, clear=True):
        with patch.dict("sys.modules", {"uvicorn": mock_uvicorn}):
            result = runner.invoke(app, ["serve"])
            assert result.exit_code == 0
            assert "Starting MCP Security Agent server on 0.0.0.0:9090" in result.stdout
            mock_uvicorn.run.assert_called_once()
            _, kwargs = mock_uvicorn.run.call_args
            assert kwargs["port"] == 9090

    mock_uvicorn.reset_mock()
    with patch.dict(os.environ, {}, clear=True):
        with patch.dict("sys.modules", {"uvicorn": mock_uvicorn}):
            result = runner.invoke(app, ["serve", "--port", "7070", "--reload"])
            assert result.exit_code == 0
            assert "Starting MCP Security Agent server on 0.0.0.0:7070" in result.stdout
            mock_uvicorn.run.assert_called_once()
            args, kwargs = mock_uvicorn.run.call_args
            assert args[0] == "mcp_security_agent.server.app:create_app"
            assert kwargs["factory"] is True
            assert kwargs["port"] == 7070
            assert kwargs["reload"] is True
