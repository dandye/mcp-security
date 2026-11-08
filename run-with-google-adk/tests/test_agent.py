"""Unit tests for mcp_security_agent.agent."""

import functools
import os
import pickle
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from google.genai import types

# Add src directory to path
src_dir = str(Path(__file__).resolve().parents[1] / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from mcp_security_agent.agent import SOC_AGENT_SYSTEM_PROMPT, create_security_agent
from mcp_security_agent.callbacks import bmc_trim_llm_request
from mcp_security_agent.config import AgentSettings


def test_create_security_agent(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    with patch.dict(os.environ, {}, clear=True):
        settings = AgentSettings(_env_file=None)
        mock_agent_instance = MagicMock()

        with patch(
            "google.adk.agents.llm_agent.LlmAgent", return_value=mock_agent_instance
        ) as mock_llm_agent_cls:
            agent = create_security_agent(settings)
            assert agent == mock_agent_instance
            mock_llm_agent_cls.assert_called_once()
            _, kwargs = mock_llm_agent_cls.call_args
            assert kwargs["name"] == "SecurityOperationsAgent"
            assert kwargs["model"] == "gemini-3.1-pro-preview"
            assert kwargs["instruction"] == SOC_AGENT_SYSTEM_PROMPT
            assert isinstance(kwargs["before_model_callback"], functools.partial)
            assert kwargs["before_model_callback"].func is bmc_trim_llm_request
            assert kwargs["before_model_callback"].keywords == {
                "max_output_schema_bytes": 4096
            }


def test_create_security_agent_honors_settings_max_tool_output_schema_bytes_without_env(
    monkeypatch,
):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    monkeypatch.delenv("ADK_MAX_TOOL_OUTPUT_SCHEMA_BYTES", raising=False)

    with patch.dict(os.environ, {}, clear=True):
        settings = AgentSettings(_env_file=None, max_tool_output_schema_bytes=256)
        os.environ.pop("ADK_MAX_TOOL_OUTPUT_SCHEMA_BYTES", None)
        assert "ADK_MAX_TOOL_OUTPUT_SCHEMA_BYTES" not in os.environ

        agent = create_security_agent(settings)
        assert agent is not None
        assert isinstance(agent.before_model_callback, functools.partial)

        restored_agent = pickle.loads(pickle.dumps(agent))
        try:
            import cloudpickle  # type: ignore[import-not-found]

            restored_agent = cloudpickle.loads(cloudpickle.dumps(restored_agent))
        except ImportError:
            pass

        small_decl = types.FunctionDeclaration(
            name="small_tool",
            description="Compact output schema",
            parameters_json_schema={"type": "object", "properties": {}},
            response_json_schema={"type": "object", "properties": {"ok": {"type": "boolean"}}},
        )
        medium_decl = types.FunctionDeclaration(
            name="medium_tool",
            description="Schema larger than 256 B but smaller than default 4096 B",
            parameters_json_schema={"type": "object", "properties": {}},
            response_json_schema={
                "type": "object",
                "properties": {
                    f"col_{idx}": {"type": "string", "description": "x" * 40}
                    for idx in range(8)
                },
            },
        )
        llm_request = type(
            "FakeLlmRequest",
            (),
            {
                "config": types.GenerateContentConfig(
                    tools=[types.Tool(function_declarations=[small_decl, medium_decl])]
                )
            },
        )()
        ctx = type("FakeCtx", (), {"state": {}})()

        restored_agent.before_model_callback(ctx, llm_request)
        assert small_decl.response_json_schema is not None
        assert medium_decl.response_json_schema is None
