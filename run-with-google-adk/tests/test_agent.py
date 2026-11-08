"""Unit tests for mcp_security_agent.agent."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add src directory to path
src_dir = str(Path(__file__).resolve().parents[1] / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from mcp_security_agent.agent import SOC_AGENT_SYSTEM_PROMPT, create_security_agent
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
