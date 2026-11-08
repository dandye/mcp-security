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
import mcp
import pytest
from unittest import mock
from mcp.server.mcpserver import Context
from gti_mcp.tools import files

@pytest.mark.asyncio
async def test_get_file_behavior_summary_api_error_handled():
    """Test get_file_behavior_summary returns error dict on API error (e.g. 404)."""
    mock_ctx = mock.MagicMock(spec=Context)

    mock_response = mock.MagicMock()
    mock_response.status = 404
    async def json_async():
        return {"error": {"message": "File not found"}}
    mock_response.json_async = json_async

    mock_client_instance = mock.MagicMock()
    mock_client_instance.get_async = mock.AsyncMock(return_value=mock_response)

    mock_vt_client = mock.MagicMock()
    mock_vt_client.__aenter__ = mock.AsyncMock(return_value=mock_client_instance)
    mock_vt_client.__aexit__ = mock.AsyncMock(return_value=None)

    with mock.patch("gti_mcp.tools.files.vt_client", return_value=mock_vt_client):
        result = await files.get_file_behavior_summary(hash="non_existent_hash", ctx=mock_ctx)
        assert isinstance(result, mcp.types.CallToolResult)
        assert result.is_error is True
        assert isinstance(result.structured_content, dict)
        assert "error" in result.structured_content
        assert "VirusTotal API Error" in result.structured_content["error"]
        assert "File not found" in result.structured_content["error"]

@pytest.mark.asyncio
async def test_get_file_behavior_summary_unexpected_format_handled():
    """Test get_file_behavior_summary returns CallToolResult(is_error=True) on unexpected response format."""
    mock_ctx = mock.MagicMock(spec=Context)

    mock_response = mock.MagicMock()
    async def json_async():
        return {"something": "unexpected"}
    mock_response.json_async = json_async

    mock_client_instance = mock.MagicMock()
    mock_client_instance.get_async = mock.AsyncMock(return_value=mock_response)

    mock_vt_client = mock.MagicMock()
    mock_vt_client.__aenter__ = mock.AsyncMock(return_value=mock_client_instance)
    mock_vt_client.__aexit__ = mock.AsyncMock(return_value=None)

    with mock.patch("gti_mcp.tools.files.vt_client", return_value=mock_vt_client):
        result = await files.get_file_behavior_summary(hash="some_hash", ctx=mock_ctx)
        assert isinstance(result, mcp.types.CallToolResult)
        assert result.is_error is True
        assert isinstance(result.structured_content, dict)
        assert "error" in result.structured_content
        assert "Unexpected response format" in result.structured_content["error"]


@pytest.mark.asyncio
async def test_get_entities_related_to_a_file_invalid_relationship_returns_error_dict():
    """Invalid relationship_name returns CallToolResult(is_error=True) via MCPServer call_tool."""
    from gti_mcp.server import server

    result = await server.call_tool(
        "get_entities_related_to_a_file",
        {
            "hash": "abc",
            "relationship_name": "not_a_real_relationship",
            "descriptors_only": True,
        },
    )
    assert isinstance(result, mcp.types.CallToolResult)
    assert result.is_error is True
    structured = result.structured_content
    assert isinstance(structured, dict)
    payload = structured.get("result", structured)
    assert isinstance(payload, dict)
    assert "error" in payload
    assert "not_a_real_relationship" in payload["error"]
