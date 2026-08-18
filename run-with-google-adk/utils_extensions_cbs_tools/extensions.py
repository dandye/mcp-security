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

from typing import List
from typing import Optional, Union, TextIO
import os
import sys
import logging

from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters, StdioConnectionParams, SseConnectionParams, StreamableHTTPConnectionParams
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset, ToolPredicate

logging.basicConfig(
    level=logging.INFO)

# google-adk >=2.x added native tools/list caching (McpToolset's
# tool_list_cache_ttl_seconds) with correct session-retry semantics, which is
# what this class used to hand-roll (and, against >=2.x, hand-roll incorrectly:
# it cached the MCP session itself, so retry_on_errors kept retrying against
# the same closed session instead of a fresh one from the session manager).
# Keeping the class as a thin wrapper preserves the tool_set_name call sites
# use for logging, without reimplementing get_tools().
def _default_tool_list_cache_ttl_seconds() -> Optional[float]:
  raw = os.environ.get("MCP_TOOL_LIST_CACHE_TTL_SECONDS", "86400").strip()
  if not raw or raw == "0":
    return None  # caching disabled, list on every get_tools() call
  return float(raw)


DEFAULT_TOOL_LIST_CACHE_TTL_SECONDS = _default_tool_list_cache_ttl_seconds()


class MCPToolSetWithSchemaAccess(McpToolset):

  def __init__(
      self,
      *,
      tool_set_name: str,
      connection_params: Union[
          StdioServerParameters,
          StdioConnectionParams,
          SseConnectionParams,
          StreamableHTTPConnectionParams,
      ],
      tool_filter: Optional[Union[ToolPredicate, List[str]]] = None,
      errlog: TextIO = sys.stderr,
  ):
    super().__init__(
        connection_params=connection_params,
        tool_filter=tool_filter,
        errlog=errlog,
        tool_list_cache_ttl_seconds=DEFAULT_TOOL_LIST_CACHE_TTL_SECONDS,
    )
    self.tool_set_name = tool_set_name
    logging.info(f"MCPToolSetWithSchemaAccess initialized with tool_set_name: '{self.tool_set_name}'")
