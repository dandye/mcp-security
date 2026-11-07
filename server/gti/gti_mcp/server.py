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
# Add lifespan support for startup/shutdown with strong typing
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass

import logging
import os
import vt

from mcp.server.mcpserver import Context, MCPServer

logging.basicConfig(level=logging.ERROR)

# If True, creates a completely fresh transport for each request
# with no session tracking or state persistence between requests.
stateless = False
if os.getenv("STATELESS") == "1":
  stateless = True


def _vt_client_factory(unused_ctx) -> vt.Client:
  api_key = os.getenv("VT_APIKEY")
  if not api_key:
    raise ValueError("VT_APIKEY environment variable is required")
  return vt.Client(api_key, trust_env=True)

vt_client_factory = _vt_client_factory


@asynccontextmanager
async def vt_client(ctx: Context) -> AsyncIterator[vt.Client]:
  """Provides a vt.Client instance for the current request."""
  client = vt_client_factory(ctx)

  try:
    yield client
  finally:
    await client.close_async()

# Create a named server and specify dependencies and discovery metadata
server = MCPServer(
    name="gti-mcp",
    title="Google Threat Intelligence MCP Server",
    version="0.2.0",
    description=(
        "MCP server for Google Threat Intelligence (GTI) and VirusTotal v3 "
        "IOC enrichment, threat actor/malware/campaign collections, sandbox "
        "behavior analysis, digital threat monitoring, and standard YARA "
        "file/payload livehunt and retrohunt rulesets."
    ),
    website_url="https://github.com/google/mcp-security",
    instructions=(
        "Use these tools to enrich indicators and pivot across Google Threat "
        "Intelligence collections. Check list_threat_profiles first when "
        "scoping organization-relevant threats, then use search_threats or "
        "get_collection_report and pivot via relationship tools "
        "(get_entities_related_to_a_collection, get_entities_related_to_a_file, "
        "get_entities_related_to_a_domain, get_entities_related_to_an_ip_address, "
        "get_entities_related_to_an_url). Ruleset and hunting tools in gti-mcp "
        "operate on standard YARA rules for binary/file payload matching, not "
        "YARA-L 2.0 Chronicle SIEM UDM event detection rules (use secops-mcp "
        "for YARA-L 2.0 SIEM rules)."
    ),
    dependencies=["vt-py"],
)

# Load tools.
from gti_mcp.tools import *


# Run the server
def main():
  transport = os.getenv("GTI_MCP_TRANSPORT", os.getenv("MCP_TRANSPORT", "stdio"))
  if transport == "streamable-http":
    server.run(transport="streamable-http", stateless_http=stateless)
  else:
    server.run(transport=transport)


if __name__ == '__main__':
  main()
