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
from typing import Optional

import logging
import os
import vt

from mcp.server.fastmcp import FastMCP, Context

from gti_mcp.egress import (
    FORBIDDEN_SANDBOX_SECRET_ENV_VARS,
    ZERO_SECRET_EGRESS_ENV,
    ZERO_SECRET_PLACEHOLDER_APIKEY,
    build_sanitized_repl_env,
    build_vt_ssl_context,
    is_zero_secret_egress_enabled,
    verify_zero_secret_sandbox_env,
)

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# If True, creates a completely fresh transport for each request
# with no session tracking or state persistence between requests.
stateless = False
if os.getenv("STATELESS") == "1":
  stateless = True


def _vt_client_factory(
    unused_ctx: Optional[Context] = None,
    *,
    host: Optional[str] = None,
    timeout: int = 300,
) -> vt.Client:
  if is_zero_secret_egress_enabled():
    verify_zero_secret_sandbox_env()
    api_key = ZERO_SECRET_PLACEHOLDER_APIKEY
    logger.debug(
        "Creating zero-secret vt.Client with placeholder header (%s)",
        ZERO_SECRET_PLACEHOLDER_APIKEY,
    )
  else:
    api_key = os.getenv("VT_APIKEY")
    if not api_key:
      raise ValueError("VT_APIKEY environment variable is required")

  verify_ssl = build_vt_ssl_context()
  return vt.Client(
      api_key,
      host=host,
      trust_env=True,
      timeout=timeout,
      verify_ssl=verify_ssl,
  )

vt_client_factory = _vt_client_factory


@asynccontextmanager
async def vt_client(ctx: Context) -> AsyncIterator[vt.Client]:
  """Provides a vt.Client instance for the current request."""
  client = vt_client_factory(ctx)

  try:
    yield client
  finally:
    await client.close_async()

# Create a named server and specify dependencies for deployment and development
server = FastMCP(
    "Google Threat Intelligence MCP server",
    dependencies=["vt-py"],
    stateless_http=stateless)

# Load tools.
from gti_mcp.tools import *

# Run the server
def main():
  verify_zero_secret_sandbox_env()
  server.run(transport='stdio')


if __name__ == '__main__':
  main()
