#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Proof of Concept: Native Model Context Protocol (MCP) in Google Antigravity SDK.

Demonstrates:
1. Native `McpStdioServer` orchestration without ReAct or custom shims.
2. Multi-server coordination across Google Threat Intelligence (GTI) and Google SecOps.
3. Schema optimization via tool allowlists (`enabled_tools`) and denylists (`disabled_tools`).
4. Declarative runtime policy enforcement (`policy.deny`, `policy.allow`).
5. Real-time streaming and tool call dispatch telemetry.
"""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
import sys
from typing import Sequence

from google.antigravity import Agent, CapabilitiesConfig, LocalAgentConfig
from google.antigravity.hooks import policy
from google.antigravity.types import McpServerConfig, McpStdioServer


def build_server_configs(
    server_mode: str,
    repo_root: Path,
    timeout_seconds: int = 30,
) -> list[McpServerConfig]:
    """Builds native Antigravity MCP server configurations.

    Args:
        server_mode: 'gti', 'secops', or 'both'.
        repo_root: Path to the mcp-security repository root.
        timeout_seconds: Timeout for MCP process initialization and tool listing.

    Returns:
        List of configured McpServerConfig objects.
    """
    servers: list[McpServerConfig] = []
    gti_dir = repo_root / "server" / "gti"
    secops_dir = repo_root / "server" / "secops"

    if server_mode in ("gti", "both"):
        gti_server = McpStdioServer(
            name="gti",
            command="uv",
            args=["--directory", str(gti_dir), "run", "gti_mcp/server.py"],
            timeout_seconds=timeout_seconds,
            # Filter to relevant threat intel tools to minimize prompt overhead
            enabled_tools=[
                "search_threats",
                "get_domain_report",
                "get_ip_address_report",
                "get_file_hash_report",
                "search_threat_actors",
            ],
        )
        servers.append(gti_server)

    if server_mode in ("secops", "both"):
        secops_server = McpStdioServer(
            name="secops",
            command="uv",
            args=["--directory", str(secops_dir), "run", "secops_mcp/server.py"],
            timeout_seconds=timeout_seconds,
            # Exclude massive feed schemas (which account for ~68% of schema payload)
            disabled_tools=[
                "create_feed",
                "update_feed",
                "run_parser",
                "list_feeds",
                "get_feed",
                "disable_feed",
                "enable_feed",
            ],
        )
        servers.append(secops_server)

    return servers


async def run_poc(
    query: str,
    server_mode: str = "both",
    model: str = "gemini-2.5-flash",
    project: str = "secops-demo-env",
    location: str = "us-central1",
    deny_tool: str | None = None,
    stream: bool = True,
) -> None:
    """Executes the Antigravity Native MCP PoC.

    Args:
        query: Query string to send to the agent.
        server_mode: Target MCP servers ('gti', 'secops', 'both').
        model: Gemini model identifier.
        project: Target GCP project ID for Vertex AI.
        location: Target GCP region for Vertex AI.
        deny_tool: Optional tool name to deny via policy hook.
        stream: Whether to stream tokens in real-time.
    """
    repo_root = Path(__file__).resolve().parent.parent
    servers = build_server_configs(server_mode, repo_root)

    print("=" * 70)
    print("Google Antigravity SDK - Native MCP Support PoC")
    print("=" * 70)
    print(f"Model:           {model}")
    print(f"Vertex Project:  {project} ({location})")
    print(f"Server Mode:     {server_mode}")
    print(f"MCP Servers:     {[s.name for s in servers]}")
    if deny_tool:
        print(f"Denied Tool:     {deny_tool} (via Policy Engine)")
    print(f"User Query:      {query}")
    print("-" * 70)

    policies: list[policy.Policy] = []
    if deny_tool:
        policies.append(policy.deny(deny_tool))

    config = LocalAgentConfig(
        model=model,
        vertex=True,
        project=project,
        location=location,
        capabilities=CapabilitiesConfig(),
        mcp_servers=servers,
        policies=policies if policies else None,
    )

    print("Starting Antigravity Agent runtime session...")
    async with Agent(config) as agent:
        print("Connected to runtime backend. Disagreeing with prompt shims; using native tools.")
        response = await agent.chat(query)

        print("\n--- Dispatched Tool Telemetry ---")
        tool_count = 0
        async for call in response.tool_calls:
            tool_count += 1
            print(f"  [ToolCall #{tool_count}] Name: {call.name} | Args: {call.args}")
        if tool_count == 0:
            print("  (No tools dispatched by the model for this turn)")

        print("\n--- Agent Response ---")
        if stream:
            async for token in response:
                sys.stdout.write(token)
                sys.stdout.flush()
            print()
        else:
            text = await response.text()
            print(text)

    print("=" * 70)
    print("PoC Session Completed Successfully.")
    print("=" * 70)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Antigravity SDK Native MCP Support PoC for mcp-security"
    )
    parser.add_argument(
        "--server",
        choices=["gti", "secops", "both"],
        default="both",
        help="MCP server suite to launch (default: both)",
    )
    parser.add_argument(
        "--query",
        default="Summarize the threat intelligence and SIEM detection tools available to you.",
        help="Query to evaluate with the agent",
    )
    parser.add_argument(
        "--model",
        default="gemini-2.5-flash",
        help="Model target (default: gemini-2.5-flash)",
    )
    parser.add_argument(
        "--project",
        default="secops-demo-env",
        help="GCP Project ID for Vertex AI (default: secops-demo-env)",
    )
    parser.add_argument(
        "--location",
        default="us-central1",
        help="GCP Location for Vertex AI (default: us-central1)",
    )
    parser.add_argument(
        "--deny-tool",
        default=None,
        help="Tool name to deny via Antigravity policy engine (e.g. get_available_log_types)",
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        help="Disable real-time token streaming",
    )

    args = parser.parse_args()

    # Ensure ADC is present
    if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        default_sa_key = Path.home() / ".config" / "gcloud" / "secops-demo-env-sa-key.json"
        if default_sa_key.exists():
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(default_sa_key)

    asyncio.run(
        run_poc(
            query=args.query,
            server_mode=args.server,
            model=args.model,
            project=args.project,
            location=args.location,
            deny_tool=args.deny_tool,
            stream=not args.no_stream,
        )
    )


if __name__ == "__main__":
    main()
