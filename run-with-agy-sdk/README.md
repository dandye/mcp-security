# Native Model Context Protocol (MCP) Support with Antigravity SDK

This directory contains a Proof of Concept (PoC) demonstrating native Model Context Protocol (MCP) integration using the Google Antigravity SDK (`google-antigravity`) with `mcp-security` tools.

## Architecture

Unlike legacy wrapper patterns that require converting MCP tools into custom ReAct agent tools or relying on extensive prompt-engineering shims, the Antigravity SDK natively supports the Model Context Protocol directly in its core agent runtime (`localharness`):

```text
+-------------------------------------------------------------------------+
|                        Antigravity Python SDK                           |
|                                                                         |
|   Agent(                                                                |
|       LocalAgentConfig(                                                 |
|           mcp_servers=[                                                 |
|               McpStdioServer(name="gti", command="uv", ...),            |
|               McpStdioServer(name="secops", command="uv", ...),         |
|           ],                                                            |
|           policies=[policy.deny("secops/delete_*")],                    |
|       )                                                                 |
|   )                                                                     |
+-------------------------------------------------------------------------+
                                    |
                        gRPC / WebSocket Session
                                    v
+-------------------------------------------------------------------------+
|                        Antigravity LocalHarness                         |
|                                                                         |
|   - Spawns and manages Stdio / Streamable HTTP MCP subprocesses         |
|   - Performs JSON-RPC handshake (`initialize`, `tools/list`)            |
|   - Formats and optimizes Gemini FunctionDeclarations                   |
|   - Enforces pre-tool execution policies before model dispatch          |
+-------------------------------------------------------------------------+
             |                                             |
   Stdio JSON-RPC (MCP)                          Stdio JSON-RPC (MCP)
             v                                             v
+--------------------------+                 +----------------------------+
|     `server/gti`         |                 |       `server/secops`      |
|  (36 FastMCP Tools)      |                 |    (68 FastMCP Tools)      |
+--------------------------+                 +----------------------------+
```

## Key Capabilities Demonstrated

1. **Native Multi-Server Orchestration**:
   - `McpStdioServer` and `McpStreamableHttpServer` configurations registered in `LocalAgentConfig(mcp_servers=[...])`.
   - Automatic namespacing: tools from `name="gti"` become `gti_<tool>` and `name="secops"` become `secops_<tool>`.
2. **Schema Optimization & Context Pruning**:
   - Fine-grained tool selection via `enabled_tools` (allowlist) and `disabled_tools` (denylist).
   - Eliminates schema bloat (e.g. removing feed ingestion tools saves ~68% of schema payload).
3. **Declarative Policy Guardrails**:
   - Native integration with Antigravity policy engine (`policy.allow`, `policy.deny`, `policy.ask_user`).
   - Pre-tool execution hooks prevent unauthorized tool execution at the runtime layer before any subprocess call.
4. **Real-time Observability & Streaming**:
   - Token streaming via `async for token in response`.
   - Tool execution introspection via `async for call in response.tool_calls`.
   - Model reasoning/thought stream inspection via `async for thought in response.thoughts`.

## Prerequisites

1. Set Google Cloud Application Default Credentials (ADC) or service account key:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS="~/.config/gcloud/secops-demo-env-sa-key.json"
   export GOOGLE_GENAI_USE_VERTEXAI="TRUE"
   ```
2. Install virtual environment with `uv`:
   ```bash
   uv venv .venv
   source .venv/bin/activate
   uv pip install google-antigravity pytest pytest-asyncio
   ```

## Running the PoC

Run the interactive PoC script:

```bash
python run-with-agy-sdk/poc_native_mcp.py --server both --query "What threat intel and SIEM tools do you have?"
```

Execute a live tool call with telemetry interception:

```bash
python run-with-agy-sdk/poc_native_mcp.py --server secops --query "Check available log types using get_available_log_types"
```

Test policy enforcement (denial):

```bash
python run-with-agy-sdk/poc_native_mcp.py --server secops --deny-tool get_available_log_types --query "Call get_available_log_types"
```

## Running Tests

```bash
pytest run-with-agy-sdk/tests/test_poc_native_mcp.py -v
```
