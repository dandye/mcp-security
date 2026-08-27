# MCP Security - Agent Guidelines

This repository (`google/mcp-security`) is a monorepo containing Model Context Protocol (MCP) servers and agent skills for Google Security products.

## Repository Architecture

The monorepo contains four distinct Python server packages under `server/` and agent skills under `extensions/`:

| Directory | Package Name | Description | Key Entry Point |
| :--- | :--- | :--- | :--- |
| `server/secops/` | `google-secops-mcp` | Chronicle / Google SecOps MCP Server | `secops_mcp.server:main` |
| `server/gti/` | `gti-mcp` | Google Threat Intelligence MCP Server | `gti_mcp.server:main` |
| `server/secops-soar/` | `secops-soar-mcp` | Google SecOps SOAR MCP Server | `secops_soar_mcp.server:run_main` |
| `server/scc/` | `scc-mcp` | Security Command Center MCP Server | `scc_mcp:main` |
| `extensions/google-secops/` | N/A | SecOps Skills for Gemini CLI & Antigravity | `.agent/skills/` |

---

## Version Bumping Guidelines

Whenever releasing or bumping versions for any server package, you **MUST** update all corresponding files in tandem. Do not update `pyproject.toml` without also updating `setup.py` and any associated runtime constants.

### Per-Package Version Checklist

1. **`google-secops-mcp`**:
   - `server/secops/pyproject.toml` (`project.version = "x.y.z"`)
   - `server/secops/setup.py` (`version="x.y.z"`)
   - `server/secops/secops_mcp/server.py` (`USER_AGENT = 'secops-app/x.y.z'`)

2. **`gti-mcp`**:
   - `server/gti/pyproject.toml` (`project.version = "x.y.z"`)
   - `server/gti/setup.py` (`version="x.y.z"`)

3. **`secops-soar-mcp`**:
   - `server/secops-soar/pyproject.toml` (`project.version = "x.y.z"`)
   - `server/secops-soar/setup.py` (`version="x.y.z"`)

4. **`scc-mcp`**:
   - `server/scc/pyproject.toml` (`project.version = "x.y.z"`)
   - `server/scc/setup.py` (`version="x.y.z"`)

---

## Dependency Constraints (`mcp < 2.0`)

All MCP servers in this repository are built on the `FastMCP` interface in `mcp` 1.x.
- **Rule**: All `dependencies` in `pyproject.toml` and `install_requires` in `setup.py` MUST pin `mcp` below `2.0` (e.g. `mcp[cli]>=1.26.0,<2.0` or `mcp>=1.23.0,<2.0`).
- **Reason**: FastMCP 2.x introduces breaking changes and renames `FastMCP` to `MCPServer`.

---

## Development, Testing & Verification

Each server has its own isolated Python environment managed with `uv`.

### 1. Environment Synchronization
```bash
cd server/<server-dir>
uv sync --extra test
```

### 2. Running Unit Tests
```bash
cd server/<server-dir>
uv run --extra test pytest
```

### 3. Verifying MCP Server Startup & Protocol Handshake
Before committing or claiming a server is ready, verify tool registration via an in-memory client session:
```python
import asyncio
from mcp.shared.memory import create_connected_server_and_client_session
# Import server object (e.g., from secops_mcp.server import server)

async def verify():
    async with create_connected_server_and_client_session(server._mcp_server) as client:
        tools = await client.list_tools()
        print(f"Registered {len(tools.tools)} tools")

asyncio.run(verify())
```

---

## Releases & Pull Requests

1. Verify unit tests pass in all modified server directories.
2. Ensure both `pyproject.toml` and `setup.py` reflect the bumped version.
3. Open PR with clear summary and verification details.
