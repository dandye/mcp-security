# Development Guide

This guide covers extending, testing, packaging, and documenting the MCP `2026-07-28` (`mcp>=2.3.0`) servers and `google-adk>=2.13.0` agent in `google/mcp-security`.

## Repository Structure

```text
mcp-security/
|-- .github/workflows/          # CI unit/contract suites, docs deploy, PyPI publish
|-- docs/                       # Sphinx + MyST Markdown documentation
|   |-- mcp_v2_capabilities.md  # MCP 2026-07-28 protocol & security reference
|   `-- servers/                # Per-server tool, resource, and prompt guides
|-- run-with-google-adk/        # Autonomous SOC Agent (mcp-security-agent 0.3.0)
|   |-- src/mcp_security_agent/ # ADK v2.13 agent, toolsets, callbacks, CLI, FastAPI
|   `-- tests/                  # Hermetic unit test suite
|-- server/
|   |-- secops/                 # google-secops-mcp (0.9.0) + server.json
|   |-- gti/                    # gti-mcp (0.2.0) + server.json
|   |-- secops-soar/            # secops-soar-mcp (0.3.0) + server.json
|   `-- scc/                    # scc-mcp (0.3.0) + server.json
`-- tests/                      # Cross-server MCP 2026-07-28 contract test suites
```

## MCP Server Architecture (`mcp>=2.3.0`)

Each server instantiates `mcp.server.mcpserver.MCPServer` and exposes:

1. **CLI and Transport Entrypoint**: Supports `--transport {stdio,streamable-http}`, `--host`, `--port`, `--stateless-http`, `/healthz`, `/readyz`, `SEP-2549` `CacheHint`, and `OpenTelemetryMiddleware`.
2. **Annotated Tools**: Every `@server.tool(...)` declares a `title`, `ToolAnnotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), typed `structuredContent`, and raises `ToolError` (returning `is_error=True`) on operational failures.
3. **Resources and Prompts**: Registers `DEFAULT_RESOURCE_SECURITY` resources (`secops://`, `gti://`, `soar://`, `scc://`), `ResourceLink` summaries, and parameterized `@server.prompt()` workflows.
4. **Phase 5 Security Controls**: Supports stateless MRTR `ctx.elicit(...)` via `AESGCMRequestStateCodec` (`MCP_ELICIT_DESTRUCTIVE`), `ctx.report_progress(...)`, OAuth 2.1 Resource Server JWT/JWKS validation (`MCP_OAUTH_ISSUER_URL`), and dark-mode MCP Apps (`ui://`).
5. **Official MCP Registry Manifest**: Ships a synchronized `server.json` validated against `https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`.

## Adding a New Tool

1. Implement the tool in the appropriate `tools/` submodule using explicit `Optional[T] = None` annotations for nullable defaults and lazy `%s` formatting in `logger.*(...)` calls.
2. Provide `title` and `ToolAnnotations(...)` on `@server.tool(...)` so client confirmation gates (`destructiveHint`) remain accurate.
3. Re-export the function explicitly in `tools/__init__.py` (`__all__`, never wildcard `import *`).
4. Add unit tests under `server/<pkg>/tests/` and document the tool in `server/<pkg>/README.md` and `docs/servers/<pkg>_mcp.md`.

```python
import logging
from typing import Any, Optional
from mcp.types import ToolAnnotations
from gti_mcp.server import server

logger = logging.getLogger("gti-mcp")


@server.tool(
    title="Get Indicator Summary",
    annotations=ToolAnnotations(
        title="Get Indicator Summary",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def get_indicator_summary(
    indicator: str,
    comment_limit: Optional[int] = None,
) -> dict[str, Any]:
    """Fetch a concise reputation summary for an indicator."""
    logger.info("Fetching summary for indicator: %s", indicator)
    return {"indicator": indicator, "limit": comment_limit}
```

## Version Synchronization (`pyproject.toml`, `setup.py`, and `server.json`)

When bumping a server package version, update all metadata files in lockstep:

- `server/<pkg>/pyproject.toml` (`[project].version`)
- `server/<pkg>/setup.py` (`version=...`, where present)
- `server/<pkg>/server.json` (`version` and `packages[0].version`)
- Runtime `MCPServer(..., version=...)`

Both `tests/test_mcp_v2_registry_and_packaging.py` (in `.github/workflows/ci-mcp-tests.yml`) and `.github/workflows/publish-packages.yml` verify synchronization before any PyPI release.

## Running Tests and Package Builds

Run per-package unit suites and cross-server MCP `2026-07-28` contract suites from the repository root:

```bash
pytest server/secops/tests/*_unit.py -v
pytest server/gti/tests/ -v
pytest server/secops-soar/tests/unit -v
pytest server/scc/tests/ -v
pytest run-with-google-adk/tests/ -v
pytest tests/test_mcp_v2_*.py -v
```

Verify `sdist` and `wheel` artifacts with `build` and `twine`:

```bash
DIST_BASE="/tmp/mcp-security-dist"
for pkg in server/secops server/gti server/secops-soar server/scc run-with-google-adk; do
  PKG_OUT="$DIST_BASE/$(basename "$pkg")"
  python -m build "$pkg" --outdir "$PKG_OUT"
  python -m twine check "$PKG_OUT"/*
done
```

## Building Documentation Locally

Build the Sphinx site with strict warning checking (`-W`) to verify zero broken MyST cross-references (`myst.xref_missing`) or syntax-highlighting errors:

```bash
DOCS_OUT_DIR="/tmp/mcp-security-docs-html"
uv run --python 3.11 \
  --with sphinx \
  --with furo \
  --with myst-parser \
  --with sphinx-copybutton \
  --with sphinx-click \
  sphinx-build -W --keep-going -b html docs "$DOCS_OUT_DIR"
```

**MyST Cross-Reference Rule:** `docs/conf.py` does not enable automatic heading-slug anchors (`myst_heading_anchors`). Link across documents by filename (`../usage_guide.md`) or define explicit `(target-label)=` MyST anchors above target headings.
