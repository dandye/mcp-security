# Google Security Operations and Threat Intelligence MCP Servers

This repository provides Model Context Protocol (MCP) servers targeting the MCP `2026-07-28` specification (`mcp>=2.3.0,<3.0.0`) and a prebuilt Autonomous Security Operations Center (SOC) Agent built on Google Agent Development Kit (`google-adk[mcp]>=2.13.0,<3.0.0`):

1. **Remote MCP Server for Google Security Operations** - Fully managed Google Cloud MCP endpoint (Recommended for Google SecOps SIEM)
2. **Google Security Operations SIEM (`google-secops-mcp` `0.9.0`)** - UDM event search, alerts, entity context, retrohunts, and YARA-L 2.0 detection rules
3. **Google Security Operations SOAR (`secops-soar-mcp` `0.3.0`)** - Case management, alert grouping, entity enrichment, and 313 marketplace integrations
4. **Google Threat Intelligence (`gti-mcp` `0.2.0`)** - IOC enrichment, threat actor and campaign collections, sandbox behavior reports, and standard YARA file/payload hunting rulesets
5. **Google Cloud Security Command Center (`scc-mcp` `0.3.0`)** - Cloud security posture findings, attack exposure prioritization, compliance search, and Cloud Asset Inventory context

For the managed **Remote MCP Server**, see the [launch announcement](https://security.googlecloudcommunity.com/community-blog-42/google-cloud-remote-mcp-server-for-secops-6559) and the [remote server setup guide](docs/remote_server.md).

## MCP 2026-07-28 Capabilities

All four local/self-hosted MCP servers implement the MCP `2026-07-28` protocol specification on `MCPServer` (`mcp>=2.3.0`):

- **Dual Transports (`stdio` and Stateless `streamable-http`)**: Run locally over `stdio` or deploy over stateless single-exchange Streamable HTTP (`--transport streamable-http --host 127.0.0.1 --port 8080`) with `server/discover`, `/healthz`, and `/readyz` endpoints.
- **Discovery Caching (`SEP-2549`) and OpenTelemetry**: Configurable `CacheHint` TTLs (`MCP_TOOLS_CACHE_TTL_MS`, plus `MCP_TOOLS_CACHE_SCOPE` on `secops-soar-mcp`) and built-in `OpenTelemetryMiddleware` span instrumentation (`OTEL_EXPORTER_OTLP_ENDPOINT`).
- **100% `ToolAnnotations` and Typed `structuredContent`**: Every registered tool declares human-readable `title` metadata and `ToolAnnotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), returns typed `structuredContent` envelopes, and signals operational failures with `is_error=True`.
- **Sandboxed Resources (`DEFAULT_RESOURCE_SECURITY`) and `ResourceLink` Compaction**: Addressable resources under `secops://`, `gti://`, `soar://`, and `scc://` URI templates paired with `ResourceLink` summaries on high-volume listing tools (`list_security_rules`, `get_security_alerts`, `search_threats`, `list_cases`, `top_vulnerability_findings`).
- **Parameterized SOC `@server.prompt()` Workflows**: Reusable investigation, YARA-L 2.0 rule validation, threat profiling, case triage, and cloud exposure prompts across all four servers.
- **Stateless Multi-Round Tool Requests (MRTR) and Progress Notifications**: Encrypted `AESGCMRequestStateCodec` elicitation (`MCP_ELICIT_DESTRUCTIVE=true`, `MCP_UNATTENDED_DESTRUCTIVE_POLICY`) before high-impact mutations (`delete_rule`, `analyse_file`, `close_case`, `set_finding_mute`) and streaming `ctx.report_progress(...)` updates on long-running operations (`test_rule`, `export_udm_search_csv`, `analyse_file`, `analyse_url`).
- **OAuth 2.1 Resource Server**: Optional RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource`) and JWT/JWKS bearer verification (`MCP_OAUTH_ISSUER_URL`, `MCP_RESOURCE_SERVER_URL`, `MCP_OAUTH_JWKS_URL`, `MCP_OAUTH_JWKS_JSON`, `MCP_REQUIRED_SCOPES`).
- **Dark-Mode MCP Apps**: Interactive HTML UI resources (`ui://secops/entity-timeline.html`, `ui://gti/ioc-verdict.html`, `ui://scc/finding-card.html`) rendered by MCP Apps-capable hosts, with `--disable-apps` / `MCP_ENABLE_APPS=false` opt-out.
- **Official MCP Registry Manifests**: Validated `server.json` manifests (`2025-12-11/server.schema.json`) in every server package directory (`io.github.google/google-secops-mcp`, `io.github.google/gti-mcp`, `io.github.google/secops-soar-mcp`, `io.github.google/scc-mcp`).

## Documentation

Full documentation is available in `docs/` and published at [https://google.github.io/mcp-security/](https://google.github.io/mcp-security/). Start at [docs/index.md](docs/index.md) or [docs/usage_guide.md](docs/usage_guide.md).

To build the Sphinx HTML documentation locally:

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

## Authentication

Google Security Operations SIEM and Security Command Center servers authenticate via Google Cloud credentials:

1. Application Default Credentials (ADC) configured via `gcloud`
2. `GOOGLE_APPLICATION_CREDENTIALS` (or `SECOPS_SA_PATH` for `google-secops-mcp`) pointing to a service account key file
3. Service account impersonation via `SECOPS_IMPERSONATE_SERVICE_ACCOUNT`

Google Threat Intelligence uses `VT_APIKEY`, and Google Security Operations SOAR uses `SOAR_URL` and `SOAR_APP_KEY`.

## Standalone Installation and Transport Modes

Install individual server packages with `uv tool install` (recommended) or `pip`:

```bash
uv tool install google-secops-mcp
uv tool install gti-mcp
uv tool install scc-mcp
uv tool install secops-soar-mcp
```

### Running Over `stdio` (Default)

```bash
PROJECT_ID="my-secops-project"
CUSTOMER_ID="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
CHRONICLE_REGION="us"

CHRONICLE_PROJECT_ID="$PROJECT_ID" \
CHRONICLE_CUSTOMER_ID="$CUSTOMER_ID" \
CHRONICLE_REGION="$CHRONICLE_REGION" \
uvx --from google-secops-mcp secops_mcp
```

### Running Over Stateless `streamable-http`

Every server exposes `/mcp`, `/healthz`, and `/readyz` when started with `--transport streamable-http`:

```bash
PROJECT_ID="my-secops-project"
CUSTOMER_ID="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
MCP_HOST="127.0.0.1"
MCP_PORT="8080"

CHRONICLE_PROJECT_ID="$PROJECT_ID" \
CHRONICLE_CUSTOMER_ID="$CUSTOMER_ID" \
CHRONICLE_REGION="us" \
MCP_TOOLS_CACHE_TTL_MS="300000" \
MCP_ELICIT_DESTRUCTIVE="true" \
uvx --from google-secops-mcp secops_mcp \
  --transport streamable-http \
  --host "$MCP_HOST" \
  --port "$MCP_PORT"
```

Verify readiness and stateless `2026-07-28` single-exchange `server/discover` without an `initialize` handshake:

```bash
MCP_URL="http://127.0.0.1:8080"

curl -fsS "$MCP_URL/readyz"

curl -fsS "$MCP_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -d '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}'
```

## Using the Google ADK Autonomous SOC Agent

The repository includes `mcp-security-agent` (`0.3.0`) in [`run-with-google-adk`](./run-with-google-adk/README.md), built on `google-adk[mcp]>=2.13.0` and defaulting to `gemini-3.1-pro-preview` (with `gemini-3-flash-preview` supported for low-latency triage) on Vertex AI `GOOGLE_CLOUD_LOCATION="global"`.

It connects to both local `stdio` servers and remote `streamable-http` endpoints (`SECOPS_MCP_URL`, `CHRONICLE_REMOTE_MCP_URL`, `GTI_MCP_URL`, `SOAR_MCP_URL`, `SCC_MCP_URL`) with dynamic Google Cloud OAuth/OIDC header providers, `use_mcp_resources=True`, `tool_name_prefix`, destructive-tool confirmation (`ADK_CONFIRM_DESTRUCTIVE_TOOLS`), MRTR elicitation callbacks (`ADK_ELICITATION_POLICY`), output schema size guards, and W3C OpenTelemetry `traceparent` propagation.

```bash
ADK_PORT="8080"
cd run-with-google-adk
cp .env.example .env

# Interactive terminal investigation REPL
uv run mcp-security-agent chat

# Web UI and Cloud Run FastAPI server
uv run mcp-security-agent serve --port "$ADK_PORT"
```

See [`run-with-google-adk/README.md`](./run-with-google-adk/README.md) for full configuration and Cloud Run deployment instructions.

## MCP Client Configurations

These MCP servers work with standard MCP clients and agent harnesses, including:

1. **Google ADK (`google-adk>=2.13.0`)** - Prebuilt agent in [`run-with-google-adk`](./run-with-google-adk/README.md)
2. **Gemini CLI** - With optional [Google SecOps Extension](docs/google_secops_extension.md) skills
3. **Goose (`aaif-goose/goose`)** - Open-source developer and security agent ([https://goose-docs.ai/](https://goose-docs.ai/))
4. **Claude Desktop and Claude Code**
5. **Cursor IDE and VS Code (Cline)**

| Client Application | Scope | macOS / Linux Location | Windows Location | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Gemini CLI** | Global | `~/.gemini/settings.json` | `%USERPROFILE%\.gemini\settings.json` | Uses `mcpServers` block; supports `httpUrl` and `stdio`. |
| **Goose (`aaif-goose/goose`)** | Global | `~/.config/goose/config.yaml` | `%APPDATA%\Block\goose\config\config.yaml` | Configure `stdio` or `streamable_http` extensions; see [Goose docs](https://goose-docs.ai/). |
| **Claude Desktop** | Global | `~/Library/Application Support/Claude/claude_desktop_config.json` | `%APPDATA%\Claude\claude_desktop_config.json` | Accessible via *Claude -> Settings -> Developer -> Edit Config*. |
| **Claude Code** | Global | `~/.claude.json` | `%USERPROFILE%\.claude.json` | Supports `stdio` and HTTP MCP servers. |
| **Cursor IDE** | Global / Project | `~/.cursor/mcp.json` or `.cursor/mcp.json` | `%USERPROFILE%\.cursor\mcp.json` | Project file overrides global settings. |
| **VS Code (Cline)** | Workspace | `<project-root>/.vscode/mcp.json` | `<project-root>/.vscode/mcp.json` | Workspace-level MCP configuration. |

### JSON Client Configuration (`uvx` Recommended)

```json
{
  "mcpServers": {
    "secops": {
      "command": "uvx",
      "args": [
        "--from",
        "google-secops-mcp",
        "secops_mcp"
      ],
      "env": {
        "CHRONICLE_PROJECT_ID": "my-secops-project",
        "CHRONICLE_CUSTOMER_ID": "a1b2c3d4-e5f6-4321-abcd-ef1234567890",
        "CHRONICLE_REGION": "us"
      }
    },
    "gti": {
      "command": "uvx",
      "args": [
        "--from",
        "gti-mcp",
        "gti_mcp"
      ],
      "env": {
        "VT_APIKEY": "your-gti-api-key"
      }
    },
    "secops-soar": {
      "command": "uvx",
      "args": [
        "--from",
        "secops-soar-mcp",
        "secops_soar_mcp",
        "--integrations",
        "CSV,OKTA"
      ],
      "env": {
        "SOAR_URL": "https://your-tenant.siemplify-soar.com:443",
        "SOAR_APP_KEY": "a1b2c3d4-e5f6-4321-abcd-ef1234567890"
      }
    },
    "scc-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "scc-mcp",
        "scc_mcp"
      ],
      "env": {}
    }
  }
}
```

### Goose Configuration (`~/.config/goose/config.yaml`)

Goose ([https://goose-docs.ai/](https://goose-docs.ai/)) supports both `stdio` and `streamable_http` MCP extensions:

```yaml
extensions:
  secops:
    name: Google Security Operations SIEM
    type: stdio
    cmd: uvx
    args:
      - --from
      - google-secops-mcp
      - secops_mcp
    envs:
      CHRONICLE_PROJECT_ID: my-secops-project
      CHRONICLE_CUSTOMER_ID: a1b2c3d4-e5f6-4321-abcd-ef1234567890
      CHRONICLE_REGION: us
  gti-remote:
    name: Google Threat Intelligence HTTP
    type: streamable_http
    uri: https://gti-mcp.example.run.app/mcp
```

### Local Source Checkout Configuration (`uv --directory`)

When developing from a local repository clone:

```json
{
  "mcpServers": {
    "secops": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/mcp-security/server/secops",
        "run",
        "secops_mcp"
      ],
      "env": {
        "CHRONICLE_PROJECT_ID": "my-secops-project",
        "CHRONICLE_CUSTOMER_ID": "a1b2c3d4-e5f6-4321-abcd-ef1234567890",
        "CHRONICLE_REGION": "us"
      }
    },
    "gti": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/mcp-security/server/gti",
        "run",
        "gti_mcp"
      ],
      "env": {
        "VT_APIKEY": "your-gti-api-key"
      }
    },
    "secops-soar": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/mcp-security/server/secops-soar",
        "run",
        "secops_soar_mcp",
        "--integrations",
        "CSV,OKTA"
      ],
      "env": {
        "SOAR_URL": "https://your-tenant.siemplify-soar.com:443",
        "SOAR_APP_KEY": "a1b2c3d4-e5f6-4321-abcd-ef1234567890"
      }
    },
    "scc-mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/mcp-security/server/scc",
        "run",
        "scc_mcp"
      ],
      "env": {}
    }
  }
}
```

You can load secrets from an `.env` file via `--env-file /path/to/.env` or `UV_ENV_FILE`. See [docs/usage_guide.md](docs/usage_guide.md) for corporate proxy (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) and custom CA bundle configuration.

## Troubleshooting

Run any server directly from the terminal to inspect startup logs:

```bash
REPO_DIR="/path/to/mcp-security"
ENV_FILE="$REPO_DIR/.env"

uv --verbose \
  --directory "$REPO_DIR/server/scc" \
  run \
  --env-file "$ENV_FILE" \
  scc_mcp
```

Verify `uv` and Python 3.11+ are on your `PATH`:

```bash
which uv
python3 --version
```

## License

Apache 2.0
