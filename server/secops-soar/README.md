# Google Security Operations SOAR MCP Server

This is a Model Context Protocol (MCP `2026-07-28`, `mcp>=2.3.0`) server (`secops-soar-mcp` `0.3.0`) for interacting with Google Security Operations SOAR.
[MCP Info](https://modelcontextprotocol.io/introduction)

## MCP 2026-07-28 Capabilities

- **Transports**: Local `stdio` (default) and stateless single-exchange `streamable-http` (`--transport streamable-http --host 127.0.0.1 --port 8080`) with `server/discover`, `/healthz`, and `/readyz`.
- **Discovery Caching (`SEP-2549`) and OpenTelemetry**: `CacheHint` TTLs and scope via `MCP_TOOLS_CACHE_TTL_MS` and `MCP_TOOLS_CACHE_SCOPE`, plus `OpenTelemetryMiddleware` span instrumentation (`OTEL_EXPORTER_OTLP_ENDPOINT`).
- **Annotations and Typed Envelopes**: 100% `title` + `ToolAnnotations` coverage across core case management tools and all 313 marketplace integration modules, typed `structuredContent`, and `is_error=True` operational failure signaling.
- **Resources and `ResourceLink` Compaction**: Exposes `soar://info/capabilities`, `soar://cases/{case_id}`, and `soar://cases/{case_id}/wall` under `DEFAULT_RESOURCE_SECURITY`, plus `ResourceLink` summaries on `list_cases`.
- **SOC Prompts**: `@server.prompt()` workflows `investigate_soar_case(case_id)` and `draft_case_closure_summary(case_id)`.
- **Stateless MRTR Elicitation**: `AESGCMRequestStateCodec` confirmation (`MCP_ELICIT_DESTRUCTIVE`, `MCP_UNATTENDED_DESTRUCTIVE_POLICY`, `MCP_REQUEST_STATE_SECRET`) on `close_case`.
- **OAuth 2.1 Resource Server**: Optional RFC 9728 Protected Resource Metadata and JWT/JWKS validation (`MCP_OAUTH_ISSUER_URL`, `MCP_RESOURCE_SERVER_URL`, `MCP_OAUTH_JWKS_URL`, `MCP_OAUTH_JWKS_JSON`, `MCP_REQUIRED_SCOPES`).
- **Official MCP Registry**: Manifest published at `server/secops-soar/server.json` (`io.github.google/secops-soar-mcp`).

## Features

### Core Tools (Case Management & Entities)

- **`list_cases()`** - Lists available cases in the SOAR platform.
- **`post_case_comment(case_id, comment)`** - Adds a textual comment to a specific case.
- **`list_alerts_by_case(case_id)`** - Lists all alerts associated with a specific case ID.
- **`list_alert_group_identifiers_by_case(case_id)`** - Lists the unique group identifiers for alerts within a specific case.
- **`list_events_by_alert(case_id, alert_id)`** - Lists the events associated with a particular alert within a given case.
- **`change_case_priority(case_id, case_priority)`** - Modifies the priority level of a specific case.
- **`get_entities_by_alert_group_identifiers(case_id, alert_group_identifiers)`** - Retrieves entities involved in one or more alert groups.
- **`get_entity_details(entity_identifier, entity_type, entity_environment)`** - Fetches detailed information about a specific entity.
- **`search_entity(term=None, type=None, is_suspicious=None, is_internal_asset=None, is_enriched=None, network_name=None, environment_name=None)`** - Searches for entities within the SOAR platform.
- **`get_case_full_details(case_id)`** - Retrieves comprehensive details for a single case.

### Dynamic Integration Tools (Marketplace)

This server can dynamically load additional tools based on integrations enabled via the `--integrations` command-line flag when the server is started. These tools correspond to modules found in the `marketplace/` directory.

Available integrations include:
- ServiceNow
- CSV
- Jira
- Slack
- Email
- VirusTotal
- Active Directory
- Microsoft Defender ATP
- And many more

## Installing in Claude Desktop

To use this MCP server with Claude Desktop:

1.  Install Claude Desktop

2.  Open Claude Desktop and select "Settings" from the Claude menu

3.  Click on "Developer" in the lefthand bar, then click "Edit Config"

4.  Update your `claude_desktop_config.json` with the following configuration
    (replace paths with your actual paths):
    
    **NOTE:** For OSX users, if you used [this one-liner](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer) to install uv, use the full path to the uv binary for the "command" value below, as uv will not be placed in the system path for Claude to use! For example: `/Users/yourusername/.local/bin/uv` instead of just `uv`.

    Additionally, for the secops-soar MCP server, you will need use the CA list bundled with the certifi package. This can be done via the following command. Change the Python minor version to match whatever version you are currently running. (ex. `Python\ 3.11`):
    `/Applications/Python\ 3.12/Install\ Certificates.command`

```json
{
  "mcpServers": {
    "secops-soar": {
      "command": "uv",
      "args": [
        "--env-file=/path/to/your/env",
        "--directory",
        "/path/to/the/repo/server/secops-soar/secops_soar_mcp",
        "run",
        "server.py"
      ],
      "env": {
        "SOAR_URL": "${SOAR_URL}",
        "SOAR_APP_KEY": "${SOAR_APP_KEY}"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

To have the MCP server provide tools for specific marketplace integrations, use the `integrations` flag followed by a comma-separated string of the desired integration names. For example, for the `ServiceNow`, `CSV`, and `Siemplify` integrations:
```json
{
  "mcpServers": {
    "secops-soar": {
      "command": "uv",
      "args": [
        "--env-file=/path/to/your/env",
        "--directory",
        "/path/to/the/repo/server/secops-soar/secops_soar_mcp",
        "run",
        "server.py",
        "--integrations",
        "ServiceNow,CSV,Siemplify"
      ],
      "env": {
        "SOAR_URL": "${SOAR_URL}",
        "SOAR_APP_KEY": "${SOAR_APP_KEY}"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Running Over Stateless `streamable-http`

```bash
SOAR_TENANT_URL="https://your-tenant.siemplify-soar.com"
SOAR_API_KEY="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
MCP_HOST="127.0.0.1"
MCP_PORT="8080"

SOAR_URL="$SOAR_TENANT_URL" \
SOAR_APP_KEY="$SOAR_API_KEY" \
MCP_ELICIT_DESTRUCTIVE="true" \
secops_soar_mcp \
  --integrations "ServiceNow,CSV,Siemplify" \
  --transport streamable-http \
  --host "$MCP_HOST" \
  --port "$MCP_PORT"
```

### Environment Variable Setup

Set up these environment variables in your system:

**For macOS/Linux:**
```bash
SOAR_TENANT_URL="https://your-tenant.siemplify-soar.com"
SOAR_API_KEY="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
export SOAR_URL="$SOAR_TENANT_URL"
export SOAR_APP_KEY="$SOAR_API_KEY"
export SOAR_INTEGRATIONS="ServiceNow,CSV,Siemplify"
```

**For Windows PowerShell:**
```powershell
$Env:SOAR_URL = "your-soar-url"
$Env:SOAR_APP_KEY = "your-soar-app-key"
$Env:SOAR_INTEGRATIONS = "ServiceNow,CSV,Siemplify"
```

## Troubleshooting

If the server shuts down at startup with an error like `Failed to fetch valid
scopes from SOAR due to an SSL certificate verification error`, this is a
local CA certificate problem, not incorrect `SOAR_URL`/`SOAR_APP_KEY` values.
Install the certifi CA bundle:

- **macOS:** run `Install Certificates.command` from your Python install,
  e.g. `/Applications/Python\ 3.12/Install\ Certificates.command` (match the
  Python minor version you're running).
- **Linux/Windows:** point `SSL_CERT_FILE` at the certifi bundle, e.g.
  `export SSL_CERT_FILE=$(python -m certifi)` (or the PowerShell equivalent
  `$Env:SSL_CERT_FILE = (python -m certifi)`).

### Corporate Proxy Configuration

The server automatically honors standard proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`). If running behind a corporate proxy, set these variables in your environment or within your MCP client configuration (`cline_mcp_settings.json`, `claude_desktop_config.json`):

```json
"env": {
  "SOAR_URL": "https://your-soar-instance",
  "SOAR_APP_KEY": "your-key",
  "HTTP_PROXY": "http://proxy.corp.example.com:8080",
  "HTTPS_PROXY": "http://proxy.corp.example.com:8080"
}
```

If your corporate proxy performs SSL decryption/inspection, point `SSL_CERT_FILE` to your corporate CA bundle.

See `docs/usage_guide.md` for further details.

## Requirements

-   Python 3.11+
-   SOAR URL and AppKey

## License

Apache 2.0

## Development

The project is structured as follows:

-   `server.py`: Main MCP server implementation
-   `marketplace/`: Directory containing integration modules
