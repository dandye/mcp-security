# Using the Google Security MCP Servers

This guide covers configuring and running the Google Security MCP servers (`mcp>=2.3.0`, protocol `2026-07-28`) across Google ADK, Gemini CLI, Goose, Claude Desktop, and VS Code.

## Prerequisites

1. **Google Cloud Authentication** (for Google Security Operations SIEM and Security Command Center):
   - Authenticate Application Default Credentials:
     ```bash
     PROJECT_ID="my-secops-project"
     ACCOUNT_EMAIL="analyst@example.com"
     gcloud config set project "$PROJECT_ID"
     gcloud auth login "$ACCOUNT_EMAIL" --update-adc
     gcloud auth application-default set-quota-project "$PROJECT_ID"
     ```
   - Or point `GOOGLE_APPLICATION_CREDENTIALS` (or `SECOPS_SA_PATH` for `google-secops-mcp`) to a service account JSON key file.

2. **Service Credentials** (as needed):
   - `CHRONICLE_PROJECT_ID`, `CHRONICLE_CUSTOMER_ID` (for example `a1b2c3d4-e5f6-4321-abcd-ef1234567890`), and `CHRONICLE_REGION` (`us` default) for Google Security Operations SIEM.
   - `VT_APIKEY` for Google Threat Intelligence.
   - `SOAR_URL` and `SOAR_APP_KEY` for Google Security Operations SOAR.

3. **Supported MCP Clients and Agent Harnesses**:
   - [Google ADK (Agent Development Kit)](https://google.github.io/adk-docs/) (`google-adk[mcp]>=2.13.0`, prebuilt agent included in `run-with-google-adk/`)
   - [Gemini CLI](https://geminicli.com)
   - [Goose (`aaif-goose/goose`)](https://goose-docs.ai/)
   - [Claude Desktop](https://claude.ai/download) and Claude Code
   - [Cline VS Code Extension](https://cline.bot/)

4. **Python Tooling**:
   - Python 3.11+ and [`uv`](https://docs.astral.sh/uv/getting-started/installation/).

(getting-started)=
## Getting Started

### Step 1: Install Packages or Clone the Repository

Install published PyPI packages via `uv tool install`:

```bash
uv tool install google-secops-mcp
uv tool install gti-mcp
uv tool install secops-soar-mcp
uv tool install scc-mcp
```

Or clone the repository for local development and the Google ADK agent:

```bash
git clone https://github.com/google/mcp-security.git
cd mcp-security
```

### Step 2: Configure Your MCP Client

#### Google ADK Autonomous SOC Agent (`run-with-google-adk`)

`mcp-security-agent` (`0.3.0`) defaults to `gemini-3.1-pro-preview` (with `gemini-3-flash-preview` supported) on Vertex AI `GOOGLE_CLOUD_LOCATION="global"` and connects over either local `stdio` or remote `streamable-http` (`SECOPS_MCP_URL`, `CHRONICLE_REMOTE_MCP_URL`, `GTI_MCP_URL`, `SOAR_MCP_URL`, `SCC_MCP_URL`):

```bash
ADK_PORT="8080"
cd run-with-google-adk
cp .env.example .env

# Interactive terminal REPL with destructive-tool confirmation and MRTR elicitation
uv run mcp-security-agent chat

# Dark-mode Web UI and FastAPI service
uv run mcp-security-agent serve --port "$ADK_PORT"
```

See the [ADK Agent Guide](https://github.com/google/mcp-security/blob/main/run-with-google-adk/README.md) for all environment variables and Cloud Run deployment instructions.

#### Gemini CLI (`~/.gemini/settings.json`)

Gemini CLI supports both the managed [Remote MCP Server](remote_server.md) (`httpUrl`) and local `stdio` servers:

```json
{
  "mcpServers": {
    "secops": {
      "command": "uvx",
      "args": ["--from", "google-secops-mcp", "secops_mcp"],
      "env": {
        "CHRONICLE_PROJECT_ID": "my-secops-project",
        "CHRONICLE_CUSTOMER_ID": "a1b2c3d4-e5f6-4321-abcd-ef1234567890",
        "CHRONICLE_REGION": "us"
      }
    },
    "gti": {
      "command": "uvx",
      "args": ["--from", "gti-mcp", "gti_mcp"],
      "env": {
        "VT_APIKEY": "your-gti-api-key"
      }
    }
  }
}
```

#### Goose (`~/.config/goose/config.yaml`)

[Goose](https://goose-docs.ai/) (`aaif-goose/goose`) connects to these servers as `stdio` or `streamable_http` extensions:

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
  scc:
    name: Security Command Center
    type: stdio
    cmd: uvx
    args:
      - --from
      - scc-mcp
      - scc_mcp
  gti-http:
    name: Google Threat Intelligence HTTP
    type: streamable_http
    uri: http://127.0.0.1:8081/mcp
```

#### Claude Desktop (`claude_desktop_config.json`)

1. Open Claude Desktop and navigate to **Settings -> Developer -> Edit Config**.
2. Add the desired server entries from the configuration reference below.
3. Save `claude_desktop_config.json` and restart Claude Desktop.

(mcp-server-configuration-reference)=
## MCP Server Configuration Reference

### Local `stdio` Configuration (`uv --directory`)

**macOS Note:** If `uv` was installed via the standalone installer into `~/.local/bin/uv`, specify the absolute path `/Users/<username>/.local/bin/uv` in `"command"` so GUI clients locate the binary.

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

### Stateless `streamable-http` Deployment

Every server can also run as a stateless HTTP service (`--transport streamable-http`) with `/healthz`, `/readyz`, `SEP-2549` `CacheHint` TTLs, MRTR destructive-action elicitation, and optional OAuth 2.1 bearer verification. See the [MCP 2026-07-28 Protocol Guide](mcp_v2_capabilities.md) for full details:

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
secops_mcp --transport streamable-http --host "$MCP_HOST" --port "$MCP_PORT"
```

(setting-up-environment-variables)=
### Setting Up Environment Variables

#### macOS and Linux

```bash
PROJECT_ID="my-secops-project"
CUSTOMER_ID="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
SOAR_TENANT_URL="https://your-tenant.siemplify-soar.com"
SOAR_API_KEY="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
GTI_KEY="your-gti-api-key"

# Google Security Operations SIEM
export CHRONICLE_PROJECT_ID="$PROJECT_ID"
export CHRONICLE_CUSTOMER_ID="$CUSTOMER_ID"
export CHRONICLE_REGION="us"

# Google Security Operations SOAR
export SOAR_URL="$SOAR_TENANT_URL"
export SOAR_APP_KEY="$SOAR_API_KEY"
export SOAR_INTEGRATIONS="ServiceNow,CSV,Siemplify"

# Google Threat Intelligence
export VT_APIKEY="$GTI_KEY"
```

#### Windows PowerShell

```powershell
$Env:CHRONICLE_PROJECT_ID = "my-secops-project"
$Env:CHRONICLE_CUSTOMER_ID = "a1b2c3d4-e5f6-4321-abcd-ef1234567890"
$Env:CHRONICLE_REGION = "us"
$Env:SOAR_URL = "https://your-tenant.siemplify-soar.com"
$Env:SOAR_APP_KEY = "a1b2c3d4-e5f6-4321-abcd-ef1234567890"
$Env:VT_APIKEY = "your-gti-api-key"
```

(usage-examples)=
## Usage Examples

### Google Threat Intelligence (GTI)

```text
Enrich file hash 44d88612fea8a8f36de82e1278abb02f, list contacted domains, and check standard YARA hunting rulesets.
```

### Google Security Operations SIEM

```text
Search UDM events for suspicious PowerShell command lines in the last 24 hours and validate a YARA-L 2.0 detection rule for encoded commands.
```

### Google Security Operations SOAR

```text
List open high-priority cases, inspect grouped alerts and entities on the top case, and draft a closure summary.
```

See [SOAR Integrations](./soar_integrations/index.md) for action documentation across marketplace integrations.

### Security Command Center (SCC)

```text
List the top critical vulnerability findings by Attack Exposure Score in project 'my-secops-project' and retrieve remediation steps.
```

## Troubleshooting

### SecOps SOAR: Finding the Correct `SOAR_URL`

If `secops-soar-mcp` exits at startup with:

```text
Error: Failed to fetch valid scopes from SOAR, please make sure you have configured the right SOAR credentials. Shutting down...
```

verify that `SOAR_URL` points to your Google Security Operations SOAR instance base URL (for example `https://your-tenant.siemplify-soar.com`) rather than a SIEM URL:

1. In Google Security Operations SOAR, open **Settings -> Webhooks**, create a placeholder webhook, and copy the scheme and host from the generated URL.
2. Alternatively, inspect a `GetCaseCardsByRequest` network call in browser developer tools on the **Cases** view and copy its origin URL.

### Corporate Proxy and Custom TLS CA Configuration

All servers honor standard `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables:

```json
{
  "mcpServers": {
    "gti": {
      "command": "uvx",
      "args": ["--from", "gti-mcp", "gti_mcp"],
      "env": {
        "VT_APIKEY": "${VT_APIKEY}",
        "HTTP_PROXY": "${HTTP_PROXY}",
        "HTTPS_PROXY": "${HTTPS_PROXY}"
      }
    }
  }
}
```

When running behind a TLS-inspecting proxy, point the transport CA variable at your corporate root bundle:

- `gti-mcp` and `secops-soar-mcp` (`aiohttp`): `SSL_CERT_FILE`
- `google-secops-mcp` (`requests`): `REQUESTS_CA_BUNDLE`
- `scc-mcp` (`grpcio` and `google-auth`): `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` and `REQUESTS_CA_BUNDLE`
