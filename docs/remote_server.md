# Remote MCP Server for Google Security Operations

The **Remote MCP Server for Google Security Operations** provides a Google-managed Streamable HTTP endpoint so MCP clients and autonomous agents connect without managing local Python server processes.

For self-hosted stateless Streamable HTTP deployments of `google-secops-mcp`, `gti-mcp`, `secops-soar-mcp`, and `scc-mcp` (including OAuth 2.1 Resource Server mode, `SEP-2549` `CacheHint` configuration, and MRTR elicitation), see the [MCP 2026-07-28 Protocol Guide](mcp_v2_capabilities.md).

## Onboarding

### Authentication and Authorization

The managed remote server authenticates requests with [Application Default Credentials (ADC)](https://docs.cloud.google.com/mcp/authenticate-mcp#user-credentials-adc-mcp-servers).

1. **Set up ADC**: Follow [Set up Application Default Credentials](https://docs.cloud.google.com/docs/authentication/provide-credentials-adc).
2. **Authenticate**: See [Authenticate to Google and Google Cloud MCP servers](https://docs.cloud.google.com/mcp/authenticate-mcp).
3. **IAM Roles**: Grant `roles/mcp.toolUser` to the calling principal (`roles/serviceusage.serviceUsageAdmin` is required to enable the MCP service).

For production workloads, follow [Agent identity](https://docs.cloud.google.com/mcp/authenticate-mcp#agent-identity) guidance in [Manage MCP servers](https://docs.cloud.google.com/mcp/manage-mcp-servers).

### Enable the Service

Enable the managed MCP endpoint on your Google Cloud project:

```bash
PROJECT_ID="my-secops-project"
gcloud components install beta
gcloud beta services mcp enable chronicle.googleapis.com/mcp --project="$PROJECT_ID"
```

See [Supported Products](https://docs.cloud.google.com/mcp/supported-products) and the [Enablement Guide](https://docs.cloud.google.com/mcp/configure-mcp-ai-application#enable-remote-mcp-server).

### Environment Context

Include your tenant parameters in your agent instructions (for example `GEMINI.md` or ADK system prompt):

```text
When using the secops-hosted-mcp MCP server, pass these parameters on every request:
Customer ID: a1b2c3d4-e5f6-4321-abcd-ef1234567890
Region: us
Project ID: my-secops-project
```

### SOAR API Migration

The hosted MCP endpoint calls **Chronicle REST APIs** (OneMCP) rather than standalone Siemplify SOAR endpoints:

- **SIEM tools**: Available immediately.
- **SOAR tools**: Require completing SOAR Phase 2 API migration; see [SOAR migration overview](https://docs.cloud.google.com/chronicle/docs/soar/admin-tasks/advanced/migrate-to-gcp). Tenants still operating standalone Siemplify SOAR endpoints should connect `secops-soar-mcp` (`SOAR_URL` / `SOAR_MCP_URL`) alongside SIEM.

## Governance

- **Model Armor**: Inspect and sanitize MCP tool inputs and outputs ([Model Armor for MCP guide](https://docs.cloud.google.com/model-armor/model-armor-mcp-google-cloud-integration)).
- **Cloud Armor**: Apply network WAF and IP allowlists ([Cloud Armor integration](https://docs.cloud.google.com/chronicle/docs/soar/marketplace-integrations/google-cloud-armor)).
- **IAM**: Enforce `roles/mcp.toolUser` alongside granular Google Security Operations roles ([MCP Access Control](https://docs.cloud.google.com/mcp/access-control)).
- **Organization Policy**: Restrict permitted MCP services across an organization ([Control MCP use in your organization](https://docs.cloud.google.com/mcp/control-mcp-use-organization)):

```json
{
  "name": "organizations/123456789012/policies/gcp.managed.allowedMCPServices",
  "spec": {
    "rules": [
      {
        "enforce": true,
        "parameters": {
          "allowedServices": [
            "chronicle.googleapis.com/mcp"
          ]
        }
      }
    ]
  }
}
```

- **Audit Logging**: Access events are recorded in Cloud Audit Logs ([MCP Audit Logging](https://docs.cloud.google.com/mcp/audit-logging)).

## Client Configuration

### Automated Setup

For **Gemini CLI** and **Antigravity**, run the setup skills bundled in the [Google SecOps Extension](./google_secops_extension.md) (`secops-setup-gemini-cli` and `secops-setup-antigravity`).

### Gemini CLI

```json
{
  "mcpServers": {
    "secops-hosted-mcp": {
      "httpUrl": "https://chronicle.us.rep.googleapis.com/mcp",
      "authProviderType": "google_credentials",
      "oauth": {
        "scopes": ["https://www.googleapis.com/auth/cloud-platform"]
      },
      "timeout": 30000,
      "headers": {
        "x-goog-user-project": "my-secops-project"
      }
    }
  }
}
```

### Goose (`aaif-goose/goose`)

Configure a `streamable_http` extension in `~/.config/goose/config.yaml` ([https://goose-docs.ai/](https://goose-docs.ai/)):

```yaml
extensions:
  secops-hosted-mcp:
    name: Google Security Operations Remote MCP
    type: streamable_http
    uri: https://chronicle.us.rep.googleapis.com/mcp
    headers:
      x-goog-user-project: my-secops-project
```

### Google ADK (`google-adk[mcp]>=2.13.0`)

In `run-with-google-adk`, set `CHRONICLE_REMOTE_MCP_URL="https://chronicle.us.rep.googleapis.com/mcp"` in `.env` and `GcpRemoteHeaderProvider` refreshes tokens automatically. When constructing `McpToolset` directly in Python, pass a dynamic `header_provider` so OAuth tokens never expire mid-session:

```python
import google.auth
from google.auth.transport.requests import Request
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams

PROJECT_ID = "my-secops-project"
REMOTE_MCP_URL = "https://chronicle.us.rep.googleapis.com/mcp"
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def secops_header_provider(_readonly_context=None) -> dict[str, str]:
    creds, _ = google.auth.default(scopes=SCOPES)
    if not creds.valid or creds.expired or not creds.token:
        creds.refresh(Request())
    return {
        "Authorization": f"Bearer {creds.token}",
        "x-goog-user-project": PROJECT_ID,
    }


toolset = McpToolset(
    connection_params=StreamableHTTPConnectionParams(url=REMOTE_MCP_URL),
    header_provider=secops_header_provider,
    tool_name_prefix="secops",
    use_mcp_resources=True,
    tool_list_cache_ttl_seconds=300.0,
)
```

### Verifying With `curl`

```bash
PROJECT_ID="my-secops-project"
CUSTOMER_ID="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
CHRONICLE_REGION="us"
MCP_ENDPOINT="https://chronicle.us.rep.googleapis.com/mcp"
ACCESS_TOKEN="$(gcloud auth application-default print-access-token)"

curl --location "$MCP_ENDPOINT" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "x-goog-user-project: $PROJECT_ID" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 1,
    \"method\": \"tools/call\",
    \"params\": {
      \"name\": \"list_rules\",
      \"arguments\": {
        \"project_id\": \"$PROJECT_ID\",
        \"customer_id\": \"$CUSTOMER_ID\",
        \"region\": \"$CHRONICLE_REGION\"
      }
    }
  }" -s
```

## Available Tools

The managed endpoint exposes Google Security Operations SIEM and (post-migration) SOAR tools dynamically via `tools/list` and `server/discover`. When connected through `run-with-google-adk`, `MCP_FILTER_BLOAT_FEED_TOOLS=True` excludes the seven heavy feed-management schemas by default to conserve model context tokens.
