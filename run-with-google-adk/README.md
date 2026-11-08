# Google ADK Security Agent Guide (`mcp-security-agent` `0.3.0`)

This guide covers running and deploying the Autonomous Security Operations Center (SOC) Agent built on Google Agent Development Kit (`google-adk[mcp]>=2.13.0,<3.0.0`) and Model Context Protocol (`mcp[cli]>=2.3.0,<3.0.0`, specification `2026-07-28`).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quickstart: Running Locally](#quickstart-running-locally)
3. [ADK v2.13 and MCP v2.3 Capabilities](#adk-v213-and-mcp-v23-capabilities)
4. [CLI Commands and Options](#cli-commands-and-options)
5. [Configuration and Environment Variables](#configuration-and-environment-variables)
6. [Running the Web UI and FastAPI Server](#running-the-web-ui-and-fastapi-server)
7. [Deploying to Google Cloud Run](#deploying-to-google-cloud-run)
8. [Integrating Custom MCP Servers](#integrating-custom-mcp-servers)
9. [Testing and Verification](#testing-and-verification)

---

## Prerequisites

1. **Python 3.11+**
2. [**uv**](https://docs.astral.sh/uv/) (recommended) or `pip`
3. **Google Cloud project or API credentials** for one or more of:
   - Google Security Operations SIEM (`server/secops` or remote Streamable HTTP)
   - Google Cloud Security Command Center (`server/scc` or remote Streamable HTTP)
   - Google Threat Intelligence (`server/gti` or remote Streamable HTTP)
   - Google Security Operations SOAR (`server/secops-soar` or remote Streamable HTTP)
4. **Model Authentication**:
   - **Vertex AI (Recommended for Gemini 3+ models)**: Authenticate Application Default Credentials and set `GOOGLE_GENAI_USE_VERTEXAI=True` with `GOOGLE_CLOUD_LOCATION=global`:
     ```bash
     ACCOUNT_EMAIL="analyst@example.com"
     gcloud auth login "$ACCOUNT_EMAIL" --update-adc
     ```
   - **Gemini Developer API**: Obtain an API key from [Google AI Studio](https://ai.google.dev/gemini-api/docs/api-key) and set `GOOGLE_API_KEY` with `GOOGLE_GENAI_USE_VERTEXAI=False`.

---

## Quickstart: Running Locally

```bash
PROJECT_ID="my-secops-project"
CUSTOMER_ID="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
ADK_PORT="8080"

cd run-with-google-adk
cp .env.example .env

# Inspect active Gemini 3+ model, resolved GCP project, and MCP toolset transports
uv run mcp-security-agent info

# Start an interactive investigation session with Google SecOps SIEM and SCC
uv run mcp-security-agent chat \
  --vertex \
  --project "$PROJECT_ID" \
  --customer-id "$CUSTOMER_ID" \
  --secops \
  --scc

# Launch the dark-mode SOC Web UI and FastAPI server
uv run mcp-security-agent serve --port "$ADK_PORT"
```

---

## ADK v2.13 and MCP v2.3 Capabilities

`mcp-security-agent` `0.3.0` adopts native `google-adk==2.13.0` and `mcp==2.3.0` features:

- **Gemini 3+ Defaults on Vertex Global**: Defaults to `GOOGLE_MODEL=gemini-3.1-pro-preview` (with `gemini-3-flash-preview` available for high-throughput triage) and `GOOGLE_CLOUD_LOCATION=global` when `GOOGLE_GENAI_USE_VERTEXAI=True`.
- **Dual `stdio` and `StreamableHTTPConnectionParams` Toolsets**: Every security domain (`secops`, `gti`, `soar`, `scc`) runs locally over isolated `stdio` subprocesses (automatically stripping parent `VIRTUAL_ENV` and `PYTHONPATH` to prevent virtualenv collisions) or connects to remote Streamable HTTP endpoints via `SECOPS_MCP_URL`, `CHRONICLE_REMOTE_MCP_URL` (`https://<region>-chronicle.googleapis.com/mcp`), `GTI_MCP_URL`, `SOAR_MCP_URL`, and `SCC_MCP_URL`.
- **Dynamic GCP OAuth2 and OIDC Header Provider**: `GcpRemoteHeaderProvider` refreshes Google Cloud OAuth access tokens or OIDC ID tokens (`MCP_REMOTE_AUTH_MODE=oauth|id_token`) per request via ADC, `SECOPS_SA_PATH`, or `SECOPS_IMPERSONATE_SERVICE_ACCOUNT`, and injects `x-goog-user-project`, remote `x-apikey` (for GTI), and W3C `traceparent` headers.
- **Tool Name Prefixing (`MCP_TOOL_NAME_PREFIX_ENABLED`)**: Optional per-server prefixes (`secops_`, `gti_`, `soar_`, `scc_`) prevent tool name collisions across multi-server deployments while keeping unprefixed tool names by default for backward compatibility.
- **MCP Resources (`MCP_USE_RESOURCES`) and Tool-List Caching (`MCP_TOOL_LIST_CACHE_TTL_SECONDS`)**: Enables ADK's `use_mcp_resources=True` (automatically namespacing `<server>_load_mcp_resource` when multiple unprefixed servers are active) and caches `tools/list` metadata for `300s` by default alongside server-side `SEP-2549` `CacheHint` TTLs.
- **Destructive-Tool Confirmation and MRTR Elicitation**:
  - `SecurityMcpToolset` inspects `ToolAnnotations.destructive_hint` and triggers ADK human-in-the-loop confirmation (`adk_request_confirmation`) in both `mcp-security-agent chat` (interactive REPL and single-turn queries) and the FastAPI Web UI (`mcp-security-agent serve`) when `ADK_CONFIRM_DESTRUCTIVE_TOOLS=true` (default `False`, or `--confirm-destructive`).
  - `McpElicitationHandler` wires MCP `2026-07-28` server-initiated `ctx.elicit(...)` forms according to `ADK_ELICITATION_POLICY` (`prompt`, `accept`, `decline`, `cancel`), failing closed to `decline` in non-interactive environments.
- **LLM Schema Sanitization and OpenTelemetry Propagation (`bmc_trim_llm_request`)**: Strips `x-google-enum-descriptions` vendor metadata, removes oversized `response_json_schema` definitions exceeding `ADK_MAX_TOOL_OUTPUT_SCHEMA_BYTES` (`4096` bytes default), and propagates active W3C OpenTelemetry `traceparent` and `tracestate` headers across outbound LLM and remote MCP calls.

---

## CLI Commands and Options

### `mcp-security-agent info`

Prints package version, active Gemini model, Vertex AI endpoint location, resolved Google Cloud project ID (`project_id`), ADC source, `tool_name_prefix_enabled`, `use_mcp_resources`, destructive-tool confirmation status, `elicitation_policy`, and transport status (`stdio`, `streamable-http`, or `disabled`) for each MCP server.

### `mcp-security-agent chat [QUERY] [OPTIONS]`

Starts an interactive terminal REPL when called without `QUERY`, or executes a confirmation-aware single-turn investigation when `QUERY` is supplied. During single-turn execution with `--confirm-destructive`, interactive terminals prompt `[Confirm] Approve execution of <tool_name>? [y/N]: ` in plain ASCII and resume in the same run; non-interactive callers exit with code `2` and print the `--session-id <id>` command to approve or reject.

| Option | Type | Description |
| :--- | :--- | :--- |
| `QUERY` | Argument | Optional single-turn investigation query (starts interactive REPL if omitted). |
| `--secops / --no-secops` | Flag | Enable or disable Google Security Operations SIEM MCP. |
| `--scc / --no-scc` | Flag | Enable or disable Security Command Center MCP. |
| `--gti / --no-gti` | Flag | Enable or disable Google Threat Intelligence MCP. |
| `--soar / --no-soar` | Flag | Enable or disable Google Security Operations SOAR MCP. |
| `--vertex / --no-vertex` | Flag | Toggle Vertex AI (`--vertex`) vs Gemini Developer API (`--no-vertex`). |
| `--model <name>` | String | Override Gemini model (default: `gemini-3.1-pro-preview`; fast option: `gemini-3-flash-preview`). |
| `--location <loc>` | String | Override Vertex AI location (default: `global`). |
| `--project <id>` | String | Override `GOOGLE_CLOUD_PROJECT` and `CHRONICLE_PROJECT_ID`. |
| `--customer-id <uuid>` | String | Override `CHRONICLE_CUSTOMER_ID`. |
| `--confirm-destructive / --no-confirm-destructive` | Flag | Toggle human confirmation for tools with `destructiveHint=True`. |
| `--prefix-tools / --no-prefix-tools` | Flag | Toggle `secops_`, `gti_`, `soar_`, `scc_` tool name prefixes. |
| `--session-id <id>` | String | Session ID to create or resume in single-turn `chat` mode (alias `--session_id`). |

### `mcp-security-agent serve [OPTIONS]`

Launches the FastAPI web console and REST/SSE API server (`--host`, `--port`, `--reload`, plus the same `--secops`, `--scc`, `--gti`, `--soar`, `--vertex`, `--model`, `--location`, `--prefix-tools`, and `--confirm-destructive` flags).

---

## Configuration and Environment Variables

### `.env.example` Overview

| Variable | Default | Description |
| :--- | :--- | :--- |
| `GOOGLE_MODEL` | `gemini-3.1-pro-preview` | Primary Gemini 3+ model (`gemini-3-flash-preview` also supported). |
| `GOOGLE_CLOUD_LOCATION` | `global` | Vertex AI endpoint location (`global` required for Gemini 3+ preview models). |
| `GOOGLE_GENAI_USE_VERTEXAI` | `False` | Route model calls via Vertex AI (`True`) or Gemini Developer API (`False`). |
| `GOOGLE_CLOUD_PROJECT` | None | Google Cloud project ID for Vertex AI, SCC, and quota billing. |
| `GOOGLE_API_KEY` | None | Gemini Developer API key when `GOOGLE_GENAI_USE_VERTEXAI=False`. |
| `LOAD_SECOPS_MCP` | Auto | Explicit override (`Y`/`N`); auto-enables when local credentials or remote URL are set. |
| `LOAD_GTI_MCP` | Auto | Explicit override (`Y`/`N`); auto-enables when `VT_APIKEY` or `GTI_MCP_URL` is set. |
| `LOAD_SECOPS_SOAR_MCP` | Auto | Explicit override (`Y`/`N`); auto-enables when `SOAR_URL` + `SOAR_APP_KEY` or `SOAR_MCP_URL` are set. |
| `LOAD_SCC_MCP` | Auto | Explicit override (`Y`/`N`); auto-enables when `SCC_MCP_URL` is set (`Y` in `.env.example`). |
| `CHRONICLE_PROJECT_ID` | None | Google Cloud project ID bound to the Google Security Operations tenant. |
| `CHRONICLE_CUSTOMER_ID` | None | Google Security Operations customer UUID (for example `a1b2c3d4-e5f6-4321-abcd-ef1234567890`). |
| `CHRONICLE_REGION` | `us` | Regional API code (`us`, `eu`, `asia`, etc.). |
| `VT_APIKEY` | None | Google Threat Intelligence / VirusTotal v3 API key. |
| `SOAR_URL` | None | Base URL of the Google Security Operations SOAR instance. |
| `SOAR_APP_KEY` | None | API key for Google Security Operations SOAR. |
| `SOAR_INTEGRATIONS` | `CSV,Siemplify,SiemplifyUtilities` | Comma-separated SOAR marketplace integrations loaded in `stdio` mode. |
| `SECOPS_MCP_URL` | None | Remote Streamable HTTP endpoint for `secops-mcp` (overrides `stdio`). |
| `CHRONICLE_REMOTE_MCP_URL` | None | Managed Google Cloud Remote MCP endpoint (`https://us-chronicle.googleapis.com/mcp` or `https://chronicle.us.rep.googleapis.com/mcp`). |
| `GTI_MCP_URL` | None | Remote Streamable HTTP endpoint for `gti-mcp`. |
| `SOAR_MCP_URL` | None | Remote Streamable HTTP endpoint for `secops-soar-mcp` (alias `SECOPS_SOAR_MCP_URL`). |
| `SCC_MCP_URL` | None | Remote Streamable HTTP endpoint for `scc-mcp`. |
| `MCP_REMOTE_USE_GCP_AUTH` | Auto (`None`) | Attach Google Cloud credentials via `GcpRemoteHeaderProvider` (`None` auto-enables for `.googleapis.com` and `.run.app` endpoints; set `True` or `False` to override). |
| `MCP_REMOTE_AUTH_MODE` | `oauth` | Token type for remote HTTP endpoints: `oauth` (access token), `id_token` (Cloud Run OIDC), or `none`. |
| `MCP_BEARER_TOKEN` | None | Static bearer token override when `MCP_REMOTE_USE_GCP_AUTH=False`. |
| `MCP_TOOL_NAME_PREFIX_ENABLED` | `False` | Prefix tools with `secops_`, `gti_`, `soar_`, `scc_`. |
| `MCP_USE_RESOURCES` | `True` | Expose MCP `2026-07-28` resources (`secops://`, `gti://`, `soar://`, `scc://`) to the ADK agent. |
| `MCP_TOOL_LIST_CACHE_TTL_SECONDS` | `300.0` | Client-side TTL cache in seconds for `tools/list` discovery (`0` disables caching). |
| `MCP_FILTER_BLOAT_FEED_TOOLS` | `True` | Exclude the 7 heavy feed-management schemas on managed Google SecOps OneMCP endpoints. |
| `ADK_CONFIRM_DESTRUCTIVE_TOOLS` | `False` | Require operator confirmation before executing tools marked `destructiveHint=True` (`N` in `.env.example`; set `ADK_CONFIRM_DESTRUCTIVE_TOOLS=true` or `Y` to enable). |
| `ADK_ELICITATION_POLICY` | `prompt` | Policy for MCP server `ctx.elicit(...)` requests: `prompt`, `accept`, `decline`, or `cancel`. |
| `ADK_MAX_TOOL_OUTPUT_SCHEMA_BYTES` | `4096` | Maximum serialized byte size for `response_json_schema` forwarded to the LLM (`0` strips all). |
| `MCP_HTTP_TIMEOUT` | `60.0` | Connection/request timeout in seconds for remote Streamable HTTP toolsets. |
| `MCP_SSE_READ_TIMEOUT` | `300.0` | Stream read timeout in seconds for remote Streamable HTTP toolsets. |
| `STDIO_PARAM_TIMEOUT` | `60.0` | Timeout in seconds for local `stdio` MCP subprocess initialization and calls. |
| `MINIMAL_LOGGING` | `False` | Suppress full LLM request payload logging in production environments. |

---

## Running the Web UI and FastAPI Server

```bash
ADK_PORT="8080"
uv run mcp-security-agent serve --port "$ADK_PORT"
```

Open `http://127.0.0.1:8080` in your browser to use the dark-mode SOC investigation console.

### REST and Streaming Endpoints

- `GET /`: Serves the dark-mode SOC investigation UI, including inline **Approve** and **Reject** confirmation buttons (as well as typed `yes` / `no` replies) when a tool with `destructiveHint=True` requests approval.
- `GET /healthz`: Liveness and readiness probe returning `{"status": "ok"}`.
- `GET /info`: Runtime metadata returning `version`, `model`, `location`, `project_id`, `user`, `tool_name_prefix_enabled`, `use_mcp_resources`, `confirm_destructive_tools`, `elicitation_policy`, `tools`, and per-server `transports` (`stdio`, `streamable-http`, or `disabled`).
- `POST /chat`: Accepts `{"message": "...", "prompt": "...", "session_id": "...", "user_id": "...", "confirmed": true, "confirmation_call_id": "..."}`. Returns synchronous JSON `{"response": "...", "session_id": "...", "confirmation_required": false, "tool_name": null, "interrupt_id": null}` (omitting intermediate `[Tool]` trace banners), or streams Server-Sent Events when `Accept: text/event-stream` is sent.
- `GET /chat?message=...`: Server-Sent Events (SSE) streaming endpoint accepting `message`, `session_id`, `user_id`, `confirmed`, and `confirmation_call_id`, emitting JSON `data:` frames with `event_type` values `content`, `tool_call`, `tool_response`, `confirmation_request`, and `error`, followed by a final `{"text": "Stream finished.", "last_msg": true, "session_id": "..."}` frame.

---

## Deploying to Google Cloud Run

Deploy from the repository root using the bundled [`Dockerfile`](./Dockerfile):

```bash
PROJECT_ID="my-secops-project"
CUSTOMER_ID="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
CLOUD_RUN_REGION="us-central1"
SERVICE_NAME="mcp-security-agent-service"

gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --project "$PROJECT_ID" \
  --region "$CLOUD_RUN_REGION" \
  --no-allow-unauthenticated \
  --set-env-vars="LOAD_SECOPS_MCP=Y,LOAD_SCC_MCP=Y,GOOGLE_GENAI_USE_VERTEXAI=True,GOOGLE_CLOUD_LOCATION=global,GOOGLE_MODEL=gemini-3.1-pro-preview,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,CHRONICLE_PROJECT_ID=$PROJECT_ID,CHRONICLE_CUSTOMER_ID=$CUSTOMER_ID"
```

> **Session Persistence Note:** By default, the FastAPI web server stores conversation and pending confirmation state in an in-memory `BoundedSessionService`. Multi-turn destructive-tool confirmation resume requires either a single worker (`--workers 1` with Cloud Run `--max-instances=1` or session affinity) or replacing the session backend with an external ADK `DatabaseSessionService` on horizontally scaled multi-instance Cloud Run deployments.

### Required IAM Roles

Grant least-privilege roles to the Cloud Run runtime service account:

- `roles/chronicle.viewer` (or `roles/chronicle.editor` when detection rule authoring is required)
- `roles/securitycenter.findingsViewer` (or `roles/securitycenter.findingsStateSetter` for `set_finding_mute`)
- `roles/cloudasset.viewer`
- `roles/aiplatform.user`

Authorized analysts can connect locally through the authenticated Cloud Run proxy:

```bash
PROJECT_ID="my-secops-project"
CLOUD_RUN_REGION="us-central1"
SERVICE_NAME="mcp-security-agent-service"

gcloud run services proxy "$SERVICE_NAME" \
  --project "$PROJECT_ID" \
  --region "$CLOUD_RUN_REGION"
```

---

## Integrating Custom MCP Servers

Reference sub-agent and custom server examples are located in [`sample_servers_to_integrate/`](./sample_servers_to_integrate/):

- Sample MCP servers: [`sample_servers_to_integrate/mcp_servers/`](./sample_servers_to_integrate/mcp_servers/) (`demo_idp` and `demo_xdr`)
- Sample ADK sub-agents: [`sample_servers_to_integrate/agents/`](./sample_servers_to_integrate/agents/) (`demo_idp_agent.py` and `demo_xdr_agent.py`)

**Note:** Keep runtime type annotations evaluated (do not add `from __future__ import annotations`) in ADK agent and toolset modules deployed to Vertex AI Reasoning Engine so `cloudpickle` can inspect call signatures at serialization time.

---

## Testing and Verification

Run the hermetic unit test suite from `run-with-google-adk/`:

```bash
cd run-with-google-adk
uv run --extra test pytest tests/ -v
```
