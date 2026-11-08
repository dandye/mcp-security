# MCP 2026-07-28 Protocol and Security Capabilities

All four servers in `google/mcp-security` (`google-secops-mcp` `0.9.0`, `gti-mcp` `0.2.0`, `secops-soar-mcp` `0.3.0`, and `scc-mcp` `0.3.0`) implement the Model Context Protocol `2026-07-28` specification using `MCPServer` from `mcp>=2.3.0,<3.0.0`.

## Transport Modes (`stdio` and Stateless `streamable-http`)

Every server CLI (`secops_mcp`, `gti_mcp`, `secops_soar_mcp`, `scc_mcp`) accepts unified transport flags:

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `--transport {stdio,streamable-http,http}` | `MCP_TRANSPORT` | `stdio` | Select local subprocess `stdio` or HTTP transport. |
| `--host HOST` | `MCP_HOST` | `127.0.0.1` | Network bind address in `streamable-http` mode. |
| `--port PORT` | `MCP_PORT` | `8000` | Network listen port in `streamable-http` mode. |
| `--stateless-http / --no-stateless-http` | `MCP_STATELESS_HTTP` | `true` | Process each HTTP request independently for horizontal scaling. |

In `streamable-http` mode, each server exposes:

- `POST /mcp`: MCP `2026-07-28` Streamable HTTP endpoint supporting stateless single-exchange calls (including `server/discover`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, and `prompts/get` without a prior stateful session handshake).
- `GET /healthz`: Liveness probe returning HTTP `200` `{"status": "ok"}`.
- `GET /readyz`: Readiness probe returning HTTP `200` `{"status": "ready"}`.

DNS rebinding protection is enforced on local HTTP bindings; additional trusted `Host` and `Origin` values can be configured via `MCP_ALLOWED_HOSTS` and `MCP_ALLOWED_ORIGINS`.

### Stateless Single-Exchange Discovery Example

```bash
PROJECT_ID="my-secops-project"
CUSTOMER_ID="a1b2c3d4-e5f6-4321-abcd-ef1234567890"
MCP_HOST="127.0.0.1"
MCP_PORT="8080"
MCP_URL="http://$MCP_HOST:$MCP_PORT"

CHRONICLE_PROJECT_ID="$PROJECT_ID" \
CHRONICLE_CUSTOMER_ID="$CUSTOMER_ID" \
CHRONICLE_REGION="us" \
secops_mcp --transport streamable-http --host "$MCP_HOST" --port "$MCP_PORT" &
SERVER_PID="$!"

curl -fsS "$MCP_URL/readyz"

curl -fsS "$MCP_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -d '{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}'

kill "$SERVER_PID"
```

## Discovery Caching (`SEP-2549` `CacheHint`)

All four servers attach `SEP-2549` `CacheHint` metadata to discovery responses so MCP clients and gateways can cache `tools/list` and `server/discover` catalogs across turns:

- `MCP_TOOLS_CACHE_TTL_MS`: Cache TTL in milliseconds (for example `300000` for 5 minutes). Setting `0` disables cache hints.
- `MCP_TOOLS_CACHE_SCOPE` (`secops-soar-mcp`): Scope hint (`public` or `private`) reflecting tenant-scoped marketplace integration bindings.

## OpenTelemetry Distributed Tracing

Each server wraps its ASGI pipeline and MCP request dispatcher with `OpenTelemetryMiddleware`. When an OpenTelemetry SDK exporter is configured in the environment, incoming W3C `traceparent` and `tracestate` headers are extracted automatically and child spans are emitted for `tools/call`, `resources/read`, and `prompts/get`:

```bash
OTEL_ENDPOINT="http://127.0.0.1:4318"
SERVICE_NAME="secops-mcp"
MCP_PORT="8080"

OTEL_EXPORTER_OTLP_ENDPOINT="$OTEL_ENDPOINT" \
OTEL_SERVICE_NAME="$SERVICE_NAME" \
secops_mcp --transport streamable-http --port "$MCP_PORT"
```

## Tool Annotations, Typed `structuredContent`, and Error Signaling

Every tool across all four servers and all 313 SOAR marketplace integrations declares:

- Human-readable `title` metadata.
- `ToolAnnotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) enabling client harnesses to auto-approve read-only queries while gating state-mutating or external-upload actions.
- Typed `structuredContent` JSON envelopes alongside text content for deterministic downstream parsing.
- `is_error=True` on operational or validation failures so agents distinguish failed API calls from empty search results.

## Resources (`DEFAULT_RESOURCE_SECURITY`) and `ResourceLink` Compaction

All four servers register sandboxed resources protected by `DEFAULT_RESOURCE_SECURITY` and emit compact `ResourceLink` references on high-volume list tools so agents fetch full artifacts on demand:

| Server | Static Capabilities Resource | Templated Resource URIs | `ResourceLink` Tools |
| :--- | :--- | :--- | :--- |
| `google-secops-mcp` | `secops://info/capabilities` | `secops://rules/{rule_id}`, `secops://reference-lists/{name}`, `secops://parsers/{log_type}`, `secops://alerts/{alert_id}` | `list_security_rules`, `get_security_alerts` |
| `gti-mcp` | `gti://info/capabilities` | `gti://files/{file_hash}`, `gti://collections/{collection_id}`, `gti://hunting-rulesets/{ruleset_id}` | `search_threats` |
| `secops-soar-mcp` | `soar://info/capabilities` | `soar://cases/{case_id}`, `soar://cases/{case_id}/wall` | `list_cases` |
| `scc-mcp` | `scc://info/capabilities` | `scc://findings/{organization_id}/{finding_id}` | `top_vulnerability_findings` |

**YARA vs YARA-L 2.0 Note:** `secops://rules/{rule_id}` serves **YARA-L 2.0** UDM event detection rules for Google Security Operations SIEM, whereas `gti://hunting-rulesets/{ruleset_id}` serves **standard YARA** rulesets for file and payload pattern matching in Google Threat Intelligence.

## Parameterized SOC `@server.prompt()` Workflows

Eight reusable SOC prompts standardize multi-step analyst workflows:

| Server | Prompt Name | Arguments | Purpose |
| :--- | :--- | :--- | :--- |
| `google-secops-mcp` | `triage_siem_alert` | `alert_id`, `lookback_hours` | Correlate alert events, entity context, and related detections. |
| `google-secops-mcp` | `validate_yaral2_detection_rule` | `rule_text` | Validate YARA-L 2.0 syntax, UDM field usage, and retrohunt scope. |
| `google-secops-mcp` | `hunt_entity_timeline` | `entity_value`, `hours` | Reconstruct chronological UDM activity for a host, user, IP, or domain. |
| `gti-mcp` | `enrich_and_pivot_ioc` | `indicator` | Enrich a hash, domain, IP, or URL and pivot across GTI relationships. |
| `gti-mcp` | `profile_threat_collection` | `collection_id` | Summarize actor/campaign TTPs, timeline events, and associated indicators. |
| `secops-soar-mcp` | `investigate_soar_case` | `case_id` | Inspect case priority, grouped alerts, involved entities, and case wall notes. |
| `secops-soar-mcp` | `draft_case_closure_summary` | `case_id` | Draft an evidence-backed root cause and remediation closure note. |
| `scc-mcp` | `triage_cloud_finding_exposure` | `finding_id`, `organization_id` | Evaluate attack exposure score, CAI asset metadata, and remediation steps. |

## Stateless Multi-Round Tool Requests (MRTR) and Progress Reporting

High-impact mutations support MCP `2026-07-28` server-initiated elicitation (`ctx.elicit(...)`) backed by `AESGCMRequestStateCodec` so stateless HTTP replicas can suspend and resume confirmation rounds without sticky sessions:

- **Gated Tools**:
  - `google-secops-mcp`: `delete_security_rule`
  - `gti-mcp`: `analyse_file` (external file submission)
  - `secops-soar-mcp`: `close_case`
  - `scc-mcp`: `set_finding_mute`
- **Configuration**:
  - `--elicit-destructive` / `MCP_ELICIT_DESTRUCTIVE=true`: Require explicit operator confirmation before executing the gated action.
  - `--unattended-policy {allow,deny}` / `MCP_UNATTENDED_DESTRUCTIVE_POLICY`: Fallback behavior when the connected client does not advertise elicitation support (defaults to `allow` on local `stdio` and `deny` fail-closed on `streamable-http`).
  - `MCP_REQUEST_STATE_SECRET`: Shared 32-byte secret (base64 or hex) used by `AESGCMRequestStateCodec` across multi-replica deployments to authenticate and decrypt suspended MRTR state tokens.
- **Progress Streaming**: Long-running tools (`test_rule`, `export_udm_search_csv`, `analyse_file`, `analyse_url`) emit `ctx.report_progress(...)` notifications when invoked with a client `progressToken`.

## OAuth 2.1 Resource Server Mode

When deployed over `streamable-http`, each server can enforce OAuth 2.1 bearer token verification and serve RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource`):

| CLI Flag | Environment Variable | Description |
| :--- | :--- | :--- |
| `--oauth-issuer-url` | `MCP_OAUTH_ISSUER_URL` | Trusted OAuth 2.1 / OIDC issuer URL (enables Resource Server auth). |
| `--resource-server-url` | `MCP_RESOURCE_SERVER_URL` | Canonical RFC 8707 audience URL validated against token `aud` claims. |
| `--required-scopes` | `MCP_REQUIRED_SCOPES` | Comma-separated scopes required on incoming bearer tokens. |
| - | `MCP_OAUTH_JWKS_URL` | Explicit JWKS endpoint URL for asymmetric signature verification (`RS256`, `ES256`). |
| - | `MCP_OAUTH_JWKS_JSON` | Inline RFC 7517 JWKS JSON document for air-gapped or test deployments. |
| - | `MCP_OAUTH_JWKS_CACHE_TTL` | JWKS keyset cache TTL in seconds. |

```bash
ISSUER_URL="https://accounts.google.com"
RESOURCE_URL="https://secops-mcp.example.run.app/mcp"
REQUIRED_SCOPES="mcp:tools"
STATE_SECRET="$(openssl rand -base64 32)"
MCP_PORT="8080"

MCP_OAUTH_ISSUER_URL="$ISSUER_URL" \
MCP_RESOURCE_SERVER_URL="$RESOURCE_URL" \
MCP_REQUIRED_SCOPES="$REQUIRED_SCOPES" \
MCP_REQUEST_STATE_SECRET="$STATE_SECRET" \
MCP_ELICIT_DESTRUCTIVE="true" \
secops_mcp --transport streamable-http --host 0.0.0.0 --port "$MCP_PORT"
```

## Dark-Mode MCP Apps

Three interactive dark-mode HTML views are registered for hosts supporting the MCP Apps extension (`io.modelcontextprotocol/ui`):

- `ui://secops/entity-timeline.html` (`google-secops-mcp`): Chronological UDM entity and event timeline viewer.
- `ui://gti/ioc-verdict.html` (`gti-mcp`): Maliciousness ratio, threat actor attribution, and relationship summary card.
- `ui://scc/finding-card.html` (`scc-mcp`): Cloud posture severity, attack exposure score, and CAI remediation card.

Pass `--disable-apps` or set `MCP_ENABLE_APPS=false` to omit `ui://` resources and `_meta.ui` tool metadata in headless environments.

## Official MCP Registry `server.json` Manifests

Each server directory ships a schema-validated Official MCP Registry manifest (`https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`):

- `server/secops/server.json`: `io.github.google/google-secops-mcp` (`0.9.0`)
- `server/gti/server.json`: `io.github.google/gti-mcp` (`0.2.0`)
- `server/secops-soar/server.json`: `io.github.google/secops-soar-mcp` (`0.3.0`)
- `server/scc/server.json`: `io.github.google/scc-mcp` (`0.3.0`)
