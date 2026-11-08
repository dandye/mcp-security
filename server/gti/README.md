# Google Threat Intelligence MCP Server

This is a Model Context Protocol (MCP `2026-07-28`, `mcp>=2.3.0`) server (`gti-mcp` `0.2.0`) for interacting with Google Threat Intelligence.
[MCP Info](https://modelcontextprotocol.io/introduction)

## MCP 2026-07-28 Capabilities

- **Transports**: Local `stdio` (default) and stateless single-exchange `streamable-http` (`--transport streamable-http --host 127.0.0.1 --port 8080`) with `server/discover`, `/healthz`, and `/readyz`.
- **Discovery Caching (`SEP-2549`) and OpenTelemetry**: `CacheHint` TTLs via `MCP_TOOLS_CACHE_TTL_MS` and `OpenTelemetryMiddleware` span instrumentation (`OTEL_EXPORTER_OTLP_ENDPOINT`).
- **Annotations and Typed Envelopes**: 100% `title` + `ToolAnnotations` coverage, typed `structuredContent`, and `is_error=True` operational failure signaling.
- **Resources and `ResourceLink` Compaction**: Exposes `gti://info/capabilities`, `gti://files/{file_hash}`, `gti://collections/{collection_id}`, and `gti://hunting-rulesets/{ruleset_id}` under `DEFAULT_RESOURCE_SECURITY`, plus `ResourceLink` summaries on `search_threats`.
- **SOC Prompts**: `@server.prompt()` workflows `enrich_and_pivot_ioc(indicator)` and `profile_threat_collection(collection_id)`.
- **Stateless MRTR Elicitation and Progress**: `AESGCMRequestStateCodec` confirmation (`MCP_ELICIT_DESTRUCTIVE`, `MCP_UNATTENDED_DESTRUCTIVE_POLICY`, `MCP_REQUEST_STATE_SECRET`) on `analyse_file` and `ctx.report_progress(...)` updates on `analyse_file` and `analyse_url`.
- **OAuth 2.1 Resource Server**: Optional RFC 9728 Protected Resource Metadata and JWT/JWKS validation (`MCP_OAUTH_ISSUER_URL`, `MCP_RESOURCE_SERVER_URL`, `MCP_OAUTH_JWKS_URL`, `MCP_OAUTH_JWKS_JSON`, `MCP_REQUIRED_SCOPES`).
- **Dark-Mode MCP App**: Interactive IOC verdict card at `ui://gti/ioc-verdict.html` (opt out via `--disable-apps` or `MCP_ENABLE_APPS=false`).
- **Official MCP Registry**: Manifest published at `server/gti/server.json` (`io.github.google/gti-mcp`).

**Rule Syntax Note:** Hunting rulesets in Google Threat Intelligence (`get_hunting_ruleset`, `gti://hunting-rulesets/{ruleset_id}`) use **standard YARA** for file and payload pattern matching, which is distinct from YARA-L 2.0 UDM event detection rules in Google Security Operations SIEM.

## Features

### Collections (Threats)

- **`get_collection_report(id)`**: Retrieves a specific collection report by its ID (e.g., `report--<hash>`, `threat-actor--<hash>`).
- **`get_entities_related_to_a_collection(id, relationship_name, limit=10)`**: Gets related entities (domains, files, IPs, URLs, other collections) for a given collection ID.
- **`search_threats(query, limit=5, order_by="relevance-")`**: Performs a general search for threats (collections) using GTI query syntax.
- **`search_campaigns(query, limit=10, order_by="relevance-")`**: Searches specifically for collections of type `campaign`.
- **`search_threat_actors(query, limit=10, order_by="relevance-")`**: Searches specifically for collections of type `threat-actor`.
- **`search_malware_families(query, limit=10, order_by="relevance-")`**: Searches specifically for collections of type `malware-family`.
- **`search_software_toolkits(query, limit=10, order_by="relevance-")`**: Searches specifically for collections of type `software-toolkit`.
- **`search_threat_reports(query, limit=10, order_by="relevance-")`**: Searches specifically for collections of type `report`.
- **`search_vulnerabilities(query, limit=10, order_by="relevance-")`**: Searches specifically for collections of type `vulnerability`.
- **`get_collection_timeline_events(id)`**: Retrieves curated timeline events for a collection.

### Files

- **`get_file_report(hash)`**: Retrieves a comprehensive analysis report for a file based on its MD5, SHA1, or SHA256 hash.
- **`get_entities_related_to_a_file(hash, relationship_name, limit=10)`**: Gets related entities (domains, IPs, URLs, behaviours, etc.) for a given file hash.
- **`get_file_behavior_report(file_behaviour_id)`**: Retrieves a specific sandbox behavior report for a file.
- **`get_file_behavior_summary(hash)`**: Retrieves a summary of all sandbox behavior reports for a file hash.

### Intelligence Search

- **`search_iocs(query, limit=10, order_by="last_submission_date-")`**: Searches for Indicators of Compromise (files, URLs, domains, IPs) using advanced GTI query syntax.

### Network Locations (Domains & IPs)

- **`get_domain_report(domain)`**: Retrieves a comprehensive analysis report for a domain.
- **`get_entities_related_to_a_domain(domain, relationship_name, limit=10)`**: Gets related entities for a given domain.
- **`get_ip_address_report(ip_address)`**: Retrieves a comprehensive analysis report for an IPv4 or IPv6 address.
- **`get_entities_related_to_an_ip_address(ip_address, relationship_name, limit=10)`**: Gets related entities for a given IP address.

### URLs

- **`get_url_report(url)`**: Retrieves a comprehensive analysis report for a URL.
- **`get_entities_related_to_an_url(url, relationship_name, limit=10)`**: Gets related entities for a given URL.

### Hunting

- **`get_hunting_ruleset`**: Get a Hunting Ruleset object from Google Threat Intelligence
- **`get_entities_related_to_a_hunting_ruleset`**:  Retrieve entities related to the the given Hunting Ruleset.

### Threat Profiles

- **`list_threat_profiles`**: List your Threat Profiles at Google Threat Intelligence.
- **`get_threat_profile(profile_id)`**: Get Threat Profile object.
- **`get_threat_profile_recommendations(profile_id, limit=10)`**: Returns the list of objects associated to the given Threat Profile.
- **`get_threat_profile_associations_timeline(profile_id)`**: Retrieves the associations timeline for the given Threat Profile.

## Configuration

### MCP Server Configuration

Add the following configuration to your MCP client's settings file:

**NOTE:** For OSX users, if you used [this one-liner](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer) to install uv, use the full path to the uv binary for the "command" value below, as uv will not be placed in the system path for Claude to use! For example: `/Users/yourusername/.local/bin/uv` instead of just `uv`.

```json
{
  "mcpServers": {
    "gti": {
      "command": "uv",
      "args": [
        "--env-file=/path/to/your/env",
        "--directory",
        "/path/to/the/repo/server/gti/gti_mcp",
        "run",
        "server.py"
      ],
      "env": {
        "VT_APIKEY": "${VT_APIKEY}"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Running Over Stateless `streamable-http`

```bash
GTI_KEY="your-gti-api-key"
MCP_HOST="127.0.0.1"
MCP_PORT="8080"

VT_APIKEY="$GTI_KEY" \
MCP_ELICIT_DESTRUCTIVE="true" \
gti_mcp --transport streamable-http --host "$MCP_HOST" --port "$MCP_PORT"
```

### Environment Variable Setup

Set up the `VT_APIKEY` environment variable in your system:

**For macOS/Linux:**
```bash
GTI_KEY="your-gti-api-key"
export VT_APIKEY="$GTI_KEY"
```
   
**For Windows PowerShell:**
```powershell
$Env:VT_APIKEY = "your-vt-api-key"
```

## License

Apache 2.0

## Development

The project is structured as follows:

- `gti_mcp/server.py`: Main MCP server implementation
- `gti_mcp/utils.py`: Utils to consume VirusTotal API using vt-py library.
- `gti_mcp/tools/`: Folder containing tools.
