# Google Threat Intelligence MCP Server

This is an MCP (Model Context Protocol) server for interacting with Google's
Threat Intelligence suite.
[MCP Info](https://modelcontextprotocol.io/introduction)

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

### DSPy RLM High-Signal File & Behavior Tools

These tools use [DSPy 3.4+ Recursive Language Models (`dspy.RLM`)](https://dspy.ai/current/diving-deeper/rlm/) to load large VirusTotal/GTI v3 JSON responses into a sandboxed Python REPL, filter benign OS/sandbox clutter, and return a compact structured intelligence dictionary with 100% verbatim cryptographic digests and `compression_metrics`:

- **`rlm_get_file_report(hash, query=None)`**: Distills `GET /files/{hash}` (1 VT API call), summarizing vendor consensus, GTI assessment, Code Insights, YARA/Sigma/IDS hits, and key relationships without dumping raw per-vendor or PE import tables.
- **`rlm_get_file_behavior_summary(hash, query=None)`**: Distills `GET /files/{hash}/behaviour_summary` (1 VT API call), filtering benign sandbox noise (`SyncRootManager`, `MSIExecute`, Fonts/Adobe/NLS reads) and extracting malicious process trees, command executions, persistence, and network C2.
- **`rlm_get_file_behavior_report(file_behaviour_id, query=None)`**: Distills `GET /file_behaviours/{file_behaviour_id}` (1 VT API call) for a single sandbox execution report.
- **`rlm_get_entities_related_to_a_file(hash, relationship_name, descriptors_only=False, limit=10, query=None)`**: Distills `GET /files/{hash}/{relationship_name}` (1 VT API call).
- **`rlm_investigate_file(hash, investigation_goal=None, max_api_calls=4)`**: Multi-call autonomous investigator that seeds the RLM REPL with `GET /files/{hash}` and binds `fetch_behavior_summary()`, `fetch_sandbox_report()`, `fetch_related_entities()`, and `fetch_collection_summary()` inside the sandbox so the RLM can pivot across static, dynamic, and attribution endpoints within `max_api_calls`.

Optional environment variables for `dspy.RLM`:
- `GTI_RLM_MODEL`: Root RLM model (defaults to `vertex_ai/gemini-3.8-flash` when `GOOGLE_CLOUD_PROJECT` is set, or `gemini/gemini-3.8-flash` when `GEMINI_API_KEY` is set; falls back to deterministic Python distillation when unconfigured).
- `GTI_RLM_SUB_MODEL`: Recursive worker model for `llm_query` / `llm_query_batched` (defaults to `vertex_ai/gemini-3.5-flash-lite` or `gemini/gemini-3.5-flash-lite`).
- `GTI_RLM_VERTEX_LOCATION`: Vertex AI endpoint location for `vertex_ai/*` models (default `global`).
- `GTI_RLM_MAX_ITERS`: Maximum REPL iterations per call (default `8`).
- `GTI_RLM_MAX_LLM_CALLS`: Maximum sub-LM calls per invocation (default `16`).
- `GTI_RLM_MAX_TOKENS`: Maximum output token budget per RLM turn (default `16384`).
- `GTI_RLM_TEMPERATURE`: Optional sampling temperature override (omitted by default on Gemini 3+ models).
- `GTI_RLM_REASONING_EFFORT`: Thinking budget effort for Gemini 3+ models (default `low`).

#### Live Compression Benchmarks (WannaCry SHA-256 `24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c`)

| Tool | Raw VT v3 Payload | RLM Distilled Output | Byte Reduction | VT API Calls | RLM REPL Turns |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `rlm_get_file_report` | `52,463 B` | `8,117 B` | **84.53%** | `1` | `3` |
| `rlm_get_file_behavior_summary` | `867,904 B` (`998,460 B` raw) | `13,073 B` | **98.49%** | `1` | `3` |
| `rlm_get_entities_related_to_a_file` (`contacted_domains`) | `116,330 B` | `2,996 B` | **97.42%** | `1` | `2` |
| `rlm_investigate_file` (`/files/{hash}` + `/behaviour_summary`) | `920,367 B` | `14,875 B` | **98.38%** | `2` | `2` |

#### Running the Examples

From the repository or worktree root (with `direnv` configured for Vertex AI and `VT_APIKEY` in `.env`):

```bash
WORKTREE_DIR="/path/to/mcp-security"
cd "$WORKTREE_DIR/server/gti"

# 1. Distill a full file report (includes all 76 vendor results inside the REPL)
direnv exec "$WORKTREE_DIR" python3 examples/rlm_file_triage_demo.py --tool report

# 2. Distill a ~1 MB multi-sandbox behaviour_summary
direnv exec "$WORKTREE_DIR" python3 examples/rlm_file_triage_demo.py --tool behavior

# 3. Distill full related entity objects (e.g. contacted_domains)
direnv exec "$WORKTREE_DIR" python3 examples/rlm_file_triage_demo.py --tool entities

# 4. Run an autonomous multi-call file investigation across static + dynamic endpoints
direnv exec "$WORKTREE_DIR" python3 examples/rlm_file_triage_demo.py --tool investigate

# 5. Run all 4 examples and write full JSON output
direnv exec "$WORKTREE_DIR" python3 examples/rlm_file_triage_demo.py --tool all --output-json /tmp/gti_rlm_examples.json
```

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

### Environment Variable Setup

Set up the `VT_APIKEY` environment variable in your system:

**For macOS/Linux:**
```bash
export VT_APIKEY="your-vt-api-key"
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
