# Google MCP Security Documentation

Welcome to the documentation for Google MCP Security. This repository provides Model Context Protocol (`2026-07-28`, `mcp>=2.3.0`) servers and a Google Agent Development Kit (`google-adk[mcp]>=2.13.0`) autonomous SOC agent for Google Cloud security products.

## Project Overview

This repository includes five components:

1. **Google Security Operations SIEM (`google-secops-mcp` `0.9.0`)** - UDM event search, alert triage, entity context, retrohunts, and YARA-L 2.0 detection rules
2. **Google Security Operations SOAR (`secops-soar-mcp` `0.3.0`)** - Case lifecycle management, alert grouping, and 313 SOAR marketplace integrations
3. **Google Threat Intelligence (`gti-mcp` `0.2.0`)** - IOC reputation, threat actor and campaign collections, sandbox behavior reports, and standard YARA file/payload hunting rulesets
4. **Google Cloud Security Command Center (`scc-mcp` `0.3.0`)** - Cloud posture findings, attack exposure scores, compliance filtering, and Cloud Asset Inventory lookups
5. **Autonomous SOC Agent (`mcp-security-agent` `0.3.0`)** - Prebuilt `google-adk>=2.13.0` CLI and FastAPI agent supporting `gemini-3.1-pro-preview` and `gemini-3-flash-preview` on Vertex AI `GOOGLE_CLOUD_LOCATION="global"`

## Quick Links

- **[Usage Guide](usage_guide.md)** - Client setup, local `stdio` and remote `streamable-http` configurations, and investigation examples for Google ADK, Gemini CLI, Goose, and Claude Desktop
- **[MCP 2026-07-28 Protocol Guide](mcp_v2_capabilities.md)** - Stateless Streamable HTTP, `SEP-2549` caching, OpenTelemetry, `ToolAnnotations`, resources, prompts, MRTR elicitation, OAuth 2.1 RS, and MCP Apps
- **[Development Guide](development_guide.md)** - Architecture, Official MCP Registry `server.json` synchronization, and testing
- **[GitHub Repository](https://github.com/google/mcp-security)** - Source code and issue tracker

## MCP Servers and Agents

- [**Remote MCP Server**](remote_server.md) - Managed Google Cloud MCP endpoint for Google Security Operations
- [**Autonomous SOC Agent (`run-with-google-adk`)**](https://github.com/google/mcp-security/blob/main/run-with-google-adk/README.md) - Prebuilt Google ADK v2.13 agent with CLI REPL, FastAPI Web UI, and multi-transport MCP toolsets
- [Google Security Operations SIEM Server](servers/secops_mcp.md) - Search UDM telemetry, triage alerts, and manage YARA-L 2.0 detection rules
- [Google Threat Intelligence (GTI) Server](servers/gti_mcp.md) - Enrich IOCs, profile threat actors, and inspect standard YARA hunting rulesets
- [Google Security Operations SOAR Server](servers/secops_soar_mcp.md) - Manage SOAR cases and orchestrate response actions
  - [SOAR Integrations](soar_integrations/index.md) - Catalog of documented SOAR marketplace integrations
- [Security Command Center (SCC) Server](servers/scc_mcp.md) - Prioritize cloud vulnerabilities and posture findings
- [Google SecOps Extension](google_secops_extension.md) - Adaptive SOC skills for Gemini CLI and Antigravity
- [Security Personas](personas/index.md) - Role-based workflows across SOC, CTI, Detection Engineering, and Cloud Security

## Contributing

Review the [CONTRIBUTING](https://github.com/google/mcp-security/blob/main/CONTRIBUTING) guide and the [Development Guide](development_guide.md) before submitting pull requests.

```{toctree}
:maxdepth: 2
:hidden:

usage_guide
mcp_v2_capabilities
remote_server
servers/secops_mcp
servers/gti_mcp
servers/secops_soar_mcp
servers/scc_mcp
soar_integrations/index
personas/index
google_secops_extension
development_guide
toc
```
