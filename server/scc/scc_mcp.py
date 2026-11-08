# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import asyncio
import base64
from collections.abc import Callable, Sequence
from dataclasses import dataclass
import hashlib
import hmac
import inspect
import json
import logging
import os
import re
import time
from typing import Any, Dict, Generic, List, Optional, TypeVar
from urllib.parse import urlparse, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from google.api_core import exceptions as google_exceptions
from google.cloud import asset_v1
from google.cloud import securitycenter_v2
from google.protobuf import json_format
import httpx2
from mcp.server.apps import Apps, EXTENSION_ID, ResourceCsp
from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.routes import build_resource_metadata_url, cors_middleware
from mcp.server.auth.settings import AuthSettings
from mcp.server.caching import CacheHint
from mcp.server.elicitation import (
    AcceptedElicitation,
    ElicitSchemaModelT,
    render_elicitation_schema,
)
from mcp.server.mcpserver import Context, DEFAULT_RESOURCE_SECURITY, MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ToolError
from mcp.server.request_state import (
    AESGCMRequestStateCodec,
    RequestStateSecurity,
    authenticated_principal,
)
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import ProtectedResourceMetadata
from mcp.types import (
    CallToolResult,
    ElicitRequest,
    ElicitRequestFormParams,
    InputRequiredResult,
    ResourceLink,
    TextContent,
    ToolAnnotations,
)
from pydantic import AnyHttpUrl, BaseModel, Field
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

try:
    from mcp.server._otel import OpenTelemetryMiddleware
except ImportError:  # pragma: no cover
    OpenTelemetryMiddleware = None  # type: ignore[assignment,misc]

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scc-mcp")
logger.setLevel(logging.INFO)

# Add handler to see uvicorn/fastapi logs if they use standard logging
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logging.getLogger().addHandler(handler)

PROTOCOL_VERSION = "2026-07-28"
DEFAULT_MAX_REQUEST_BODY_SIZE = 4_194_304
DEFAULT_SESSION_IDLE_TIMEOUT = 1800
DEFAULT_MAX_SESSIONS = 10_000
DEFAULT_TOOLS_CACHE_TTL_MS = 300_000
DEFAULT_PROMPTS_CACHE_TTL_MS = 300_000
DEFAULT_RESOURCES_CACHE_TTL_MS = 60_000
_WILDCARD_BIND_HOSTS = frozenset({"0.0.0.0", "::", "[::]", "*", ""})


def _resolve_tools_cache_ttl_ms(default: int = DEFAULT_TOOLS_CACHE_TTL_MS) -> int:
    """Resolve the tools/list SEP-2549 cache TTL in milliseconds."""
    raw_ttl = os.getenv("MCP_TOOLS_CACHE_TTL_MS")
    if raw_ttl is None or not raw_ttl.strip():
        return default
    try:
        parsed = int(raw_ttl.strip())
    except ValueError:
        logger.warning(
            "Invalid MCP_TOOLS_CACHE_TTL_MS value %r; using default %d ms",
            raw_ttl,
            default,
        )
        return default
    if parsed < 0:
        logger.warning(
            "Negative MCP_TOOLS_CACHE_TTL_MS value %d; using default %d ms",
            parsed,
            default,
        )
        return default
    return parsed


def _build_cache_hints() -> dict[str, CacheHint]:
    """Build SEP-2549 list freshness cache hints for SCC MCP."""
    return {
        "tools/list": CacheHint(
            ttl_ms=_resolve_tools_cache_ttl_ms(),
            scope="public",
        ),
        "prompts/list": CacheHint(
            ttl_ms=DEFAULT_PROMPTS_CACHE_TTL_MS,
            scope="public",
        ),
        "resources/list": CacheHint(
            ttl_ms=DEFAULT_RESOURCES_CACHE_TTL_MS,
            scope="private",
        ),
    }


def _is_otel_enabled() -> bool:
    """Return True unless MCP_OTEL_ENABLED is set to a falsy value."""
    return os.environ.get("MCP_OTEL_ENABLED", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _deduplicate_otel_middleware(server_instance: MCPServer) -> None:
    """Synchronize OpenTelemetryMiddleware on the low-level server with MCP_OTEL_ENABLED."""
    if OpenTelemetryMiddleware is None:
        return
    lowlevel = getattr(server_instance, "_lowlevel_server", None)
    mw_list = getattr(lowlevel, "middleware", None)
    if not isinstance(mw_list, list):
        return
    if not _is_otel_enabled():
        mw_list[:] = [
            item for item in mw_list if not isinstance(item, OpenTelemetryMiddleware)
        ]
        return
    seen_otel = False
    deduped: list[Any] = []
    for item in mw_list:
        if isinstance(item, OpenTelemetryMiddleware):
            if seen_otel:
                continue
            seen_otel = True
        deduped.append(item)
    if not seen_otel:
        deduped.insert(0, OpenTelemetryMiddleware())
    mw_list[:] = deduped


def _register_health_routes(server_instance: MCPServer) -> None:
    """Register /healthz and /readyz custom routes idempotently."""
    existing_routes = getattr(server_instance, "_custom_starlette_routes", [])
    existing_paths = {getattr(route, "path", None) for route in existing_routes}

    async def _probe_response(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "server": server_instance.name,
                "protocol_version": PROTOCOL_VERSION,
            }
        )

    if "/healthz" not in existing_paths:
        server_instance.custom_route("/healthz", methods=["GET"])(_probe_response)
    if "/readyz" not in existing_paths:
        server_instance.custom_route("/readyz", methods=["GET"])(_probe_response)


_EPHEMERAL_STATE_KEY: bytes = os.urandom(32)
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSY_ENV_VALUES = frozenset({"0", "false", "no", "off"})

SCC_FINDING_CARD_URI = "ui://scc/finding-card.html"

FINDING_CARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Google Cloud SCC Finding Posture View</title>
<style>
:root {
  color-scheme: dark;
  --bg-canvas: #0E1012;
  --bg-elevated: #15181C;
  --border-hairline: #262B33;
  --ink-primary: #ECEFF4;
  --ink-secondary: #9AA4B2;
  --focus-ring: #6FA8FF;
  --font-display: "Space Grotesk", "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, sans-serif;
  --font-sans: "Plus Jakarta Sans", "DM Sans", -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: "JetBrains Mono", "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  background: var(--bg-canvas);
  color: var(--ink-primary);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.5;
}
main {
  padding: 24px;
  max-width: 1100px;
  margin: 0 auto;
}
header {
  padding-bottom: 18px;
  border-bottom: 1px solid var(--border-hairline);
}
h1 {
  margin: 0 0 8px 0;
  font-family: var(--font-display);
  font-size: 20px;
  font-weight: 600;
  letter-spacing: -0.02em;
}
.posture-summary {
  margin: 0;
  color: var(--ink-secondary);
  font-size: 13px;
  max-width: 68ch;
  font-variant-numeric: tabular-nums;
}
h2 {
  margin: 28px 0 12px 0;
  font-family: var(--font-display);
  font-size: 15px;
  font-weight: 600;
  letter-spacing: -0.01em;
}
.idx {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--ink-secondary);
  margin-right: 8px;
  font-variant-numeric: tabular-nums;
}
.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 12px 0;
  border-bottom: 1px solid var(--border-hairline);
  align-items: center;
}
.filter-label {
  font-size: 12px;
  color: var(--ink-secondary);
}
button.filter-pill {
  min-height: 34px;
  padding: 6px 12px;
  background: var(--bg-elevated);
  color: var(--ink-secondary);
  border: 1px solid var(--border-hairline);
  border-radius: 4px;
  font-family: var(--font-sans);
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
}
button.filter-pill[aria-pressed="true"] {
  background: #1E2631;
  color: var(--ink-primary);
  border-color: var(--focus-ring);
}
button.filter-pill:focus-visible {
  outline: 2px solid var(--focus-ring);
  outline-offset: 2px;
}
table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}
th {
  padding: 10px 12px;
  font-size: 12px;
  font-weight: 600;
  color: var(--ink-secondary);
  border-bottom: 1px solid var(--border-hairline);
}
td {
  padding: 12px;
  font-size: 13px;
  border-bottom: 1px solid var(--border-hairline);
  vertical-align: top;
}
tr.finding-row {
  cursor: pointer;
}
tr.finding-row:hover {
  background: var(--bg-elevated);
}
tr.finding-row:focus-visible {
  outline: 2px solid var(--focus-ring);
  outline-offset: -2px;
  background: var(--bg-elevated);
}
.mono {
  font-family: var(--font-mono);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
  word-break: break-all;
}
.badge {
  display: inline-block;
  padding: 2px 8px;
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 600;
  border-radius: 4px;
  border: 1px solid var(--border-hairline);
  background: var(--bg-elevated);
}
.badge-CRITICAL { color: #FF8A80; background: #2A1414; border-color: #6E2825; }
.badge-HIGH { color: #FFB870; background: #291B0E; border-color: #6B441C; }
.badge-MEDIUM { color: #F6D365; background: #26200D; border-color: #665419; }
.badge-LOW { color: #7CC4FA; background: #10202E; border-color: #224E70; }
.badge-CLEAN { color: #6EE7B7; background: #0F261E; border-color: #1D5943; }
.remediation-plane {
  padding: 16px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-hairline);
  max-width: 72ch;
  font-size: 13px;
  color: var(--ink-primary);
}
.empty-state {
  padding: 20px 0;
  color: var(--ink-secondary);
  font-size: 13px;
  max-width: 65ch;
}
</style>
</head>
<body>
<main>
  <header>
    <h1>Security Command Center Exposure and Remediation</h1>
    <p class="posture-summary" id="posture-summary">Awaiting top_vulnerability_findings or get_finding_remediation output.</p>
  </header>

  <section aria-labelledby="sec-findings">
    <h2 id="sec-findings"><span class="idx">01</span>Prioritized SCC v2 Findings</h2>
    <div class="filter-bar" id="sev-bar" role="toolbar" aria-label="Filter SCC findings by severity"></div>
    <table>
      <thead>
        <tr>
          <th scope="col">Severity</th>
          <th scope="col">Exposure Score</th>
          <th scope="col">Category</th>
          <th scope="col">Affected GCP Resource</th>
          <th scope="col">Compliance Frameworks</th>
        </tr>
      </thead>
      <tbody id="findings-body">
        <tr><td colspan="5" class="empty-state">Run top_vulnerability_findings or get_finding_remediation to inspect cloud findings.</td></tr>
      </tbody>
    </table>
  </section>

  <section aria-labelledby="sec-rem">
    <h2 id="sec-rem"><span class="idx">02</span>Prescriptive Remediation Steps</h2>
    <div class="remediation-plane" id="remediation-box">Select or query a finding to review remediation guidance and Cloud Asset Inventory context.</div>
  </section>
</main>
<script>
(function () {
  var state = { items: [], sev: "ALL" };
  var nextId = 1;

  function normSev(raw) {
    var s = String(raw || "").toUpperCase();
    if (s.indexOf("CRIT") >= 0) return "CRITICAL";
    if (s.indexOf("HIGH") >= 0) return "HIGH";
    if (s.indexOf("MED") >= 0) return "MEDIUM";
    if (s.indexOf("LOW") >= 0) return "LOW";
    return "CLEAN";
  }

  function formatCompliance(f) {
    var comps = (f && f.compliances) || (f && f.finding_details && f.finding_details.compliances) || [];
    if (!Array.isArray(comps) || !comps.length) return "-";
    return comps.slice(0, 4).map(function (c) {
      var ids = Array.isArray(c.ids) ? c.ids.slice(0, 2).join(",") : "";
      return String(c.standard || "STD") + (ids ? (" " + ids) : "");
    }).join("; ");
  }

  function normalizePayload(p) {
    if (!p || typeof p !== "object") return [];
    if (Array.isArray(p.top_findings)) {
      return p.top_findings.map(function (f) {
        return {
          severity: normSev(f.severity),
          score: f.attackExposureScore != null ? Number(f.attackExposureScore).toFixed(1) : "N/A",
          category: String(f.category || "FINDING"),
          resource: String(f.resourceName || f.name || "-"),
          compliance: formatCompliance(f),
          nextSteps: String(f.nextSteps || f.description || "Review finding in SCC.")
        };
      });
    }
    if (p.finding_name || p.remediation_steps) {
      var fd = p.finding_details || {};
      var ae = (fd.attackExposure && fd.attackExposure.score != null) ? Number(fd.attackExposure.score).toFixed(1) : "N/A";
      return [{
        severity: normSev(fd.severity || "HIGH"),
        score: ae,
        category: String(fd.category || "REMEDIATION_TARGET"),
        resource: String(p.resource_name || fd.resourceName || p.finding_name || "-"),
        compliance: formatCompliance(fd),
        nextSteps: String(p.remediation_steps || fd.nextSteps || p.description || "-")
      }];
    }
    return [];
  }

  function renderFilterBar() {
    var bar = document.getElementById("sev-bar");
    bar.textContent = "";
    var lbl = document.createElement("span");
    lbl.className = "filter-label";
    lbl.textContent = "Severity:";
    bar.appendChild(lbl);
    ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].forEach(function (s) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "filter-pill";
      btn.setAttribute("aria-pressed", state.sev === s ? "true" : "false");
      btn.textContent = s;
      btn.addEventListener("click", function () {
        state.sev = s;
        renderFilterBar();
        renderRows();
      });
      bar.appendChild(btn);
    });
  }

  function renderRows() {
    var tbody = document.getElementById("findings-body");
    tbody.textContent = "";
    var filtered = state.items.filter(function (it) {
      return state.sev === "ALL" || it.severity === state.sev;
    });
    if (!filtered.length) {
      var trE = document.createElement("tr");
      var tdE = document.createElement("td");
      tdE.colSpan = 5; tdE.className = "empty-state";
      tdE.textContent = state.items.length ? "No findings match the selected severity." : "No active SCC findings returned.";
      trE.appendChild(tdE); tbody.appendChild(trE);
      notifyHeight();
      return;
    }
    filtered.forEach(function (it) {
      var tr = document.createElement("tr");
      tr.className = "finding-row";
      tr.tabIndex = 0;
      tr.setAttribute("tabindex", "0");
      var cSev = document.createElement("td");
      var b = document.createElement("span"); b.className = "badge badge-" + it.severity; b.textContent = it.severity;
      cSev.appendChild(b);
      var cScore = document.createElement("td"); cScore.className = "mono"; cScore.textContent = it.score;
      var cCat = document.createElement("td"); cCat.className = "mono"; cCat.textContent = it.category;
      var cRes = document.createElement("td"); cRes.className = "mono"; cRes.textContent = it.resource;
      var cCmp = document.createElement("td"); cCmp.textContent = it.compliance;
      tr.appendChild(cSev); tr.appendChild(cScore); tr.appendChild(cCat); tr.appendChild(cRes); tr.appendChild(cCmp);
      function selectRow() {
        document.getElementById("remediation-box").textContent = it.nextSteps;
      }
      tr.addEventListener("click", selectRow);
      tr.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          selectRow();
        }
      });
      tbody.appendChild(tr);
    });
    document.getElementById("remediation-box").textContent = filtered[0].nextSteps;
    notifyHeight();
  }

  function postRpc(msg) {
    if (window.parent && window.parent !== window) window.parent.postMessage(msg, "*");
  }
  function notifyHeight() {
    var h = Math.min(Math.max(document.documentElement.scrollHeight, 180), 800);
    postRpc({ jsonrpc: "2.0", method: "ui/notifications/size-changed", params: { height: h } });
  }

  window.addEventListener("message", function (ev) {
    if (ev.source !== window.parent) return;
    var d = ev.data;
    if (!d || d.jsonrpc !== "2.0") return;
    if (d.method === "ping" || d.method === "ui/resource-teardown") {
      postRpc({ jsonrpc: "2.0", id: d.id, result: {} });
      return;
    }
    if (d.id === 1 && d.result) {
      postRpc({ jsonrpc: "2.0", method: "ui/notifications/initialized", params: {} });
      notifyHeight();
      return;
    }
    if (d.method === "ui/notifications/tool-result" && d.params) {
      var p = d.params.structuredContent || null;
      if (!p && Array.isArray(d.params.content) && d.params.content[0] && d.params.content[0].text) {
        try { p = JSON.parse(d.params.content[0].text); } catch (_e) {}
      }
      if (p) {
        state.items = normalizePayload(p);
        document.getElementById("posture-summary").textContent =
          "Loaded " + state.items.length + " SCC v2 finding(s) prioritized by Attack Exposure Score.";
        renderFilterBar();
        renderRows();
      }
    }
  });

  renderFilterBar();
  postRpc({
    jsonrpc: "2.0",
    id: nextId++,
    method: "ui/initialize",
    params: {
      protocolVersion: "2026-01-26",
      appInfo: { name: "scc-finding-card", version: "0.3.0" },
      appCapabilities: {}
    }
  });
})();
</script>
</body>
</html>"""


def derive_request_state_key(secret: Optional[str] = None) -> bytes:
    """Derive a 32-byte AES-GCM key from MCP_REQUEST_STATE_SECRET or ephemeral fallback."""
    raw = secret if secret is not None else os.getenv("MCP_REQUEST_STATE_SECRET")
    if raw is None or not raw.strip():
        return _EPHEMERAL_STATE_KEY
    cleaned = raw.strip()
    if len(cleaned) == 64:
        try:
            decoded_hex = bytes.fromhex(cleaned)
            if len(decoded_hex) == 32:
                return decoded_hex
        except ValueError:
            pass
    padded = cleaned + "=" * (-len(cleaned) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded_b64 = decoder(padded.encode("ascii"))
            if len(decoded_b64) == 32:
                return decoded_b64
        except Exception:
            pass
    return hashlib.sha256(cleaned.encode("utf-8")).digest()


class EnvAwareAESGCMCodec:
    """RequestStateCodec backed by AESGCMRequestStateCodec using MCP_REQUEST_STATE_SECRET."""

    def __init__(self, secret: Optional[str] = None) -> None:
        self._explicit_secret = secret
        self._cached_key: Optional[bytes] = None
        self._cached_codec: Optional[AESGCMRequestStateCodec] = None

    def _codec(self) -> AESGCMRequestStateCodec:
        key_bytes = derive_request_state_key(self._explicit_secret)
        if self._cached_codec is None or self._cached_key != key_bytes:
            self._cached_key = key_bytes
            self._cached_codec = AESGCMRequestStateCodec([key_bytes])
        return self._cached_codec

    def seal(self, payload: bytes) -> str:
        return self._codec().seal(payload)

    def unseal(self, token: str) -> bytes:
        return self._codec().unseal(token)


def build_request_state_security(
    secret: Optional[str] = None,
) -> RequestStateSecurity:
    """Construct RequestStateSecurity with AES-GCM sealing and principal binding."""
    return RequestStateSecurity(
        codec=EnvAwareAESGCMCodec(secret=secret),
        bind_principal=authenticated_principal,
    )


class DestructiveConfirmation(BaseModel):
    """Confirmation schema for muting SCC findings."""

    confirm: bool = Field(
        description="Set true to confirm muting the SCC finding, or false to abort."
    )
    reason: str = Field(
        default="",
        description="Optional operator justification or risk acceptance note.",
    )


SchemaT = TypeVar("SchemaT", bound=BaseModel)


@dataclass
class ElicitationOutcome(Generic[SchemaT]):
    """Result of destructive-operation confirmation evaluation."""

    proceed: bool
    data: Optional[SchemaT] = None
    input_required: Optional[InputRequiredResult] = None
    cancelled_response: Optional[dict[str, Any]] = None


def is_elicit_destructive_enabled() -> bool:
    raw = os.getenv("MCP_ELICIT_DESTRUCTIVE", "false").strip().lower()
    return raw in _TRUTHY_ENV_VALUES


def _is_http_context(ctx: Context) -> bool:
    req_ctx = getattr(ctx, "_request_context", None)
    if req_ctx is not None and getattr(req_ctx, "request", None) is not None:
        return True
    env_transport = os.getenv("MCP_TRANSPORT", "").strip().lower()
    return env_transport in {"streamable-http", "http"}


def resolve_unattended_policy(*, is_http: bool) -> str:
    raw = os.getenv("MCP_UNATTENDED_DESTRUCTIVE_POLICY", "").strip().lower()
    if raw in {"allow", "deny"}:
        return raw
    return "deny" if is_http else "allow"


async def confirm_destructive_action(
    ctx: Optional[Context],
    *,
    action_name: str,
    message: str,
    schema: type[ElicitSchemaModelT] = DestructiveConfirmation,  # type: ignore[assignment]
) -> ElicitationOutcome[ElicitSchemaModelT]:
    """Gate destructive actions with stateless MRTR or backchannel elicitation."""
    if not is_elicit_destructive_enabled() or ctx is None:
        return ElicitationOutcome(proceed=True)

    input_responses = getattr(ctx, "input_responses", None) or {}
    if "confirm_destructive" in input_responses:
        raw_state = getattr(ctx, "request_state", None)
        if not isinstance(raw_state, str) or not raw_state:
            raise ToolError(
                f"Destructive confirmation response for '{action_name}' requires a valid server-minted requestState."
            )
        try:
            parsed_state = json.loads(raw_state)
        except ValueError as exc:
            raise ToolError("Invalid requestState payload.") from exc
        if (
            not isinstance(parsed_state, dict)
            or parsed_state.get("v") != 1
            or parsed_state.get("action") != action_name
        ):
            raise ToolError(
                f"requestState action mismatch for '{action_name}'."
            )
        resp = input_responses["confirm_destructive"]
        action = getattr(resp, "action", None)
        content = getattr(resp, "content", None) or {}
        if isinstance(resp, dict):
            action = resp.get("action")
            content = resp.get("content") or {}
        if action == "accept":
            parsed = schema.model_validate(content)
            if getattr(parsed, "confirm", False) is True:
                return ElicitationOutcome(proceed=True, data=parsed)
            return ElicitationOutcome(
                proceed=False,
                cancelled_response={
                    "status": "cancelled",
                    "cancelled": True,
                    "elicitation_action": "decline",
                    "action": action_name,
                    "message": (
                        f"Operation '{action_name}' was aborted because confirmation was false."
                    ),
                },
            )
        return ElicitationOutcome(
            proceed=False,
            cancelled_response={
                "status": "cancelled",
                "cancelled": True,
                "elicitation_action": str(action or "cancel"),
                "action": action_name,
                "message": f"Operation '{action_name}' cancelled by operator ({action}).",
            },
        )

    caps = getattr(ctx, "client_capabilities", None)
    supports_elicitation = bool(
        caps is not None and getattr(caps, "elicitation", None) is not None
    )
    if not supports_elicitation:
        is_http = _is_http_context(ctx)
        policy = resolve_unattended_policy(is_http=is_http)
        if policy == "deny":
            raise ToolError(
                f"Destructive operation '{action_name}' requires client elicitation support "
                "over streamable-http, or explicit MCP_UNATTENDED_DESTRUCTIVE_POLICY=allow."
            )
        return ElicitationOutcome(proceed=True)

    can_send_request = False
    try:
        can_send_request = bool(getattr(ctx.session, "can_send_request", False))
    except Exception:
        can_send_request = False

    if not can_send_request:
        return ElicitationOutcome(
            proceed=False,
            input_required=InputRequiredResult(
                input_requests={
                    "confirm_destructive": ElicitRequest(
                        params=ElicitRequestFormParams(
                            message=message,
                            requested_schema=render_elicitation_schema(schema),
                        )
                    )
                },
                request_state=json.dumps(
                    {"v": 1, "action": action_name},
                    separators=(",", ":"),
                ),
            ),
        )

    elicit_res = await ctx.elicit(message=message, schema=schema)
    if isinstance(elicit_res, AcceptedElicitation):
        if getattr(elicit_res.data, "confirm", False) is True:
            return ElicitationOutcome(proceed=True, data=elicit_res.data)
        return ElicitationOutcome(
            proceed=False,
            cancelled_response={
                "status": "cancelled",
                "cancelled": True,
                "elicitation_action": "decline",
                "action": action_name,
                "message": (
                    f"Operation '{action_name}' was aborted because confirmation was false."
                ),
            },
        )
    return ElicitationOutcome(
        proceed=False,
        cancelled_response={
            "status": "cancelled",
            "cancelled": True,
            "elicitation_action": str(getattr(elicit_res, "action", "cancel")),
            "action": action_name,
            "message": (
                f"Operation '{action_name}' cancelled by operator "
                f"({getattr(elicit_res, 'action', 'cancel')})."
            ),
        },
    )


elicit_destructive_confirmation = confirm_destructive_action


DEFAULT_JWKS_CACHE_TTL_SECONDS = 300.0
_JWKS_REFRESH_COOLDOWN_SECONDS = 5.0
_GOOGLE_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})
_GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
_GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
SCC_UI_TOOL_URIS: dict[str, str] = {
    "top_vulnerability_findings": SCC_FINDING_CARD_URI,
    "get_finding_remediation": SCC_FINDING_CARD_URI,
}


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _parse_compact_jwt_parts(
    token: str,
) -> Optional[tuple[dict[str, Any], dict[str, Any], bytes, bytes]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        sig = _b64url_decode(sig_b64)
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return header, payload, signing_input, sig


def _verify_signature_with_public_key(
    pub_key: Any,
    alg: str,
    signing_input: bytes,
    sig: bytes,
) -> bool:
    try:
        if alg == "RS256":
            if not isinstance(pub_key, rsa.RSAPublicKey):
                return False
            pub_key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return True
        if alg == "ES256":
            if not isinstance(pub_key, ec.EllipticCurvePublicKey) or not isinstance(
                pub_key.curve, ec.SECP256R1
            ):
                return False
            if len(sig) != 64:
                return False
            r_int = int.from_bytes(sig[:32], "big")
            s_int = int.from_bytes(sig[32:], "big")
            der_sig = encode_dss_signature(r_int, s_int)
            pub_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
            return True
    except Exception:
        return False
    return False


def _jwk_to_public_key(jwk: dict[str, Any]) -> Any:
    use = jwk.get("use")
    if use is not None and str(use) != "sig":
        return None
    kty = str(jwk.get("kty") or "")
    try:
        if kty == "RSA":
            n_b64 = jwk.get("n")
            e_b64 = jwk.get("e")
            if not isinstance(n_b64, str) or not isinstance(e_b64, str):
                return None
            n_int = int.from_bytes(_b64url_decode(n_b64), "big")
            e_int = int.from_bytes(_b64url_decode(e_b64), "big")
            return rsa.RSAPublicNumbers(e_int, n_int).public_key()
        if kty == "EC":
            if jwk.get("crv") != "P-256":
                return None
            x_b64 = jwk.get("x")
            y_b64 = jwk.get("y")
            if not isinstance(x_b64, str) or not isinstance(y_b64, str):
                return None
            x_bytes = _b64url_decode(x_b64)
            y_bytes = _b64url_decode(y_b64)
            if len(x_bytes) != 32 or len(y_bytes) != 32:
                return None
            x_int = int.from_bytes(x_bytes, "big")
            y_int = int.from_bytes(y_bytes, "big")
            return ec.EllipticCurvePublicNumbers(
                x_int, y_int, ec.SECP256R1()
            ).public_key()
    except Exception:
        return None
    return None


def _verify_jwt_against_jwks(
    header: dict[str, Any],
    payload: dict[str, Any],
    signing_input: bytes,
    sig: bytes,
    jwks_doc: dict[str, Any],
) -> tuple[Optional[dict[str, Any]], bool]:
    alg = str(header.get("alg") or "")
    if alg not in {"RS256", "ES256"}:
        return None, False
    keys = jwks_doc.get("keys")
    if not isinstance(keys, list) or not keys:
        return None, False
    token_kid = header.get("kid")
    if isinstance(token_kid, str) and token_kid:
        candidates = [
            k for k in keys if isinstance(k, dict) and k.get("kid") == token_kid
        ]
        if not candidates:
            return None, True
    else:
        candidates = [k for k in keys if isinstance(k, dict)]

    for jwk in candidates:
        jwk_alg = jwk.get("alg")
        if jwk_alg is not None and str(jwk_alg) != alg:
            continue
        pub_key = _jwk_to_public_key(jwk)
        if pub_key is not None and _verify_signature_with_public_key(
            pub_key, alg, signing_input, sig
        ):
            return payload, False
    return None, False


def _parse_max_age_seconds(cache_control: Optional[str]) -> Optional[float]:
    if not cache_control:
        return None
    for directive in cache_control.split(","):
        part = directive.strip().lower()
        if part.startswith("max-age="):
            try:
                val = float(part.split("=", 1)[1].strip().strip('"'))
                if val > 0:
                    return val
            except ValueError:
                pass
    return None


def _verify_compact_jwt(
    token: str,
    *,
    hs256_secret: Optional[str] = None,
    public_key_pem: Optional[str] = None,
    jwks: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, Any]]:
    """Verify a compact 3-part JWS (HS256, RS256, or ES256) and return decoded JSON claims."""
    parsed = _parse_compact_jwt_parts(token)
    if parsed is None:
        return None
    header, payload, signing_input, sig = parsed
    alg = str(header.get("alg") or "")

    if hs256_secret:
        if alg != "HS256":
            return None
        expected = hmac.new(
            hs256_secret.encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected, sig):
            return None
        return payload

    if public_key_pem:
        if alg not in {"RS256", "ES256"}:
            return None
        try:
            pub_key = serialization.load_pem_public_key(
                public_key_pem.encode("utf-8")
            )
        except Exception:
            return None
        if not _verify_signature_with_public_key(pub_key, alg, signing_input, sig):
            return None
        return payload

    if jwks is not None:
        verified, _ = _verify_jwt_against_jwks(
            header, payload, signing_input, sig, jwks
        )
        return verified

    return None


def _normalize_url(url: str) -> str:
    return str(url).strip().rstrip("/")


def _resolve_oidc_certs_url(issuer_url: str) -> str:
    """Resolve the default RFC 7517 JWKS URL for an OIDC issuer."""
    normalized = _normalize_url(issuer_url)
    if normalized in _GOOGLE_ISSUERS:
        return _GOOGLE_JWKS_URL
    return f"{normalized}/.well-known/jwks.json"


class GoogleOIDCTokenVerifier(TokenVerifier):
    """OAuth 2.1 / Google OIDC TokenVerifier enforcing issuer, expiry, and RFC 8707 audience.

    Note: `AuthSettings.required_scopes` is enforced downstream by `RequireAuthMiddleware`
    so missing OAuth scopes return HTTP 403 `insufficient_scope` rather than HTTP 401.
    """

    def __init__(
        self,
        *,
        issuer_url: str,
        resource_server_url: str,
        hs256_secret: Optional[str] = None,
        public_key_pem: Optional[str] = None,
        jwks_json: Optional[str | dict[str, Any]] = None,
        jwks_url: Optional[str] = None,
        jwks_cache_ttl: float = DEFAULT_JWKS_CACHE_TTL_SECONDS,
        jwks_http_client: Optional[httpx2.AsyncClient] = None,
        oidc_certs_url: Optional[str] = None,
        oidc_request: Optional[Any] = None,
        verify_callback: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self.issuer_url = str(issuer_url).strip()
        self.resource_server_url = str(resource_server_url).strip()
        self.hs256_secret = hs256_secret
        self.public_key_pem = public_key_pem
        self.jwks_json = jwks_json
        self.jwks_url = jwks_url
        self.jwks_cache_ttl = float(jwks_cache_ttl)
        self._jwks_http_client = jwks_http_client
        self._owned_jwks_client: Optional[httpx2.AsyncClient] = None
        self.oidc_certs_url = oidc_certs_url
        self._oidc_request = oidc_request
        self.verify_callback = verify_callback
        self._normalized_issuer = _normalize_url(self.issuer_url)
        self._normalized_resource = _normalize_url(self.resource_server_url)
        self._cached_inline_jwks_raw: Optional[str] = None
        self._cached_inline_jwks_doc: Optional[dict[str, Any]] = None
        self._jwks_lock = asyncio.Lock()
        self._cached_jwks_url: Optional[str] = None
        self._cached_jwks_doc: Optional[dict[str, Any]] = None
        self._cached_jwks_expires_at: float = 0.0
        self._last_jwks_fetch_at: float = 0.0

    def _resolve_inline_jwks(self) -> Optional[dict[str, Any]]:
        if isinstance(self.jwks_json, dict):
            return self.jwks_json
        raw = (
            self.jwks_json
            if isinstance(self.jwks_json, str)
            else os.getenv("MCP_OAUTH_JWKS_JSON", "")
        ).strip()
        if not raw:
            return None
        if raw == self._cached_inline_jwks_raw and self._cached_inline_jwks_doc is not None:
            return self._cached_inline_jwks_doc
        try:
            parsed = json.loads(raw)
        except ValueError:
            logger.warning("Invalid JSON in MCP_OAUTH_JWKS_JSON; rejecting token.")
            return {}
        if not isinstance(parsed, dict):
            return {}
        self._cached_inline_jwks_raw = raw
        self._cached_inline_jwks_doc = parsed
        return parsed

    async def _get_remote_jwks(
        self,
        jwks_url: str,
        *,
        force_refresh: bool = False,
    ) -> Optional[dict[str, Any]]:
        now_mono = time.monotonic()
        if (
            not force_refresh
            and self._cached_jwks_doc is not None
            and self._cached_jwks_url == jwks_url
            and now_mono < self._cached_jwks_expires_at
        ):
            return self._cached_jwks_doc

        async with self._jwks_lock:
            now_mono = time.monotonic()
            if (
                not force_refresh
                and self._cached_jwks_doc is not None
                and self._cached_jwks_url == jwks_url
                and now_mono < self._cached_jwks_expires_at
            ):
                return self._cached_jwks_doc

            client = self._jwks_http_client
            if client is None:
                if self._owned_jwks_client is None:
                    self._owned_jwks_client = httpx2.AsyncClient(timeout=10.0)
                client = self._owned_jwks_client

            try:
                resp = await client.get(jwks_url)
                if resp.status_code != 200:
                    logger.warning(
                        "Remote JWKS endpoint %s returned HTTP %d",
                        jwks_url,
                        resp.status_code,
                    )
                    return None
                doc = resp.json()
            except Exception as exc:
                logger.debug("Failed to fetch remote JWKS from %s: %s", jwks_url, exc)
                return None

            if not isinstance(doc, dict):
                return None

            ttl = _parse_max_age_seconds(resp.headers.get("cache-control"))
            if ttl is None:
                env_ttl = os.getenv("MCP_OAUTH_JWKS_CACHE_TTL", "").strip()
                if env_ttl:
                    try:
                        ttl = max(float(env_ttl), 1.0)
                    except ValueError:
                        ttl = self.jwks_cache_ttl
                else:
                    ttl = self.jwks_cache_ttl

            fetched_at = time.monotonic()
            self._cached_jwks_url = jwks_url
            self._cached_jwks_doc = doc
            self._cached_jwks_expires_at = fetched_at + ttl
            self._last_jwks_fetch_at = fetched_at
            return doc

    @property
    def certs_url(self) -> Optional[str]:
        explicit = (
            self.oidc_certs_url or os.getenv("MCP_OAUTH_CERTS_URL") or ""
        ).strip()
        return explicit or None

    def _issuer_matches(self, raw_iss: Any) -> bool:
        iss = _normalize_url(str(raw_iss or ""))
        if not iss:
            return False
        if self._normalized_issuer in _GOOGLE_ISSUERS:
            return iss in _GOOGLE_ISSUERS
        return iss == self._normalized_issuer

    async def _verify_via_remote_jwks(
        self,
        token: str,
        jwks_url: str,
    ) -> Optional[dict[str, Any]]:
        parsed = _parse_compact_jwt_parts(token)
        if parsed is None:
            return None
        header, payload, signing_input, sig = parsed
        if str(header.get("alg") or "") not in {"RS256", "ES256"}:
            return None

        jwks_doc = await self._get_remote_jwks(jwks_url, force_refresh=False)
        if jwks_doc is None:
            return None
        verified, unknown_kid = _verify_jwt_against_jwks(
            header, payload, signing_input, sig, jwks_doc
        )
        if (
            verified is None
            and unknown_kid
            and (time.monotonic() - self._last_jwks_fetch_at) >= _JWKS_REFRESH_COOLDOWN_SECONDS
        ):
            refreshed_doc = await self._get_remote_jwks(jwks_url, force_refresh=True)
            if refreshed_doc is not None:
                verified, _ = _verify_jwt_against_jwks(
                    header, payload, signing_input, sig, refreshed_doc
                )
        if verified is not None and not self._issuer_matches(verified.get("iss")):
            return None
        return verified

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        cleaned = token.strip()
        if not cleaned:
            return None

        claims: Optional[dict[str, Any]] = None
        if self.verify_callback is not None:
            raw_claims = self.verify_callback(cleaned)
            if inspect.isawaitable(raw_claims):
                raw_claims = await raw_claims
            if isinstance(raw_claims, AccessToken):
                if raw_claims.expires_at is not None and int(
                    raw_claims.expires_at
                ) <= int(time.time()):
                    return None
                if (
                    raw_claims.resource is not None
                    and _normalize_url(str(raw_claims.resource)) != self._normalized_resource
                ):
                    return None
                return raw_claims
            if isinstance(raw_claims, dict):
                claims = raw_claims
            else:
                return None
        else:
            secret = (
                self.hs256_secret or os.getenv("MCP_OAUTH_HS256_SECRET") or ""
            ).strip()
            pem = (
                self.public_key_pem or os.getenv("MCP_OAUTH_PUBLIC_KEY_PEM") or ""
            ).strip()
            inline_jwks = self._resolve_inline_jwks()
            remote_jwks = (
                self.jwks_url or os.getenv("MCP_OAUTH_JWKS_URL") or ""
            ).strip()
            if secret or pem:
                claims = _verify_compact_jwt(
                    cleaned,
                    hs256_secret=secret or None,
                    public_key_pem=pem or None,
                )
            elif inline_jwks is not None:
                claims = _verify_compact_jwt(cleaned, jwks=inline_jwks)
            elif remote_jwks:
                claims = await self._verify_via_remote_jwks(cleaned, remote_jwks)
            elif self._oidc_request is not None:
                claims = await self._verify_via_google_oidc(cleaned)
            else:
                certs_url = self.certs_url or _resolve_oidc_certs_url(self.issuer_url)
                claims = await self._verify_via_remote_jwks(cleaned, jwks_url=certs_url)

        if not isinstance(claims, dict):
            return None

        now = time.time()
        exp_raw = claims.get("exp")
        if exp_raw is None:
            return None
        try:
            exp_int = int(float(exp_raw))
        except (TypeError, ValueError):
            return None
        if exp_int <= int(now):
            return None

        nbf_raw = claims.get("nbf")
        if nbf_raw is not None:
            try:
                if float(nbf_raw) > now:
                    return None
            except (TypeError, ValueError):
                return None

        if not self._issuer_matches(claims.get("iss")):
            return None

        audiences: list[str] = []
        for field_name in ("aud", "resource"):
            val = claims.get(field_name)
            if isinstance(val, str) and val.strip():
                audiences.append(_normalize_url(val))
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item.strip():
                        audiences.append(_normalize_url(item))
        if self._normalized_resource not in audiences:
            return None

        scopes: list[str] = []
        raw_scope = claims.get("scope")
        if isinstance(raw_scope, str):
            scopes.extend(s for s in raw_scope.split() if s)
        raw_scp = claims.get("scp")
        if isinstance(raw_scp, str):
            scopes.extend(s for s in raw_scp.split() if s and s not in scopes)
        elif isinstance(raw_scp, list):
            for item in raw_scp:
                if isinstance(item, str) and item.strip() and item.strip() not in scopes:
                    scopes.append(item.strip())

        client_id = str(
            claims.get("azp")
            or claims.get("client_id")
            or claims.get("sub")
            or "authenticated-client"
        )
        subject = str(claims["sub"]) if claims.get("sub") is not None else None
        return AccessToken(
            token=cleaned,
            client_id=client_id,
            scopes=scopes,
            expires_at=exp_int,
            resource=self.resource_server_url,
            subject=subject,
            claims=claims,
        )

    def _resolve_oidc_certs_url(self) -> str:
        return self.certs_url or _resolve_oidc_certs_url(self.issuer_url)

    async def _verify_via_google_oidc(
        self,
        token: str,
    ) -> Optional[dict[str, Any]]:
        explicit_certs_url = self.certs_url
        if explicit_certs_url:
            certs_url = explicit_certs_url
        elif self._normalized_issuer in _GOOGLE_ISSUERS:
            certs_url = _GOOGLE_CERTS_URL
        else:
            certs_url = _resolve_oidc_certs_url(self.issuer_url)
        try:
            from google.auth.transport import requests as google_requests
            from google.oauth2 import id_token as google_id_token

            if self._oidc_request is None:
                self._oidc_request = google_requests.Request()
            verified = await asyncio.to_thread(
                google_id_token.verify_token,
                token,
                self._oidc_request,
                audience=None,
                certs_url=certs_url,
            )
            return dict(verified) if isinstance(verified, dict) else None
        except ImportError as exc:
            logger.warning(
                "google-auth or requests not installed for custom oidc_request; falling back to async JWKS verification: %s",
                exc,
            )
            fallback_url = explicit_certs_url or _resolve_oidc_certs_url(self.issuer_url)
            return await self._verify_via_remote_jwks(token, jwks_url=fallback_url)
        except Exception as exc:
            if exc.__class__.__name__ == "InvalidAudienceError":
                try:
                    certs = await asyncio.to_thread(
                        google_id_token._fetch_certs,
                        self._oidc_request,
                        certs_url,
                    )
                    if isinstance(certs, dict) and "keys" in certs:
                        return _verify_compact_jwt(token, jwks=certs)
                except Exception:
                    pass
            logger.debug("OIDC token signature verification failed: %s", exc)
            return None


def parse_required_scopes(
    required_scopes: Optional[Sequence[str] | str] = None,
) -> list[str]:
    if required_scopes is None:
        raw = os.getenv("MCP_REQUIRED_SCOPES", "")
        if not raw.strip():
            return []
        return [s.strip() for s in raw.replace(",", " ").split() if s.strip()]
    if isinstance(required_scopes, str):
        return [
            s.strip() for s in required_scopes.replace(",", " ").split() if s.strip()
        ]
    out: list[str] = []
    for item in required_scopes:
        for sub in str(item).replace(",", " ").split():
            if sub.strip():
                out.append(sub.strip())
    return out


def resolve_oauth_configuration(
    *,
    oauth_issuer_url: Optional[str] = None,
    resource_server_url: Optional[str] = None,
    required_scopes: Optional[Sequence[str] | str] = None,
    token_verifier: Optional[TokenVerifier] = None,
) -> tuple[Optional[AuthSettings], Optional[TokenVerifier]]:
    issuer = (
        oauth_issuer_url
        if oauth_issuer_url is not None
        else os.getenv("MCP_OAUTH_ISSUER_URL", "")
    ).strip()
    resource_url = (
        resource_server_url
        if resource_server_url is not None
        else os.getenv("MCP_RESOURCE_SERVER_URL", "")
    ).strip()
    if not issuer or not resource_url:
        return None, None

    scopes = parse_required_scopes(required_scopes)
    auth_settings = AuthSettings(
        issuer_url=AnyHttpUrl(issuer),
        resource_server_url=AnyHttpUrl(resource_url),
        required_scopes=scopes or None,
        validate_token_resource=True,
    )
    verifier = token_verifier or GoogleOIDCTokenVerifier(
        issuer_url=issuer,
        resource_server_url=resource_url,
    )
    return auth_settings, verifier


def extract_resource_host_patterns(resource_server_url: Optional[str]) -> list[str]:
    raw = (
        resource_server_url
        if resource_server_url is not None
        else os.getenv("MCP_RESOURCE_SERVER_URL", "")
    ).strip()
    if not raw:
        return []
    parsed = urlparse(raw)
    hostname = parsed.hostname
    if not hostname:
        return []
    if ":" in hostname and not hostname.startswith("["):
        bracketed = f"[{hostname}]"
        return [bracketed, f"{bracketed}:*"]
    out = [hostname, f"{hostname}:*"]
    if parsed.port:
        out.append(f"{hostname}:{parsed.port}")
    return out


def build_root_oauth_well_known_routes(
    auth_settings: AuthSettings,
    *,
    server_name: str,
) -> list[Route]:
    if auth_settings.resource_server_url is None:
        return []
    metadata_url = build_resource_metadata_url(auth_settings.resource_server_url)
    well_known_path = urlparse(str(metadata_url)).path
    if well_known_path == "/.well-known/oauth-protected-resource":
        return []

    metadata = ProtectedResourceMetadata(
        resource=auth_settings.resource_server_url,
        authorization_servers=[auth_settings.issuer_url],
        scopes_supported=auth_settings.required_scopes,
        resource_name=server_name,
    )
    handler = ProtectedResourceMetadataHandler(metadata)
    return [
        Route(
            "/.well-known/oauth-protected-resource",
            endpoint=cors_middleware(handler.handle, ["GET", "OPTIONS"]),
            methods=["GET", "OPTIONS"],
        )
    ]


def is_apps_enabled() -> bool:
    raw = os.getenv("MCP_ENABLE_APPS", "true").strip().lower()
    return raw not in _FALSY_ENV_VALUES


def build_strict_csp() -> ResourceCsp:
    return ResourceCsp(
        connect_domains=[],
        resource_domains=[],
        frame_domains=[],
        base_uri_domains=[],
    )


def _create_scc_apps() -> Apps:
    apps = Apps()
    apps.add_html_resource(
        SCC_FINDING_CARD_URI,
        FINDING_CARD_HTML,
        name="scc_finding_card",
        title="Google Cloud SCC Finding Exposure and Remediation",
        description=(
            "Interactive dark-mode Google Cloud Security Command Center v2 "
            "finding exposure score, resource posture, compliance controls, "
            "and prescriptive remediation view."
        ),
        csp=build_strict_csp(),
        prefers_border=True,
    )
    return apps


def build_scc_apps_extensions() -> list[Apps]:
    if not is_apps_enabled():
        return []
    return [_create_scc_apps()]


def sync_apps_state(server_instance: Any) -> bool:
    """Synchronize MCP Apps extension, ui:// resource, and tool _meta.ui state with MCP_ENABLE_APPS."""
    enabled = is_apps_enabled()
    ext_list = getattr(server_instance, "_extensions", None)
    lowlevel = getattr(server_instance, "_lowlevel_server", None)
    lowlevel_exts = getattr(lowlevel, "extensions", None)
    res_mgr = getattr(server_instance, "_resource_manager", None)
    res_map = getattr(res_mgr, "_resources", None)
    tool_mgr = getattr(server_instance, "_tool_manager", None)
    tool_map = getattr(tool_mgr, "_tools", None)

    if enabled:
        apps = _create_scc_apps()
        if isinstance(ext_list, list) and not any(
            getattr(e, "identifier", None) == EXTENSION_ID for e in ext_list
        ):
            ext_list.append(apps)
        if isinstance(lowlevel_exts, dict):
            lowlevel_exts[EXTENSION_ID] = apps.settings()
        if isinstance(res_map, dict):
            for binding in apps.resources():
                uri_key = str(binding.resource.uri)
                if uri_key not in res_map:
                    server_instance.add_resource(binding.resource)
        if isinstance(tool_map, dict):
            for tool_name, resource_uri in SCC_UI_TOOL_URIS.items():
                tool_obj = tool_map.get(tool_name)
                if tool_obj is not None:
                    merged_meta = dict(tool_obj.meta or {})
                    merged_meta["ui"] = {"resourceUri": resource_uri}
                    tool_obj.meta = merged_meta
    else:
        if isinstance(ext_list, list):
            ext_list[:] = [
                e
                for e in ext_list
                if getattr(e, "identifier", None) != EXTENSION_ID
            ]
        if isinstance(lowlevel_exts, dict):
            lowlevel_exts.pop(EXTENSION_ID, None)
        if isinstance(res_map, dict):
            for key in [k for k in list(res_map) if str(k).startswith("ui://")]:
                res_map.pop(key, None)
        if isinstance(tool_map, dict):
            for tool_name in SCC_UI_TOOL_URIS:
                tool_obj = tool_map.get(tool_name)
                if tool_obj is not None and isinstance(tool_obj.meta, dict):
                    cleaned = {
                        k: v for k, v in tool_obj.meta.items() if k != "ui"
                    }
                    tool_obj.meta = cleaned or None
    return enabled


def ui_tool_meta(resource_uri: str) -> Optional[dict[str, Any]]:
    if not is_apps_enabled():
        return None
    return {"ui": {"resourceUri": resource_uri}}


# Initialize MCPServer with rich 2026-07-28 discovery metadata, SEP-2549 cache hints, and OTel
mcp = MCPServer(
    name="scc-mcp",
    title="Google Cloud Security Command Center MCP Server",
    version="0.3.0",
    description=(
        "MCP server for Google Cloud Security Command Center (SCC v2) and "
        "Cloud Asset Inventory (CAI) posture findings, attack exposure "
        "prioritization, compliance control mapping, remediation guidance, "
        "and finding mute management."
    ),
    website_url="https://github.com/google/mcp-security",
    instructions=(
        "Use these tools to triage Google Cloud security posture and active "
        "threats in Security Command Center v2. Always supply either "
        "project_id or organization_id. Prioritize risk with "
        "top_vulnerability_findings (sorted by Attack Exposure Score) or "
        "query broadly with search_findings and search_findings_by_compliance, "
        "inspect full finding and Cloud Asset Inventory context with "
        "get_finding_details and get_finding_remediation, and update finding "
        "suppression state with set_finding_mute."
    ),
    cache_hints=_build_cache_hints(),
    resource_security=DEFAULT_RESOURCE_SECURITY,
    request_state_security=build_request_state_security(),
    extensions=build_scc_apps_extensions() or None,
    middleware=(
        [OpenTelemetryMiddleware()]
        if (OpenTelemetryMiddleware is not None and _is_otel_enabled())
        else None
    ),
)
_deduplicate_otel_middleware(mcp)
_register_health_routes(mcp)

# --- SCC Client Initialization ---
# The client automatically uses Application Default Credentials (ADC).
# Ensure ADC are configured in the environment where the server runs
# (e.g., by running `gcloud auth application-default login`).
try:
    scc_client = securitycenter_v2.SecurityCenterClient()
    logger.info("Successfully initialized Google Cloud Security Center v2 Client.")
except Exception as e:
    logger.error("Failed to initialize Security Center Client: %s", e, exc_info=True)
    # Depending on requirements, you might want to exit or prevent tool registration
    scc_client = None  # Indicate client is not available

# --- CAI Client Initialization ---
try:
    cai_client = asset_v1.AssetServiceClient()
    logger.info("Successfully initialized Google Cloud Asset Inventory Client.")
except Exception as e:
    logger.error("Failed to initialize Cloud Asset Inventory Client: %s", e, exc_info=True)
    cai_client = None  # Indicate client is not available

# --- Helper Function for Proto to Dict Conversion ---


def tool_error_result(error: str, **details: Any) -> CallToolResult:
    """Build a structured MCP error result with is_error=True."""
    payload: dict[str, Any] = {"error": error, **details}
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))],
        structured_content=payload,
        is_error=True,
    )


def proto_message_to_dict(message: Any) -> Dict[str, Any]:
    """Converts a protobuf message to a dictionary."""
    try:
        return json_format.MessageToDict(message._pb)
    except Exception as e:
        logger.error("Error converting protobuf message to dict: %s", e)
        return {"error": "Failed to serialize response part", "details": str(e)}


def _build_parent(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    location: str = "global",
) -> str:
    """Build the canonical SCC v2 parent resource path."""
    if organization_id:
        return f"organizations/{organization_id}/sources/-/locations/{location}"
    elif project_id:
        return f"projects/{project_id}/sources/-/locations/{location}"
    raise ValueError("Either project_id or organization_id must be provided.")


def _build_or_filter(field: str, value: str) -> str:
    """Build a SCC filter clause supporting OR-separated or comma-separated values."""
    parts = [
        p.strip().upper()
        for p in re.split(r"\s+or\s+|,", value, flags=re.IGNORECASE)
        if p.strip()
    ]
    if len(parts) > 1:
        return "(" + " OR ".join(f'{field}="{p}"' for p in parts) + ")"
    elif parts:
        return f'{field}="{parts[0]}"'
    return ""


# --- Security Command Center Tools ---

@mcp.tool(
    title="Search SCC Findings",
    annotations=ToolAnnotations(
        title="Search SCC Findings",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def search_findings(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    finding_class: Optional[str] = None,
    severity: Optional[str] = None,
    state: Optional[str] = "ACTIVE",
    category: Optional[str] = None,
    resource_name: Optional[str] = None,
    resource_type: Optional[str] = None,
    mute: Optional[str] = None,
    custom_filter: Optional[str] = None,
    max_findings: int = 50,
    location: str = "global",
    order_by: str = "event_time desc",
) -> dict[str, Any]:
    """Name: search_findings

    Description: Searches and lists ALL types of Security Command Center findings for a specific project
                 or organization with flexible filtering. Returns full finding details including descriptions,
                 remediation steps, severity, attack exposure, and all associated metadata. Supports filtering
                 by finding class (VULNERABILITY, THREAT, MISCONFIGURATION, OBSERVATION, SCC_ERROR,
                 POSTURE_VIOLATION, TOXIC_COMBINATION, SENSITIVE_DATA_RISK, CHOKEPOINT), severity,
                 state, category, resource name/type, and mute status.
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    finding_class (optional): Filter by finding class. Valid values: VULNERABILITY, THREAT,
        MISCONFIGURATION, OBSERVATION, SCC_ERROR, POSTURE_VIOLATION, TOXIC_COMBINATION,
        SENSITIVE_DATA_RISK, CHOKEPOINT. Can combine with OR (e.g., 'THREAT OR MISCONFIGURATION').
    severity (optional): Filter by severity. Valid values: CRITICAL, HIGH, MEDIUM, LOW.
        Can combine with OR (e.g., 'HIGH OR CRITICAL').
    state (optional): Filter by state. Valid values: ACTIVE, INACTIVE. Defaults to 'ACTIVE'.
        Set to None or empty string to search all states.
    category (optional): Filter by finding category (e.g., 'PUBLIC_BUCKET_ACL', 'XSS', 'SQL_INJECTION',
        'OPEN_FIREWALL', 'MFA_NOT_ENFORCED', etc.).
    resource_name (optional): Filter by the full resource name associated with the finding.
    resource_type (optional): Filter by resource type (e.g., 'google.compute.Instance', 'google.storage.Bucket').
    mute (optional): Filter by mute status. Valid values: MUTED, UNMUTED, UNDEFINED.
    custom_filter (optional): A raw SCC filter string that will be appended to any other filters using AND.
        Use this for advanced filtering not covered by other parameters.
    max_findings (optional): Maximum number of findings to return. Defaults to 50.
    location (optional): The Google Cloud location for SCC v2 (e.g., 'global', 'us-central1'). Defaults to 'global'.
    order_by (optional): Ordering of results. Defaults to 'event_time desc'. Other options include
        'severity desc', 'create_time desc'.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")

    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    filter_parts = []
    if state:
        filter_parts.append(f'state="{state}"')
    if finding_class:
        filter_parts.append(_build_or_filter("findingClass", finding_class))
    if severity:
        filter_parts.append(_build_or_filter("severity", severity))
    if category:
        filter_parts.append(f'category="{category}"')
    if resource_name:
        filter_parts.append(f'resourceName="{resource_name}"')
    if resource_type:
        filter_parts.append(f'resource.type="{resource_type}"')
    if mute:
        filter_parts.append(f'mute="{mute.upper()}"')
    if custom_filter:
        filter_parts.append(custom_filter)

    filter_str = " AND ".join(filter_parts) if filter_parts else ""
    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    logger.info("Searching findings for %s, filter: %s", target_label, filter_str)

    try:
        request_args = {
            "parent": parent,
            "filter": filter_str,
            "page_size": min(max_findings, 1000),
            "order_by": order_by,
        }

        response_pager = scc_client.list_findings(request=request_args)

        all_findings = []
        last_page = None
        for page in response_pager.pages:
            last_page = page
            for item in page.list_findings_results:
                if len(all_findings) >= max_findings:
                    break
                all_findings.append(proto_message_to_dict(item.finding))
            if len(all_findings) >= max_findings:
                break

        more_findings_may_exist = bool(
            last_page and getattr(last_page, "next_page_token", None)
        ) or len(all_findings) >= max_findings

        return {
            "findings": all_findings,
            "count": len(all_findings),
            "filter_applied": filter_str if filter_str else "No filter (all findings)",
            "more_findings_may_exist": more_findings_may_exist,
        }

    except google_exceptions.NotFound as e:
        logger.error("Target not found for search on %s: %s", parent, e)
        return tool_error_result(
            "Not Found",
            details=f"Could not find {target_label} or relevant resources. {str(e)}",
        )
    except google_exceptions.PermissionDenied as e:
        logger.error("Permission denied for search on %s: %s", parent, e)
        return tool_error_result("Permission Denied", details=str(e))
    except google_exceptions.InvalidArgument as e:
        logger.error("Invalid argument (check filter syntax?) for search on %s: %s", parent, e)
        return tool_error_result("Invalid Argument", details=str(e))
    except Exception as e:
        logger.error("An unexpected error occurred searching findings: %s", e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


@mcp.tool(
    title="Get SCC Finding Details",
    annotations=ToolAnnotations(
        title="Get SCC Finding Details",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def get_finding_details(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    location: str = "global",
    include_resource_details: bool = True,
) -> dict[str, Any]:
    """Name: get_finding_details

    Description: Gets the full details of a specific finding by its finding ID, including description,
                 remediation steps, severity, attack exposure, compliance information, MITRE ATT&CK data,
                 vulnerability details, and optionally the affected resource details from Cloud Asset
                 Inventory (CAI). Works for any finding class (VULNERABILITY, THREAT, MISCONFIGURATION, etc.).
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    finding_id (required): The ID of the finding to retrieve.
    location (optional): The Google Cloud location for SCC v2 (e.g., 'global', 'us-central1'). Defaults to 'global'.
    include_resource_details (optional): Whether to fetch additional resource details from Cloud Asset
        Inventory. Defaults to True.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")

    if not finding_id:
        return tool_error_result("finding_id is required.")

    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    if organization_id:
        finding_name_filter = f"organizations/{organization_id}/sources/-/locations/{location}/findings/{finding_id}"
    else:
        finding_name_filter = f"projects/{project_id}/sources/-/locations/{location}/findings/{finding_id}"

    filter_str = f'name="{finding_name_filter}"'
    logger.info("Getting details for finding %s in %s", finding_id, target_label)

    try:
        scc_request_args = {
            "parent": parent,
            "filter": filter_str,
            "page_size": 1,
        }

        response_pager = scc_client.list_findings(request=scc_request_args)
        first_finding = None
        page = next(iter(response_pager.pages), None)
        if page and page.list_findings_results:
            results = list(page.list_findings_results)
            if results:
                first_finding = results[0].finding

        if not first_finding:
            return tool_error_result(
                "Finding not found",
                details=f"No finding with ID '{finding_id}' found in {target_label}.",
            )

        finding_dict = proto_message_to_dict(first_finding)

        result = {
            "finding": finding_dict,
            "finding_id": finding_id,
        }

        # Optionally fetch resource details from CAI
        resource_name_from_finding = finding_dict.get("resourceName")
        if include_resource_details and resource_name_from_finding and cai_client:
            try:
                cai_scope = f"organizations/{organization_id}" if organization_id else f"projects/{project_id}"
                cai_request = asset_v1.SearchAllResourcesRequest(
                    scope=cai_scope,
                    query=f'name="{resource_name_from_finding}"',
                    page_size=1,
                )
                cai_response = cai_client.search_all_resources(request=cai_request)
                asset_result = next(iter(cai_response), None)
                if asset_result:
                    result["resource_details_cai"] = proto_message_to_dict(asset_result)
                    logger.info("Successfully fetched CAI details for %s", resource_name_from_finding)
                else:
                    result["resource_details_cai"] = {"warning": "Resource not found in CAI.", "resource_name": resource_name_from_finding}
            except Exception as cai_e:
                logger.error("Error fetching CAI details: %s", cai_e)
                result["resource_details_cai"] = {"error": "Failed to fetch resource details from CAI.", "details": str(cai_e)}
        elif include_resource_details and not cai_client:
            result["resource_details_cai"] = {"error": "Cloud Asset Inventory Client not initialized."}

        return result

    except google_exceptions.NotFound as e:
        logger.error("Resource not found: %s", e)
        return tool_error_result("Not Found", details=str(e))
    except google_exceptions.PermissionDenied as e:
        logger.error("Permission denied: %s", e)
        return tool_error_result("Permission Denied", details=str(e))
    except google_exceptions.InvalidArgument as e:
        logger.error("Invalid argument: %s", e)
        return tool_error_result("Invalid Argument", details=str(e))
    except Exception as e:
        logger.error("Unexpected error getting finding details: %s", e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


@mcp.tool(
    title="Search SCC Findings by Compliance",
    annotations=ToolAnnotations(
        title="Search SCC Findings by Compliance",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def search_findings_by_compliance(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    search_text: Optional[str] = None,
    compliance_standard: Optional[str] = None,
    compliance_version: Optional[str] = None,
    compliance_id: Optional[str] = None,
    severity: Optional[str] = None,
    state: Optional[str] = "ACTIVE",
    max_findings: int = 50,
    location: str = "global",
) -> dict[str, Any]:
    """Name: search_findings_by_compliance

    Description: Searches Security Command Center findings by compliance framework information (e.g., CIS benchmarks,
                 PCI DSS, NIST 800-53, ISO 27001) or by free-text search on finding descriptions and categories.
                 Use this tool when you have a compliance control name or description (e.g.,
                 'ServiceAccount should not have Admin privileges', 'Ensure log metric filter and alerts exist')
                 and want to find the corresponding SCC findings. Also supports filtering by specific compliance
                 standard name, version, and control ID.
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    search_text (optional): Free-text to search across finding descriptions, categories, and compliance standard names.
        Matches if any of these fields contain the search text (case-insensitive). Examples:
        'ServiceAccount should not have Admin privileges', 'log metric filter', 'MFA', 'firewall'.
    compliance_standard (optional): Filter by compliance standard name (case-insensitive partial match).
        Examples: 'CIS', 'CIS Google Cloud Platform', 'PCI DSS', 'NIST 800-53', 'ISO 27001'.
    compliance_version (optional): Filter by compliance standard version (exact match). Examples: '1.3.0', '2.0'.
    compliance_id (optional): Filter by compliance control ID (exact match). Examples: '1.5', '4.1', '6.2.1'.
    severity (optional): Pre-filter by severity at the API level. Valid values: CRITICAL, HIGH, MEDIUM, LOW.
        Supports OR (e.g., 'HIGH OR CRITICAL').
    state (optional): Filter by state. Valid values: ACTIVE, INACTIVE. Defaults to 'ACTIVE'.
        Set to None or empty string to search all states.
    max_findings (optional): Maximum number of matching findings to return. Defaults to 50.
    location (optional): The Google Cloud location for SCC v2. Defaults to 'global'.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")

    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    if not search_text and not compliance_standard and not compliance_id:
        return tool_error_result(
            "Missing parameters",
            details="At least one of search_text, compliance_standard, or compliance_id must be provided.",
        )

    filter_parts = []
    if state:
        filter_parts.append(f'state="{state}"')
    if severity:
        filter_parts.append(_build_or_filter("severity", severity))

    filter_str = " AND ".join(filter_parts) if filter_parts else ""
    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    logger.info(
        "Searching findings by compliance for %s, search_text=%r, standard=%r, version=%r, id=%r",
        target_label,
        search_text,
        compliance_standard,
        compliance_version,
        compliance_id,
    )

    try:
        # Fetch findings from the API (with API-level filters only)
        # We fetch more than max_findings because client-side filtering will reduce the count
        fetch_limit = max_findings * 10  # Overfetch to account for client-side filtering
        request_args = {
            "parent": parent,
            "filter": filter_str,
            "page_size": min(fetch_limit, 1000),
        }

        response_pager = scc_client.list_findings(request=request_args)

        matched_findings = []
        scanned_count = 0
        search_text_lower = search_text.lower() if search_text else None

        for page in response_pager.pages:
            for item in page.list_findings_results:
                if len(matched_findings) >= max_findings:
                    break
                if scanned_count >= fetch_limit:
                    break

                scanned_count += 1
                finding_dict = proto_message_to_dict(item.finding)

                # --- Client-side compliance filtering ---
                compliances = finding_dict.get("compliances", [])
                description = finding_dict.get("description", "")
                category = finding_dict.get("category", "")

                # Check compliance_standard filter
                if compliance_standard:
                    standard_lower = compliance_standard.lower()
                    has_standard = any(
                        standard_lower in c.get("standard", "").lower()
                        for c in compliances
                    )
                    if not has_standard:
                        continue

                # Check compliance_version filter
                if compliance_version:
                    has_version = any(
                        c.get("version") == compliance_version
                        for c in compliances
                    )
                    if not has_version:
                        continue

                # Check compliance_id filter
                if compliance_id:
                    has_id = any(
                        compliance_id in c.get("ids", [])
                        for c in compliances
                    )
                    if not has_id:
                        continue

                # Check search_text filter (matches description, category, or compliance standard names)
                if search_text_lower:
                    text_match = (
                        search_text_lower in description.lower()
                        or search_text_lower in category.lower()
                        or any(
                            search_text_lower in c.get("standard", "").lower()
                            for c in compliances
                        )
                    )
                    if not text_match:
                        continue

                # Finding passed all filters — enrich with compliance summary
                compliance_summary = []
                for c in compliances:
                    comp_entry = {
                        "standard": c.get("standard"),
                        "version": c.get("version"),
                        "ids": c.get("ids", []),
                    }
                    compliance_summary.append(comp_entry)

                finding_dict["compliance_summary"] = compliance_summary
                matched_findings.append(finding_dict)

            if len(matched_findings) >= max_findings or scanned_count >= fetch_limit:
                break

        return {
            "findings": matched_findings,
            "count": len(matched_findings),
            "scanned_count": scanned_count,
            "filters_applied": {
                "search_text": search_text,
                "compliance_standard": compliance_standard,
                "compliance_version": compliance_version,
                "compliance_id": compliance_id,
                "severity": severity,
                "state": state,
            },
            "more_findings_may_exist": scanned_count >= fetch_limit and len(matched_findings) >= max_findings,
        }

    except google_exceptions.NotFound as e:
        logger.error("Target not found for compliance search on %s: %s", parent, e)
        return tool_error_result("Not Found", details=f"Could not find {target_label}. {str(e)}")
    except google_exceptions.PermissionDenied as e:
        logger.error("Permission denied for compliance search on %s: %s", parent, e)
        return tool_error_result("Permission Denied", details=str(e))
    except google_exceptions.InvalidArgument as e:
        logger.error("Invalid argument for compliance search on %s: %s", parent, e)
        return tool_error_result("Invalid Argument", details=str(e))
    except Exception as e:
        logger.error("Unexpected error in compliance search: %s", e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


_ORG_FINDING_NAME_RE = re.compile(
    r"^organizations/([^/]+)/sources/[^/]+/(?:locations/[^/]+/)?findings/([^/]+)$"
)
_ANY_FINDING_ID_RE = re.compile(r"/findings/([^/]+)$")
_UNSAFE_RESOURCE_LINK_CHARS = frozenset("/\\%?#")


def _is_safe_resource_segment(value: str) -> bool:
    """Return True when value is safe to embed as a single ResourceLink URI segment."""
    if not value or value in {".", ".."} or ".." in value:
        return False
    return not any(
        ord(ch) < 32 or ord(ch) == 127 or ch.isspace() or ch in _UNSAFE_RESOURCE_LINK_CHARS
        for ch in value
    )


def _build_scc_finding_resource_links(
    findings: list[dict[str, Any]],
    organization_id: Optional[str] = None,
) -> list[ResourceLink]:
    """Build scc://findings/{organization_id}/{finding_id} ResourceLink items."""
    links: list[ResourceLink] = []
    seen_uris: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        raw_name = str(finding.get("name") or "").strip()
        resolved_org = (organization_id or "").strip()
        resolved_finding_id = ""

        if ".." not in raw_name:
            org_match = _ORG_FINDING_NAME_RE.match(raw_name)
            if org_match:
                resolved_org = org_match.group(1)
                resolved_finding_id = org_match.group(2)
            elif resolved_org and raw_name:
                id_match = _ANY_FINDING_ID_RE.search(raw_name)
                if id_match:
                    resolved_finding_id = id_match.group(1)
                elif "/" not in raw_name:
                    resolved_finding_id = raw_name

        if not (
            _is_safe_resource_segment(resolved_org)
            and _is_safe_resource_segment(resolved_finding_id)
        ):
            continue

        uri = f"scc://findings/{resolved_org}/{resolved_finding_id}"
        if uri in seen_uris:
            continue
        seen_uris.add(uri)

        category = str(finding.get("category") or resolved_finding_id)
        severity = str(finding.get("severity") or "UNKNOWN")
        links.append(
            ResourceLink(
                type="resource_link",
                uri=uri,
                name=f"{category} ({resolved_finding_id})",
                title=f"SCC {severity} Finding: {category}",
                description=(
                    f"Google Cloud SCC v2 finding {resolved_finding_id} "
                    f"in organization {resolved_org}"
                ),
                mime_type="application/json",
            )
        )
    return links


@mcp.tool(
    title="List Top SCC Vulnerability Findings",
    annotations=ToolAnnotations(
        title="List Top SCC Vulnerability Findings",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
    meta=ui_tool_meta(SCC_FINDING_CARD_URI),
)
async def top_vulnerability_findings(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    max_findings: int = 20,
    location: str = "global",
    ctx: Optional[Context] = None,
) -> dict[str, Any]:
    """Name: top_vulnerability_findings

    Description: Lists the top ACTIVE, HIGH or CRITICAL severity findings of class VULNERABILITY for a specific project
                 or organization, sorted by Attack Exposure Score (descending). Includes the Attack Exposure score in the
                 output if available. Aids prioritization for remediation.
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    max_findings (optional): The maximum number of findings to return. Defaults to 20.
    location (optional): The Google Cloud location for SCC v2 (e.g., 'global', 'us-central1'). Defaults to 'global'.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")

    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    filter_str = 'state="ACTIVE" AND findingClass="VULNERABILITY" AND (severity="HIGH" OR severity="CRITICAL")'

    # Fetch significantly more than max_findings so sort-by-attack-exposure is meaningful
    # across the full population, not just the first page.
    final_max = max(max_findings if max_findings and max_findings > 0 else 20, 1)
    fetch_size = min(final_max * 10, 1000)

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    logger.info(
        "Getting top vulnerability findings for %s, fetching up to %d for sorting",
        target_label,
        fetch_size,
    )

    try:
        response_pager = scc_client.list_findings(request={
            "parent": parent,
            "filter": filter_str,
            "page_size": min(fetch_size, 1000),
        })

        all_fetched = []
        for page in response_pager.pages:
            for item in page.list_findings_results:
                if len(all_fetched) >= fetch_size:
                    break
                finding_dict = proto_message_to_dict(item.finding)
                all_fetched.append({
                    "name": finding_dict.get("name"),
                    "category": finding_dict.get("category"),
                    "resourceName": finding_dict.get("resourceName"),
                    "severity": finding_dict.get("severity"),
                    "description": finding_dict.get("description", "No description provided."),
                    "nextSteps": finding_dict.get("nextSteps", ""),
                    "attackExposureScore": (
                        finding_dict.get("attackExposure") or {}
                    ).get("score"),
                })
            if len(all_fetched) >= fetch_size:
                break

        all_fetched.sort(
            key=lambda f: float(f["attackExposureScore"]) if f["attackExposureScore"] is not None else -1.0,
            reverse=True,
        )
        sorted_findings = all_fetched[:final_max]

        payload: dict[str, Any] = {
            "top_findings": sorted_findings,
            "count": len(sorted_findings),
            "fetched_for_sorting": len(all_fetched),
            "more_findings_exist_beyond_fetch_limit": len(all_fetched) >= fetch_size,
        }
        if ctx is not None:
            resource_links = _build_scc_finding_resource_links(
                sorted_findings,
                organization_id=organization_id,
            )
            return CallToolResult(  # type: ignore[return-value]
                content=[
                    TextContent(
                        type="text",
                        text=json.dumps(payload, indent=2),
                    ),
                    *resource_links,
                ],
                structured_content=payload,
            )
        return payload

    except google_exceptions.NotFound as e:
        logger.error("Target or resource not found for top findings on %s: %s", parent, e)
        return tool_error_result(
            "Not Found",
            details=f"Could not find {target_label} or relevant resources. {str(e)}",
        )
    except google_exceptions.PermissionDenied as e:
        logger.error("Permission denied for top findings on %s: %s", parent, e)
        return tool_error_result("Permission Denied", details=str(e))
    except google_exceptions.InvalidArgument as e:
        logger.error("Invalid argument (check filter syntax?) for top findings on %s: %s", parent, e)
        return tool_error_result("Invalid Argument", details=str(e))
    except Exception as e:
        logger.error("An unexpected error occurred getting top findings: %s", e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


@mcp.tool(
    title="Get SCC Finding Remediation",
    annotations=ToolAnnotations(
        title="Get SCC Finding Remediation",
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    ),
    meta=ui_tool_meta(SCC_FINDING_CARD_URI),
)
async def get_finding_remediation(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    resource_name: Optional[str] = None,
    category: Optional[str] = None,
    finding_id: Optional[str] = None,
    location: str = "global",
) -> dict[str, Any]:
    """Name: get_finding_remediation

    Description: Gets the remediation steps (nextSteps) for a specific finding within a project or organization,
                 along with details of the affected resource fetched from Cloud Asset Inventory (CAI).
                 The finding can be identified either by its resource_name and category (for ACTIVE findings)
                 or directly by its finding_id (regardless of state).
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    resource_name (optional): The full resource name associated with the finding.
        (e.g., '//container.googleapis.com/projects/my-project/locations/us-central1/clusters/my-cluster')
    category (optional): The category of the finding (e.g., 'GKE_SECURITY_BULLETIN').
    finding_id (optional): The ID of the finding to search for directly.
    location (optional): The Google Cloud location for SCC v2 (e.g., 'global', 'us-central1'). Defaults to 'global'.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")
    # Also check CAI client
    if not cai_client:
        return tool_error_result("Cloud Asset Inventory Client not initialized.")

    # Input validation
    if not resource_name and not category and not finding_id:
        return tool_error_result(
            "Missing required parameters",
            details="Either resource_name and category or finding_id must be provided.",
        )
    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    first_finding_result = None
    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    filter_str = ""

    try:
        if finding_id:
            # --- Use list_findings with name filter for finding_id (SCC v2 Client) ---
            # v2 finding names include /locations/{location}/
            if organization_id:
                finding_name_to_filter = f"organizations/{organization_id}/sources/-/locations/{location}/findings/{finding_id}"
            else:
                finding_name_to_filter = f"projects/{project_id}/sources/-/locations/{location}/findings/{finding_id}"
            filter_str = f'name="{finding_name_to_filter}"'
            logger.info("Attempting to list findings by name filter: %s", filter_str)
            scc_request_args = {
                "parent": parent,
                "filter": filter_str,
                "page_size": 1,  # Expecting only one result for a unique name
            }
        elif resource_name and category:
            # --- Use list_findings for resource/category ---
            filter_str = f'state="ACTIVE" AND resourceName="{resource_name}" AND category="{category}"'
            logger.info(
                "Attempting to list active findings for resource: %s, category: %s",
                resource_name,
                category,
            )
            scc_request_args = {
                "parent": parent,
                "filter": filter_str,
                "page_size": 2,  # Fetch 2 to detect multiple matches
            }
        else:
            # This case should be caught by initial validation, but safety check.
            return tool_error_result("Invalid Arguments", details="No valid criteria provided.")

        # --- Perform the list_findings call ---
        logger.debug(
            "Executing list_findings with parent=%r, filter=%r, page_size=%d",
            parent,
            filter_str,
            scc_request_args["page_size"],
        )
        scc_response_pager = scc_client.list_findings(request=scc_request_args)

        results = []
        page = next(iter(scc_response_pager.pages), None)
        if page and page.list_findings_results:
            results = list(page.list_findings_results)

        # --- Process results ---
        if len(results) >= 1:
            if len(results) > 1 and resource_name:  # Warning only needed for resource/category search
                logger.warning(
                    "Multiple (%d) ACTIVE findings found for resource %r and category %r. Using the first one.",
                    len(results),
                    resource_name,
                    category,
                )
            first_finding_result = results[0].finding
            logger.info("Successfully retrieved finding matching criteria.")
        else:
            first_finding_result = None

        # --- Process the found finding (if any) ---
        if first_finding_result:
            finding_dict = proto_message_to_dict(first_finding_result)
            remediation_steps = finding_dict.get("nextSteps", "No remediation steps provided for this finding.")
            finding_name = finding_dict.get("name")
            description = finding_dict.get("description", "No description available.")
            resource_name_from_finding = finding_dict.get("resourceName")

            logger.info("Processing finding %s. Fetching CAI details...", finding_name)
            asset_details = None
            if resource_name_from_finding:
                try:
                    cai_scope = f"organizations/{organization_id}" if organization_id else f"projects/{project_id}"
                    cai_request = asset_v1.SearchAllResourcesRequest(
                        scope=cai_scope,
                        query=f'name="{resource_name_from_finding}"',
                        page_size=1,
                    )
                    logger.debug(
                        "Attempting CAI search with scope=%r, query=%r, page_size=1",
                        cai_scope,
                        cai_request.query,
                    )
                    cai_response = cai_client.search_all_resources(request=cai_request)
                    asset_result = next(iter(cai_response), None)
                    if asset_result:
                        asset_details = proto_message_to_dict(asset_result)
                        logger.info("Successfully fetched CAI details for %s", resource_name_from_finding)
                    else:
                        logger.warning(
                            "Could not find asset details in CAI for resource: %s within scope %s",
                            resource_name_from_finding,
                            cai_scope,
                        )
                        asset_details = {"error": "Resource details not found in CAI.", "resource_name": resource_name_from_finding}
                except google_exceptions.PermissionDenied as cai_e:
                    logger.error(
                        "Permission denied fetching CAI details for %s: %s",
                        resource_name_from_finding,
                        cai_e,
                    )
                    asset_details = {"error": "Permission Denied fetching resource details from CAI.", "details": str(cai_e)}
                except google_exceptions.InvalidArgument as cai_e:
                    logger.error(
                        "Invalid argument fetching CAI details for %s: %s",
                        resource_name_from_finding,
                        cai_e,
                    )
                    asset_details = {"error": "Invalid Argument fetching resource details from CAI.", "details": str(cai_e)}
                except Exception as cai_e:
                    logger.error(
                        "An unexpected error occurred fetching CAI details for %s: %s",
                        resource_name_from_finding,
                        cai_e,
                        exc_info=True,
                    )
                    asset_details = {"error": "An unexpected error occurred fetching resource details from CAI.", "details": str(cai_e)}
            else:
                logger.warning("Finding %s does not have a resourceName, cannot fetch CAI details.", finding_name)
                asset_details = {"warning": "Finding does not have an associated resource name."}

            return {
                "remediation_steps": remediation_steps,
                "finding_name": finding_name,
                "description": description,
                "resource_name": resource_name_from_finding,
                "resource_details_cai": asset_details,
                "finding_details": finding_dict,
            }
        else:
            # --- Handle case where no finding was found ---
            search_criteria = f"finding ID '{finding_id}' (using name filter)" if finding_id else f"active finding for resource '{resource_name}' and category '{category}'"
            logger.warning(
                "No finding found matching %s in %s. Filter: %s",
                search_criteria,
                target_label,
                filter_str,
            )
            return tool_error_result(
                "Finding not found",
                message=f"No finding found matching the specified criteria ({search_criteria}).",
            )

    # --- Outer Exception Handling ---
    except google_exceptions.NotFound as e:
        logger.error(
            "Resource not found during SCC operation for %s (finding_id: %s, resource: %s): %s",
            target_label,
            finding_id,
            resource_name,
            e,
        )
        return tool_error_result(
            "Not Found",
            details=f"Could not find {target_label} or related SCC resources. {str(e)}",
        )
    except google_exceptions.PermissionDenied as e:
        logger.error(
            "Permission denied during SCC operation for %s (finding_id: %s, resource: %s): %s",
            target_label,
            finding_id,
            resource_name,
            e,
        )
        return tool_error_result("Permission Denied", details=str(e))
    except google_exceptions.InvalidArgument as e:
        logger.error(
            "Invalid argument during SCC operation for %s (finding_id: %s, resource: %s): %s",
            target_label,
            finding_id,
            resource_name,
            e,
        )
        return tool_error_result(
            "Invalid Argument",
            details=f"Check SCC filter syntax or input parameters. {str(e)}",
        )
    except Exception as e:
        # General fallback, including potential CAI client errors not caught inside
        logger.error("An unexpected error occurred in get_finding_remediation: %s", e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


@mcp.tool(
    title="Set SCC Finding Mute State",
    annotations=ToolAnnotations(
        title="Set SCC Finding Mute State",
        read_only_hint=False,
        destructive_hint=True,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
async def set_finding_mute(
    project_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    mute: Optional[str] = None,
    location: str = "global",
    ctx: Optional[Context] = None,
) -> dict[str, Any]:
    """Name: set_finding_mute

    Description: Mutes or unmutes a specific Security Command Center finding. Muted findings are
                 hidden from default views but remain in the system for compliance purposes. Use
                 MUTED to suppress known/accepted risks and UNMUTED to resurface them.
    Parameters:
    project_id (optional): The Google Cloud project ID (e.g., 'my-gcp-project'). Either project_id or organization_id must be provided.
    organization_id (optional): The Google Cloud organization ID (e.g., '123456789'). When provided, queries findings across all projects in the organization.
    finding_id (required): The ID of the finding to mute or unmute.
    mute (required): The mute state to set. Valid values: MUTED, UNMUTED.
    location (optional): The Google Cloud location for SCC v2. Defaults to 'global'.
    """
    if not scc_client:
        return tool_error_result("Security Center Client not initialized.")

    if not finding_id:
        return tool_error_result("finding_id is required.")

    if not project_id and not organization_id:
        return tool_error_result("Either project_id or organization_id must be provided.")

    if not mute:
        return tool_error_result("mute parameter is required.")

    mute_upper = mute.upper()
    if mute_upper not in ("MUTED", "UNMUTED"):
        return tool_error_result("Invalid mute value", details="Must be 'MUTED' or 'UNMUTED'.")

    # set_mute requires the canonical finding name (with actual source ID, not wildcard).
    # Look up the finding first via list_findings to resolve the full name.
    try:
        parent = _build_parent(project_id=project_id, organization_id=organization_id, location=location)
    except ValueError as e:
        return tool_error_result(str(e))

    target_label = f"organization '{organization_id}'" if organization_id else f"project '{project_id}'"
    if organization_id:
        finding_path = f"organizations/{organization_id}/sources/-/locations/{location}/findings/{finding_id}"
    else:
        finding_path = f"projects/{project_id}/sources/-/locations/{location}/findings/{finding_id}"
    filter_str = f'name="{finding_path}"'

    if mute_upper == "MUTED":
        outcome = await confirm_destructive_action(
            ctx,
            action_name="set_finding_mute",
            message=f"Confirm muting Google Cloud SCC finding '{finding_path}'.",
        )
        if outcome.input_required is not None:
            return outcome.input_required  # type: ignore[return-value]
        if not outcome.proceed:
            return {
                **(outcome.cancelled_response or {}),
                "finding_path": finding_path,
                "finding_id": finding_id,
                "muted": False,
            }

    logger.info("Resolving finding %s for mute operation in %s", finding_id, target_label)

    try:
        response_pager = scc_client.list_findings(request={
            "parent": parent,
            "filter": filter_str,
            "page_size": 1,
        })
        page = next(iter(response_pager.pages), None)
        finding = None
        if page and page.list_findings_results:
            finding = list(page.list_findings_results)[0].finding

        if not finding:
            return tool_error_result(
                "Finding not found",
                details=f"No finding with ID '{finding_id}' in {target_label}.",
            )

        full_name = finding.name
        mute_enum = securitycenter_v2.Finding.Mute[mute_upper]

        request = securitycenter_v2.SetMuteRequest(
            name=full_name,
            mute=mute_enum,
        )
        updated = scc_client.set_mute(request=request)

        return {
            "success": True,
            "finding_name": full_name,
            "mute_state": mute_upper,
            "finding": proto_message_to_dict(updated),
        }

    except google_exceptions.NotFound as e:
        logger.error("Finding not found: %s", e)
        return tool_error_result("Not Found", details=str(e))
    except google_exceptions.PermissionDenied as e:
        logger.error("Permission denied setting mute: %s", e)
        return tool_error_result("Permission Denied", details=str(e))
    except KeyError:
        return tool_error_result(
            "Invalid mute value",
            details=f"'{mute}' is not a valid Mute enum value. Use MUTED or UNMUTED.",
        )
    except Exception as e:
        logger.error("Unexpected error setting mute on %s: %s", finding_id, e, exc_info=True)
        return tool_error_result("An unexpected error occurred", details=str(e))


# --- MCP Resources and Prompts ---


@mcp.resource(
    "scc://info/capabilities",
    name="scc_capabilities",
    title="Google Cloud Security Command Center Capabilities",
    description=(
        "Static catalog summarizing Google Cloud Security Command Center "
        "(SCC v2) MCP server version, posture and vulnerability prioritization "
        "capabilities, resource URI templates, and cloud exposure prompts."
    ),
    mime_type="application/json",
)
def scc_capabilities() -> dict[str, Any]:
    """Return static Google Cloud Security Command Center server capabilities."""
    return {
        "server": mcp.name,
        "version": "0.3.0",
        "protocol_version": PROTOCOL_VERSION,
        "platform": "Google Cloud Security Command Center (SCC v2) & Cloud Asset Inventory (CAI)",
        "capabilities": [
            "SCC v2 active threat, vulnerability, misconfiguration, and toxic combination search",
            "Attack Exposure Score ranking for top vulnerability findings",
            "CIS, PCI DSS, NIST 800-53, and ISO 27001 compliance control mapping",
            "Cloud Asset Inventory (CAI) resource metadata enrichment and remediation steps",
            "Finding mute state lifecycle management",
        ],
        "resource_templates": [
            "scc://findings/{organization_id}/{finding_id}",
        ],
        "prompts": [
            "triage_cloud_finding_exposure",
        ],
    }


_UNSAFE_RESOURCE_SEGMENT_RE = re.compile(r'[\s/\\?#\{\}"\'%\x00-\x1f\x7f]')


def _validate_scc_resource_segment(param_name: str, value: str) -> str:
    """Validate a single decoded SCC URI template segment against injection characters."""
    cleaned = value.strip()
    if not cleaned or cleaned in {".", ".."} or _UNSAFE_RESOURCE_SEGMENT_RE.search(value):
        raise ResourceError(f"Invalid resource parameter '{param_name}'.")
    return cleaned


@mcp.resource(
    "scc://findings/{organization_id}/{finding_id}",
    name="scc_finding_details",
    title="Google Cloud SCC v2 Finding Details",
    description=(
        "Read-only Google Cloud Security Command Center v2 finding details, "
        "Attack Exposure Score, compliance mappings, and Cloud Asset Inventory "
        "resource metadata for organizations/{organization_id}/sources/-/findings/{finding_id}."
    ),
    mime_type="application/json",
)
async def read_scc_finding(
    organization_id: str,
    finding_id: str,
) -> dict[str, Any]:
    """Fetch SCC v2 finding details and CAI resource metadata by organization_id and finding_id."""
    organization_id = _validate_scc_resource_segment("organization_id", organization_id)
    finding_id = _validate_scc_resource_segment("finding_id", finding_id)
    details = await get_finding_details(
        organization_id=organization_id,
        finding_id=finding_id,
        include_resource_details=True,
    )
    if isinstance(details, CallToolResult):
        err_payload = details.structured_content or {}
        err_msg = str(err_payload.get("error") or "Failed to fetch SCC finding")
        extra = str(err_payload.get("details") or "").strip()
        full_msg = f"{err_msg}: {extra}" if extra else err_msg
        raise ResourceError(full_msg)
    if isinstance(details, dict) and isinstance(details.get("error"), str):
        raise ResourceError(details["error"])
    return {
        "organization_id": organization_id,
        **details,
    }


@mcp.prompt(
    title="Triage Google Cloud SCC Finding Exposure",
    description=(
        "Google Cloud Security Command Center (SCC v2) cloud vulnerability and "
        "misconfiguration triage workflow: evaluate Attack Exposure Score, "
        "Cloud Asset Inventory blast radius, compliance impact, and remediation."
    ),
)
def triage_cloud_finding_exposure(finding_id: str, organization_id: str) -> str:
    """Build a structured Google Cloud SCC v2 finding exposure triage prompt."""
    return (
        f"Execute a Google Cloud Security Command Center (SCC v2) exposure "
        f"and blast-radius triage workflow for finding `{finding_id}` in "
        f"organization `{organization_id}`:\n\n"
        f"1. **Finding & Asset Context Inspection**\n"
        f"   - Read resource `scc://findings/{organization_id}/{finding_id}` "
        f"(or call `get_finding_details(organization_id=\"{organization_id}\", "
        f"finding_id=\"{finding_id}\", include_resource_details=True)`) to "
        f"retrieve finding class, category, severity, state, CVE/CVSS data, "
        f"MITRE ATT&CK mappings, and Cloud Asset Inventory (CAI) resource "
        f"configuration.\n\n"
        f"2. **Attack Exposure Score & Blast-Radius Assessment**\n"
        f"   - Evaluate the `attackExposure` score, internet reachability, "
        f"attached service accounts, IAM bindings, and project/folder "
        f"criticality.\n"
        f"   - Call `search_findings(organization_id=\"{organization_id}\", "
        f"resource_name=...)` on the affected `resourceName` to check for "
        f"co-existing `TOXIC_COMBINATION`, `CHOKEPOINT`, `THREAT`, or "
        f"`MISCONFIGURATION` findings on the same cloud asset.\n\n"
        f"3. **Compliance & Remediation Plan**\n"
        f"   - Call `get_finding_remediation(organization_id=\"{organization_id}\", "
        f"finding_id=\"{finding_id}\")` to extract prescriptive `nextSteps` "
        f"and affected compliance controls (CIS, PCI DSS, NIST 800-53, ISO 27001).\n\n"
        f"4. **Prioritized Disposition**\n"
        f"   - Deliver a risk-ranked remediation recommendation (Immediate "
        f"Mitigation, Scheduled Patch/Config Fix, or Documented Risk Acceptance "
        f"prior to any `set_finding_mute` action)."
    )


# --- Main execution ---


def _resolve_allowed_hosts(
    host: str = "127.0.0.1",
    allowed_hosts: Optional[list[str]] = None,
) -> list[str]:
    """Build the Host-header allowlist for DNS-rebinding protection."""
    candidates: list[str] = [
        "127.0.0.1:*",
        "127.0.0.1",
        "localhost:*",
        "localhost",
        "[::1]:*",
        "[::1]",
    ]
    normalized_host = host.strip()
    if normalized_host and normalized_host not in _WILDCARD_BIND_HOSTS:
        if ":" in normalized_host and not normalized_host.startswith("["):
            bracketed = f"[{normalized_host}]"
            candidates.extend([bracketed, f"{bracketed}:*"])
        else:
            candidates.append(normalized_host)
            if not normalized_host.endswith(":*") and ":" not in normalized_host.lstrip("["):
                candidates.append(f"{normalized_host}:*")
            elif normalized_host.startswith("[") and normalized_host.endswith("]"):
                candidates.append(f"{normalized_host}:*")

    env_hosts = os.getenv("MCP_ALLOWED_HOSTS", "")
    if env_hosts.strip():
        for entry in env_hosts.split(","):
            cleaned = entry.strip()
            if cleaned:
                candidates.append(cleaned)

    if allowed_hosts:
        for entry in allowed_hosts:
            cleaned = entry.strip()
            if cleaned:
                candidates.append(cleaned)

    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _is_valid_origin_entry(entry: str) -> bool:
    """Return True when entry matches scheme://host[:port] (or :* wildcard port)."""
    if not entry or any(ord(ch) <= 32 or ord(ch) == 127 for ch in entry):
        return False
    probe = f"{entry[:-2]}:80" if entry.endswith(":*") else entry
    try:
        parsed = urlsplit(probe)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    if not parsed.hostname or "*" in parsed.hostname:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    if parsed.path or parsed.query or parsed.fragment:
        return False
    if port is not None and not (1 <= port <= 65535):
        return False
    return True


def _resolve_allowed_origins(
    resolved_hosts: Sequence[str],
    allowed_origins: Optional[list[str]] = None,
) -> list[str]:
    """Build the Origin-header allowlist from resolved allowed_hosts and MCP_ALLOWED_ORIGINS."""
    candidates: list[str] = []
    for host_pattern in resolved_hosts:
        cleaned = host_pattern.strip()
        if not cleaned:
            continue
        candidates.append(f"http://{cleaned}")
        candidates.append(f"https://{cleaned}")
        if cleaned.endswith(":*"):
            base_host = cleaned[:-2]
            if base_host:
                candidates.append(f"http://{base_host}")
                candidates.append(f"https://{base_host}")

    env_origins = os.getenv("MCP_ALLOWED_ORIGINS", "")
    if env_origins.strip():
        for entry in env_origins.split(","):
            cleaned = entry.strip()
            if not cleaned:
                continue
            if not _is_valid_origin_entry(cleaned):
                logger.warning(
                    "Ignoring malformed MCP_ALLOWED_ORIGINS entry %r; expected scheme://host[:port]",
                    cleaned,
                )
                continue
            candidates.append(cleaned)

    if allowed_origins:
        for entry in allowed_origins:
            cleaned = entry.strip()
            if cleaned:
                candidates.append(cleaned)

    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def build_streamable_http_app(
    server_instance: MCPServer = mcp,
    *,
    host: str = "127.0.0.1",
    stateless_http: bool = True,
    allowed_hosts: Optional[list[str]] = None,
    allowed_origins: Optional[list[str]] = None,
    oauth_issuer_url: Optional[str] = None,
    resource_server_url: Optional[str] = None,
    required_scopes: Optional[Sequence[str] | str] = None,
    token_verifier: Optional[TokenVerifier] = None,
) -> Starlette:
    """Build the bounded Streamable HTTP ASGI application with health probes and optional OAuth 2.1 RS."""
    sync_apps_state(server_instance)
    _deduplicate_otel_middleware(server_instance)
    _register_health_routes(server_instance)
    extra_hosts = list(allowed_hosts or [])
    extra_hosts.extend(extract_resource_host_patterns(resource_server_url))
    resolved_hosts = _resolve_allowed_hosts(
        host=host,
        allowed_hosts=extra_hosts or None,
    )
    resolved_origins = _resolve_allowed_origins(
        resolved_hosts,
        allowed_origins=allowed_origins,
    )
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=resolved_hosts,
        allowed_origins=resolved_origins,
    )
    auth_settings, resolved_verifier = resolve_oauth_configuration(
        oauth_issuer_url=oauth_issuer_url,
        resource_server_url=resource_server_url,
        required_scopes=required_scopes,
        token_verifier=token_verifier,
    )
    if auth_settings is not None and resolved_verifier is not None:
        custom_routes = list(getattr(server_instance, "_custom_starlette_routes", []))
        existing_paths = {getattr(r, "path", None) for r in custom_routes}
        for wk_route in build_root_oauth_well_known_routes(
            auth_settings, server_name=server_instance.name
        ):
            if wk_route.path not in existing_paths:
                custom_routes.append(wk_route)
        return server_instance._lowlevel_server.streamable_http_app(
            streamable_http_path="/mcp",
            stateless_http=stateless_http,
            max_request_body_size=DEFAULT_MAX_REQUEST_BODY_SIZE,
            session_idle_timeout=DEFAULT_SESSION_IDLE_TIMEOUT,
            max_sessions=DEFAULT_MAX_SESSIONS,
            transport_security=transport_security,
            host=host,
            auth=auth_settings,
            token_verifier=resolved_verifier,
            custom_starlette_routes=custom_routes,
        )
    return server_instance.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=stateless_http,
        max_request_body_size=DEFAULT_MAX_REQUEST_BODY_SIZE,
        session_idle_timeout=DEFAULT_SESSION_IDLE_TIMEOUT,
        max_sessions=DEFAULT_MAX_SESSIONS,
        transport_security=transport_security,
        host=host,
    )


def _resolve_default_stateless_http() -> bool:
    """Resolve default stateless HTTP mode from MCP_STATELESS_HTTP (defaults True)."""
    raw = os.getenv("MCP_STATELESS_HTTP")
    if raw is None or not raw.strip():
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def _normalize_transport(raw_transport: str) -> str:
    """Normalize CLI/environment transport aliases."""
    normalized = raw_transport.strip().lower()
    if normalized == "http":
        return "streamable-http"
    return normalized


def _first_nonempty_env(*names: str, default: str) -> str:
    """Return the first non-empty stripped environment variable value, or default."""
    for name in names:
        raw = os.getenv(name)
        if raw is not None and raw.strip():
            return raw.strip()
    return default


class _MCPArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that validates MCP_* environment defaults on parse."""

    def parse_known_args(
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
    ) -> tuple[argparse.Namespace, list[str]]:
        parsed_ns, remaining = super().parse_known_args(args, namespace)
        if getattr(parsed_ns, "transport", None) is None:
            raw_transport = _first_nonempty_env("MCP_TRANSPORT", default="stdio")
            normalized_transport = _normalize_transport(raw_transport)
            if normalized_transport not in {"stdio", "streamable-http"}:
                self.error(
                    f"invalid MCP_TRANSPORT value {raw_transport!r} "
                    "(choose from 'stdio', 'streamable-http', 'http')"
                )
            parsed_ns.transport = normalized_transport
        else:
            parsed_ns.transport = _normalize_transport(parsed_ns.transport)

        if getattr(parsed_ns, "host", None) is None:
            parsed_ns.host = _first_nonempty_env("MCP_HOST", default="127.0.0.1")

        if getattr(parsed_ns, "port", None) is None:
            raw_port = _first_nonempty_env("MCP_PORT", default="8000")
            try:
                parsed_port = int(raw_port)
            except ValueError:
                self.error(f"invalid MCP_PORT integer value: {raw_port!r}")
            if not (1 <= parsed_port <= 65535):
                self.error(f"MCP_PORT must be between 1 and 65535, got {parsed_port}")
            parsed_ns.port = parsed_port
        elif not (1 <= parsed_ns.port <= 65535):
            self.error(f"--port must be between 1 and 65535, got {parsed_ns.port}")

        if getattr(parsed_ns, "unattended_policy", None) is None:
            raw_policy = os.getenv("MCP_UNATTENDED_DESTRUCTIVE_POLICY", "").strip().lower()
            if raw_policy:
                if raw_policy not in {"allow", "deny"}:
                    self.error(
                        f"invalid MCP_UNATTENDED_DESTRUCTIVE_POLICY value {raw_policy!r} "
                        "(choose from 'allow', 'deny')"
                    )
                parsed_ns.unattended_policy = raw_policy

        return parsed_ns, remaining


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for SCC MCP."""
    parser = _MCPArgumentParser(
        description="Google Cloud Security Command Center MCP Server",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "http"),
        default=None,
        help="MCP transport to serve (default: MCP_TRANSPORT or stdio).",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Bind host for streamable-http transport (default: MCP_HOST or 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port for streamable-http transport (default: MCP_PORT or 8000).",
    )
    parser.add_argument(
        "--stateless-http",
        action=argparse.BooleanOptionalAction,
        default=_resolve_default_stateless_http(),
        help="Serve stateless Streamable HTTP requests (default: MCP_STATELESS_HTTP or true).",
    )
    parser.add_argument(
        "--elicit-destructive",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Require user elicitation before muting SCC findings (default: MCP_ELICIT_DESTRUCTIVE or false).",
    )
    parser.add_argument(
        "--unattended-policy",
        choices=("allow", "deny"),
        default=None,
        help="Policy when client lacks elicitation capability (default: allow on stdio, deny on streamable-http).",
    )
    parser.add_argument(
        "--oauth-issuer-url",
        default=None,
        help="OAuth 2.1 / OIDC issuer URL for streamable-http Resource Server mode (MCP_OAUTH_ISSUER_URL).",
    )
    parser.add_argument(
        "--resource-server-url",
        default=None,
        help="Canonical RFC 8707 Resource Server URL for audience validation (MCP_RESOURCE_SERVER_URL).",
    )
    parser.add_argument(
        "--required-scopes",
        default=None,
        help="Comma-separated OAuth 2.1 scopes required on streamable-http requests (MCP_REQUIRED_SCOPES).",
    )
    parser.add_argument(
        "--disable-apps",
        action="store_true",
        default=False,
        help="Disable interactive MCP Apps UI resources and tool metadata (sets MCP_ENABLE_APPS=false).",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Runs the SCC MCP server."""
    args = build_arg_parser().parse_args(argv)
    if args.elicit_destructive is not None:
        os.environ["MCP_ELICIT_DESTRUCTIVE"] = "true" if args.elicit_destructive else "false"
    if args.unattended_policy is not None:
        os.environ["MCP_UNATTENDED_DESTRUCTIVE_POLICY"] = args.unattended_policy
    if getattr(args, "disable_apps", False):
        os.environ["MCP_ENABLE_APPS"] = "false"
    if not scc_client:
        logger.critical("SCC Client failed to initialize. MCP server cannot serve SCC tools.")

    transport = _normalize_transport(args.transport)
    os.environ["MCP_TRANSPORT"] = transport
    sync_apps_state(mcp)
    _deduplicate_otel_middleware(mcp)
    if transport == "streamable-http":
        app = build_streamable_http_app(
            mcp,
            host=args.host,
            stateless_http=args.stateless_http,
            oauth_issuer_url=args.oauth_issuer_url,
            resource_server_url=args.resource_server_url,
            required_scopes=args.required_scopes,
        )
        logger.info(
            "Starting %s over streamable-http on %s:%d (stateless_http=%s)",
            mcp.name,
            args.host,
            args.port,
            args.stateless_http,
        )
        uvicorn.run(app, host=args.host, port=args.port)
    elif transport == "stdio":
        logger.info("Starting SCC MCP server...")
        mcp.run(transport="stdio")
    else:  # pragma: no cover
        raise ValueError(f"Unsupported MCP transport: {transport!r}")


if __name__ == "__main__":
    main()
