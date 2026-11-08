# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Phase 5 helpers for SecOps MCP: MRTR elicitation, OAuth 2.1 RS, and MCP Apps."""

from __future__ import annotations

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
import time
from typing import Any, Generic, Optional, TypeVar
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import httpx2
from mcp.server.apps import Apps, EXTENSION_ID, ResourceCsp
from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.routes import build_resource_metadata_url, cors_middleware
from mcp.server.auth.settings import AuthSettings
from mcp.server.elicitation import (
    AcceptedElicitation,
    ElicitSchemaModelT,
    render_elicitation_schema,
)
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.request_state import (
    AESGCMRequestStateCodec,
    RequestStateSecurity,
    authenticated_principal,
)
from mcp.shared.auth import ProtectedResourceMetadata
from mcp.types import (
    ElicitRequest,
    ElicitRequestFormParams,
    InputRequiredResult,
)
from pydantic import AnyHttpUrl, BaseModel, Field
from starlette.routing import Route

logger = logging.getLogger("secops-mcp")

_EPHEMERAL_STATE_KEY: bytes = os.urandom(32)
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSY_ENV_VALUES = frozenset({"0", "false", "no", "off"})

SECOPS_ENTITY_TIMELINE_URI = "ui://secops/entity-timeline.html"

ENTITY_TIMELINE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Chronicle Entity and Event Timeline</title>
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
  max-width: 1120px;
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
  color: var(--ink-primary);
}
.summary-line {
  margin: 0;
  color: var(--ink-secondary);
  font-size: 13px;
  max-width: 68ch;
  font-variant-numeric: tabular-nums;
}
.query-strip {
  margin-top: 14px;
  padding: 10px 14px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-hairline);
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--ink-primary);
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
}
h2 {
  margin: 28px 0 12px 0;
  font-family: var(--font-display);
  font-size: 15px;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--ink-primary);
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
  padding: 14px 0;
  border-bottom: 1px solid var(--border-hairline);
  align-items: center;
}
.filter-group-label {
  font-size: 12px;
  color: var(--ink-secondary);
  margin-right: 4px;
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
  font-variant-numeric: tabular-nums;
}
button.filter-pill:hover {
  color: var(--ink-primary);
  border-color: #3E4652;
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
.table-wrap {
  width: 100%;
  overflow-x: auto;
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
  white-space: nowrap;
}
td {
  padding: 12px;
  font-size: 13px;
  border-bottom: 1px solid var(--border-hairline);
  vertical-align: top;
}
.mono {
  font-family: var(--font-mono);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}
.muted {
  color: var(--ink-secondary);
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
  color: var(--ink-primary);
}
.badge-CRITICAL { color: #FF8A80; background: #2A1414; border-color: #6E2825; }
.badge-HIGH { color: #FFB870; background: #291B0E; border-color: #6B441C; }
.badge-MEDIUM { color: #F6D365; background: #26200D; border-color: #665419; }
.badge-LOW { color: #7CC4FA; background: #10202E; border-color: #224E70; }
.badge-CLEAN { color: #6EE7B7; background: #0F261E; border-color: #1D5943; }
.empty-state {
  padding: 24px 0;
  color: var(--ink-secondary);
  font-size: 13px;
  max-width: 65ch;
}
</style>
</head>
<body>
<main>
  <header>
    <h1 id="view-title">Chronicle UDM Event and Entity Ledger</h1>
    <p class="summary-line" id="summary-line">Awaiting Chronicle SIEM tool output from search_security_events or lookup_entity.</p>
    <div class="query-strip" id="query-strip" hidden></div>
  </header>

  <section aria-labelledby="sec-timeline">
    <h2 id="sec-timeline"><span class="idx">01</span>Event and Alert Timeline</h2>
    <div class="filter-bar" id="severity-filters" role="toolbar" aria-label="Filter timeline by severity and event type"></div>
    <div class="table-wrap">
      <table aria-label="UDM Event Timeline">
        <thead>
          <tr>
            <th scope="col">Timestamp (UTC)</th>
            <th scope="col">Severity</th>
            <th scope="col">UDM Event Type</th>
            <th scope="col">Principal / Source</th>
            <th scope="col">Target / Indicator</th>
            <th scope="col">Summary</th>
          </tr>
        </thead>
        <tbody id="timeline-body">
          <tr><td colspan="6" class="empty-state">Run search_security_events or lookup_entity to populate the timeline.</td></tr>
        </tbody>
      </table>
    </div>
  </section>
</main>
<script>
(function () {
  var state = { rows: [], severity: "ALL", eventType: "ALL" };
  var nextId = 1;

  function normalizeSeverity(raw) {
    var val = String(raw || "").toUpperCase();
    if (val.indexOf("CRIT") >= 0) return "CRITICAL";
    if (val.indexOf("HIGH") >= 0) return "HIGH";
    if (val.indexOf("MED") >= 0) return "MEDIUM";
    if (val.indexOf("LOW") >= 0) return "LOW";
    return "CLEAN";
  }

  function extractRows(payload) {
    if (!payload || typeof payload !== "object") return [];
    var rows = [];
    var eventsContainer = payload.events;
    var rawList = Array.isArray(eventsContainer)
      ? eventsContainer
      : (eventsContainer && Array.isArray(eventsContainer.events) ? eventsContainer.events : []);
    for (var i = 0; i < rawList.length; i++) {
      var item = rawList[i] || {};
      var udm = item.udm || item.event || item;
      var meta = udm.metadata || {};
      var principal = udm.principal || {};
      var target = udm.target || {};
      var secList = Array.isArray(udm.securityResult) ? udm.securityResult : (udm.security_result ? [udm.security_result] : []);
      var sec0 = secList[0] || {};
      var sev = normalizeSeverity(sec0.severity || item.severity || "LOW");
      var evType = String(meta.eventType || meta.event_type || "GENERIC_EVENT");
      var src = principal.hostname || (Array.isArray(principal.ip) ? principal.ip[0] : principal.ip) || (principal.user && principal.user.userid) || "-";
      var dst = target.hostname || (Array.isArray(target.ip) ? target.ip[0] : target.ip) || target.url || "-";
      var desc = sec0.summary || sec0.description || meta.productEventType || meta.product_name || "UDM telemetry record";
      rows.push({
        ts: String(meta.eventTimestamp || meta.event_timestamp || item.timestamp || "-"),
        severity: sev,
        eventType: evType,
        principal: String(src),
        target: String(dst),
        summary: String(desc)
      });
    }
    if (!rows.length && typeof payload.summary === "string") {
      rows.push({
        ts: String(payload.last_seen || payload.first_seen || "Window summary"),
        severity: payload.alert_rule_count > 0 ? "HIGH" : (payload.found === false ? "LOW" : "CLEAN"),
        eventType: String(payload.entity_type || "ENTITY_SUMMARY"),
        principal: String(payload.entity_value || "-"),
        target: payload.related_entity_count ? (String(payload.related_entity_count) + " related entities") : "-",
        summary: payload.summary.slice(0, 220)
      });
    }
    return rows;
  }

  function renderFilters() {
    var bar = document.getElementById("severity-filters");
    bar.textContent = "";
    var severities = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"];
    var lbl = document.createElement("span");
    lbl.className = "filter-group-label";
    lbl.textContent = "Severity:";
    bar.appendChild(lbl);
    severities.forEach(function (sev) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "filter-pill";
      btn.setAttribute("aria-pressed", state.severity === sev ? "true" : "false");
      btn.textContent = sev;
      btn.addEventListener("click", function () {
        state.severity = sev;
        renderFilters();
        renderTable();
      });
      bar.appendChild(btn);
    });

    var seenTypes = ["ALL"];
    state.rows.forEach(function (r) {
      if (seenTypes.indexOf(r.eventType) < 0 && seenTypes.length < 6) seenTypes.push(r.eventType);
    });
    if (seenTypes.length > 2) {
      var typeLbl = document.createElement("span");
      typeLbl.className = "filter-group-label";
      typeLbl.textContent = "Event Type:";
      bar.appendChild(typeLbl);
      seenTypes.forEach(function (et) {
        var tbtn = document.createElement("button");
        tbtn.type = "button";
        tbtn.className = "filter-pill";
        tbtn.setAttribute("aria-pressed", state.eventType === et ? "true" : "false");
        tbtn.textContent = et;
        tbtn.addEventListener("click", function () {
          state.eventType = et;
          renderFilters();
          renderTable();
        });
        bar.appendChild(tbtn);
      });
    }
  }

  function renderTable() {
    var tbody = document.getElementById("timeline-body");
    tbody.textContent = "";
    var filtered = state.rows.filter(function (r) {
      var sevOk = state.severity === "ALL" || r.severity === state.severity;
      var typeOk = state.eventType === "ALL" || r.eventType === state.eventType;
      return sevOk && typeOk;
    });
    if (!filtered.length) {
      var trEmpty = document.createElement("tr");
      var tdEmpty = document.createElement("td");
      tdEmpty.colSpan = 6;
      tdEmpty.className = "empty-state";
      tdEmpty.textContent = state.rows.length ? "No timeline records match the active filter." : "No UDM events returned for this query.";
      trEmpty.appendChild(tdEmpty);
      tbody.appendChild(trEmpty);
      notifyHeight();
      return;
    }
    filtered.forEach(function (r) {
      var tr = document.createElement("tr");
      var cTs = document.createElement("td"); cTs.className = "mono"; cTs.textContent = r.ts;
      var cSev = document.createElement("td");
      var b = document.createElement("span"); b.className = "badge badge-" + r.severity; b.textContent = r.severity;
      cSev.appendChild(b);
      var cType = document.createElement("td"); cType.className = "mono"; cType.textContent = r.eventType;
      var cSrc = document.createElement("td"); cSrc.className = "mono"; cSrc.textContent = r.principal;
      var cDst = document.createElement("td"); cDst.className = "mono"; cDst.textContent = r.target;
      var cSum = document.createElement("td"); cSum.textContent = r.summary;
      tr.appendChild(cTs); tr.appendChild(cSev); tr.appendChild(cType);
      tr.appendChild(cSrc); tr.appendChild(cDst); tr.appendChild(cSum);
      tbody.appendChild(tr);
    });
    notifyHeight();
  }

  function applyResult(result) {
    var payload = (result && result.structuredContent) || null;
    if (!payload && result && Array.isArray(result.content) && result.content[0] && result.content[0].text) {
      try { payload = JSON.parse(result.content[0].text); } catch (_e) { payload = { summary: result.content[0].text }; }
    }
    if (!payload) return;
    var qStrip = document.getElementById("query-strip");
    if (payload.udm_query) {
      qStrip.hidden = false;
      qStrip.textContent = "UDM: " + payload.udm_query;
    } else if (payload.entity_value) {
      qStrip.hidden = false;
      qStrip.textContent = "Entity: " + payload.entity_value;
    }
    state.rows = extractRows(payload);
    var total = (payload.events && typeof payload.events.total_events === "number") ? payload.events.total_events : state.rows.length;
    document.getElementById("summary-line").textContent =
      "Displaying " + state.rows.length + " record(s) (total matched: " + total + ").";
    renderFilters();
    renderTable();
  }

  function postRpc(msg) {
    if (window.parent && window.parent !== window) {
      window.parent.postMessage(msg, "*");
    }
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
      applyResult(d.params);
    }
  });

  renderFilters();
  postRpc({
    jsonrpc: "2.0",
    id: nextId++,
    method: "ui/initialize",
    params: {
      protocolVersion: "2026-01-26",
      appInfo: { name: "secops-entity-timeline", version: "0.9.0" },
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
    """Pydantic confirmation schema for destructive or external-upload MCP operations."""

    confirm: bool = Field(
        description="Set true to confirm and execute the operation, or false to abort."
    )
    reason: str = Field(
        default="",
        description="Optional operator justification or audit note.",
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
    """Return True when MCP_ELICIT_DESTRUCTIVE enables confirmation prompts."""
    raw = os.getenv("MCP_ELICIT_DESTRUCTIVE", "false").strip().lower()
    return raw in _TRUTHY_ENV_VALUES


def _is_http_context(ctx: Context) -> bool:
    """Detect whether the current tool invocation arrived over HTTP transport."""
    req_ctx = getattr(ctx, "_request_context", None)
    if req_ctx is not None and getattr(req_ctx, "request", None) is not None:
        return True
    env_transport = os.getenv("MCP_TRANSPORT", "").strip().lower()
    return env_transport in {"streamable-http", "http"}


def resolve_unattended_policy(*, is_http: bool) -> str:
    """Resolve MCP_UNATTENDED_DESTRUCTIVE_POLICY ('deny' on HTTP, 'allow' on stdio)."""
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
    """Gate destructive or external-upload actions with stateless MRTR or backchannel elicitation."""
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
SECOPS_UI_TOOL_URIS: dict[str, str] = {
    "lookup_entity": SECOPS_ENTITY_TIMELINE_URI,
    "search_security_events": SECOPS_ENTITY_TIMELINE_URI,
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
    """Parse comma- or space-separated OAuth scopes from argument or MCP_REQUIRED_SCOPES."""
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
    """Resolve optional OAuth 2.1 Resource Server settings and TokenVerifier."""
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
    """Extract Host-header allowlist entries from MCP_RESOURCE_SERVER_URL."""
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
    """Expose /.well-known/oauth-protected-resource at root when resource URL has a path."""
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
    """Return True unless MCP_ENABLE_APPS is explicitly set to a falsy value."""
    raw = os.getenv("MCP_ENABLE_APPS", "true").strip().lower()
    return raw not in _FALSY_ENV_VALUES


def build_strict_csp() -> ResourceCsp:
    """Return a zero-network ResourceCsp for self-contained dark-mode MCP Apps."""
    return ResourceCsp(
        connect_domains=[],
        resource_domains=[],
        frame_domains=[],
        base_uri_domains=[],
    )


def _create_secops_apps() -> Apps:
    apps = Apps()
    apps.add_html_resource(
        SECOPS_ENTITY_TIMELINE_URI,
        ENTITY_TIMELINE_HTML,
        name="secops_entity_timeline",
        title="Chronicle UDM Event and Entity Timeline",
        description=(
            "Interactive dark-mode Chronicle SIEM UDM event and alert timeline "
            "with severity and event-type filter controls."
        ),
        csp=build_strict_csp(),
        prefers_border=True,
    )
    return apps


def build_secops_apps_extensions() -> list[Apps]:
    """Build MCP Apps extension list for SecOps MCP (empty if MCP_ENABLE_APPS=false)."""
    if not is_apps_enabled():
        return []
    return [_create_secops_apps()]


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
        apps = _create_secops_apps()
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
            for tool_name, resource_uri in SECOPS_UI_TOOL_URIS.items():
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
            for tool_name in SECOPS_UI_TOOL_URIS:
                tool_obj = tool_map.get(tool_name)
                if tool_obj is not None and isinstance(tool_obj.meta, dict):
                    cleaned = {
                        k: v for k, v in tool_obj.meta.items() if k != "ui"
                    }
                    tool_obj.meta = cleaned or None
    return enabled


def ui_tool_meta(resource_uri: str) -> Optional[dict[str, Any]]:
    """Return _meta.ui.resourceUri tool metadata when MCP Apps are enabled."""
    if not is_apps_enabled():
        return None
    return {"ui": {"resourceUri": resource_uri}}
