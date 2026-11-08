# Copyright 2026 Google LLC
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
"""Phase 5 helpers for GTI MCP: MRTR elicitation, OAuth 2.1 RS, and MCP Apps."""

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
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from mcp.server.apps import Apps, ResourceCsp
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

logger = logging.getLogger("gti-mcp")

_EPHEMERAL_STATE_KEY: bytes = os.urandom(32)
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSY_ENV_VALUES = frozenset({"0", "false", "no", "off"})

GTI_IOC_VERDICT_URI = "ui://gti/ioc-verdict.html"

IOC_VERDICT_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Google Threat Intelligence IOC Verdict</title>
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
  max-width: 1080px;
  margin: 0 auto;
}
header {
  padding-bottom: 18px;
  border-bottom: 1px solid var(--border-hairline);
}
.header-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
h1 {
  margin: 0;
  font-family: var(--font-display);
  font-size: 20px;
  font-weight: 600;
  letter-spacing: -0.02em;
}
.ioc-id {
  margin: 8px 0 0 0;
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--ink-primary);
  word-break: break-all;
  font-variant-numeric: tabular-nums;
}
.verdict-ledger {
  margin: 12px 0 0 0;
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
.badge {
  display: inline-block;
  padding: 3px 10px;
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
.tab-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 12px 0;
  border-bottom: 1px solid var(--border-hairline);
}
button.tab-btn {
  min-height: 34px;
  padding: 6px 14px;
  background: var(--bg-elevated);
  color: var(--ink-secondary);
  border: 1px solid var(--border-hairline);
  border-radius: 4px;
  font-family: var(--font-sans);
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
}
button.tab-btn[aria-pressed="true"] {
  background: #1E2631;
  color: var(--ink-primary);
  border-color: var(--focus-ring);
}
button.tab-btn:focus-visible {
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
.mono {
  font-family: var(--font-mono);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
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
    <div class="header-row">
      <h1>GTI Indicator Verdict and Attribution</h1>
      <span class="badge badge-LOW" id="verdict-badge">PENDING</span>
    </div>
    <p class="ioc-id" id="ioc-identifier">Awaiting get_file_report, get_domain_report, or get_ip_address_report result.</p>
    <p class="verdict-ledger" id="verdict-ledger">Detection ratio: 0 / 0 engines | Reputation: 0 | Type: unknown</p>
  </header>

  <div class="tab-bar" role="toolbar" aria-label="Filter indicator sections">
    <button type="button" class="tab-btn" id="btn-all" aria-pressed="true">All Sections</button>
    <button type="button" class="tab-btn" id="btn-mitre" aria-pressed="false">MITRE ATT&amp;CK Only</button>
    <button type="button" class="tab-btn" id="btn-rels" aria-pressed="false">Relationships Only</button>
  </div>

  <section id="sec-mitre-wrap" aria-labelledby="sec-mitre">
    <h2 id="sec-mitre"><span class="idx">01</span>MITRE ATT&amp;CK Tactics and Techniques</h2>
    <table>
      <thead>
        <tr>
          <th scope="col">Technique ID</th>
          <th scope="col">Tactic / Classification</th>
          <th scope="col">Description</th>
        </tr>
      </thead>
      <tbody id="mitre-body">
        <tr><td colspan="3" class="empty-state">No MITRE ATT&amp;CK techniques loaded yet.</td></tr>
      </tbody>
    </table>
  </section>

  <section id="sec-rels-wrap" aria-labelledby="sec-rels">
    <h2 id="sec-rels"><span class="idx">02</span>Graph Relationships and Associations</h2>
    <table>
      <thead>
        <tr>
          <th scope="col">Relationship Facet</th>
          <th scope="col">Count</th>
          <th scope="col">Sample Indicators / Collections</th>
        </tr>
      </thead>
      <tbody id="rels-body">
        <tr><td colspan="3" class="empty-state">No relationship facets loaded yet.</td></tr>
      </tbody>
    </table>
  </section>
</main>
<script>
(function () {
  var nextId = 1;
  function setMode(mode) {
    document.getElementById("btn-all").setAttribute("aria-pressed", mode === "all" ? "true" : "false");
    document.getElementById("btn-mitre").setAttribute("aria-pressed", mode === "mitre" ? "true" : "false");
    document.getElementById("btn-rels").setAttribute("aria-pressed", mode === "rels" ? "true" : "false");
    document.getElementById("sec-mitre-wrap").hidden = (mode === "rels");
    document.getElementById("sec-rels-wrap").hidden = (mode === "mitre");
    notifyHeight();
  }
  document.getElementById("btn-all").addEventListener("click", function () { setMode("all"); });
  document.getElementById("btn-mitre").addEventListener("click", function () { setMode("mitre"); });
  document.getElementById("btn-rels").addEventListener("click", function () { setMode("rels"); });

  function computeVerdict(malicious, suspicious, total, gtiSeverity) {
    var gti = String(gtiSeverity || "").toUpperCase();
    if (gti.indexOf("CRIT") >= 0 || malicious >= 10) return "CRITICAL";
    if (gti.indexOf("HIGH") >= 0 || malicious >= 3) return "HIGH";
    if (gti.indexOf("MED") >= 0 || malicious >= 1 || suspicious >= 2) return "MEDIUM";
    if (suspicious >= 1) return "LOW";
    return total > 0 ? "CLEAN" : "LOW";
  }

  function applyPayload(raw) {
    var root = (raw && raw.data && raw.data.attributes) ? raw.data : raw;
    if (!root || typeof root !== "object") return;
    var attrs = root.attributes || root;
    var stats = attrs.last_analysis_stats || {};
    var mal = Number(stats.malicious || 0);
    var susp = Number(stats.suspicious || 0);
    var harmless = Number(stats.harmless || 0);
    var undetected = Number(stats.undetected || 0);
    var total = mal + susp + harmless + undetected;
    var gtiAssessment = attrs.gti_assessment || {};
    var gtiSev = (gtiAssessment.severity && gtiAssessment.severity.value) || gtiAssessment.verdict || "";
    var verdict = computeVerdict(mal, susp, total, gtiSev);

    var badge = document.getElementById("verdict-badge");
    badge.className = "badge badge-" + verdict;
    badge.textContent = verdict;

    document.getElementById("ioc-identifier").textContent =
      String(root.id || attrs.meaningful_name || attrs.sha256 || "Indicator");
    document.getElementById("verdict-ledger").textContent =
      "Detection ratio: " + mal + " malicious, " + susp + " suspicious / " + total +
      " engines | Reputation: " + String(attrs.reputation != null ? attrs.reputation : 0) +
      " | Type: " + String(root.type || attrs.type_description || "ioc");

    var mitreBody = document.getElementById("mitre-body");
    mitreBody.textContent = "";
    var techniques = [];
    if (Array.isArray(attrs.mitre_attack_techniques)) {
      techniques = attrs.mitre_attack_techniques;
    } else if (attrs.crowdsourced_ids_results && Array.isArray(attrs.crowdsourced_ids_results)) {
      techniques = attrs.crowdsourced_ids_results;
    } else if (attrs.popular_threat_classification && Array.isArray(attrs.popular_threat_classification.popular_threat_category)) {
      attrs.popular_threat_classification.popular_threat_category.forEach(function (c) {
        techniques.push({ id: "THREAT_CLASS", tactic: c.value || "category", description: "Count: " + String(c.count || 1) });
      });
    }
    if (!techniques.length) {
      var trM = document.createElement("tr");
      var tdM = document.createElement("td");
      tdM.colSpan = 3; tdM.className = "empty-state";
      tdM.textContent = "No MITRE ATT&CK techniques reported on this indicator.";
      trM.appendChild(tdM); mitreBody.appendChild(trM);
    } else {
      techniques.slice(0, 20).forEach(function (t) {
        var tr = document.createElement("tr");
        var cId = document.createElement("td"); cId.className = "mono"; cId.textContent = String(t.id || t.technique_id || "T----");
        var cTac = document.createElement("td"); cTac.textContent = String(t.tactic || t.severity || "execution");
        var cDesc = document.createElement("td"); cDesc.textContent = String(t.description || t.name || t.rule_msg || "-");
        tr.appendChild(cId); tr.appendChild(cTac); tr.appendChild(cDesc);
        mitreBody.appendChild(tr);
      });
    }

    var relsBody = document.getElementById("rels-body");
    relsBody.textContent = "";
    var rels = root.relationships || {};
    var relKeys = Object.keys(rels);
    if (!relKeys.length) {
      var trR = document.createElement("tr");
      var tdR = document.createElement("td");
      tdR.colSpan = 3; tdR.className = "empty-state";
      tdR.textContent = "No graph relationships included in this report.";
      trR.appendChild(tdR); relsBody.appendChild(trR);
    } else {
      relKeys.forEach(function (k) {
        var entry = rels[k];
        var arr = Array.isArray(entry) ? entry : (entry && Array.isArray(entry.data) ? entry.data : []);
        var sample = arr.slice(0, 4).map(function (x) {
          return String((x && (x.id || (x.attributes && x.attributes.name))) || "object");
        }).join(", ");
        var tr = document.createElement("tr");
        var cName = document.createElement("td"); cName.className = "mono"; cName.textContent = k;
        var cCnt = document.createElement("td"); cCnt.className = "mono"; cCnt.textContent = String(arr.length);
        var cSmp = document.createElement("td"); cSmp.className = "mono"; cSmp.textContent = sample || "-";
        tr.appendChild(cName); tr.appendChild(cCnt); tr.appendChild(cSmp);
        relsBody.appendChild(tr);
      });
    }
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
      if (p) applyPayload(p);
    }
  });

  postRpc({
    jsonrpc: "2.0",
    id: nextId++,
    method: "ui/initialize",
    params: {
      protocolVersion: "2026-01-26",
      appInfo: { name: "gti-ioc-verdict", version: "0.2.0" },
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

  def _codec(self) -> AESGCMRequestStateCodec:
    return AESGCMRequestStateCodec(
        [derive_request_state_key(self._explicit_secret)]
    )

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
  """Pydantic confirmation schema for external file upload or destructive actions."""

  confirm: bool = Field(
      description="Set true to confirm external file upload to VirusTotal/GTI, or false to abort."
  )
  reason: str = Field(
      default="",
      description="Optional justification or ticket reference for the upload.",
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
            "message": (
                f"Operation '{action_name}' cancelled by operator ({action})."
            ),
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


def _b64url_decode(segment: str) -> bytes:
  padded = segment + "=" * (-len(segment) % 4)
  return base64.urlsafe_b64decode(padded.encode("ascii"))


def _verify_compact_jwt(
    token: str,
    *,
    hs256_secret: Optional[str] = None,
    public_key_pem: Optional[str] = None,
) -> Optional[dict[str, Any]]:
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

  alg = str(header.get("alg") or "")
  signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

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
    if alg != "RS256":
      return None
    try:
      pub_key = serialization.load_pem_public_key(
          public_key_pem.encode("utf-8")
      )
      if not isinstance(pub_key, rsa.RSAPublicKey):
        return None
      pub_key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
      return None
    return payload

  return None


def _normalize_url(url: str) -> str:
  return str(url).strip().rstrip("/")


class GoogleOIDCTokenVerifier(TokenVerifier):
  """OAuth 2.1 / Google OIDC TokenVerifier enforcing issuer, expiry, and RFC 8707 audience."""

  def __init__(
      self,
      *,
      issuer_url: str,
      resource_server_url: str,
      required_scopes: Sequence[str] = (),
      hs256_secret: Optional[str] = None,
      public_key_pem: Optional[str] = None,
      verify_callback: Optional[Callable[[str], Any]] = None,
  ) -> None:
    self.issuer_url = str(issuer_url).strip()
    self.resource_server_url = str(resource_server_url).strip()
    self.required_scopes = list(required_scopes)
    self.hs256_secret = hs256_secret
    self.public_key_pem = public_key_pem
    self.verify_callback = verify_callback
    self._normalized_issuer = _normalize_url(self.issuer_url)
    self._normalized_resource = _normalize_url(self.resource_server_url)

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
      if secret or pem:
        claims = _verify_compact_jwt(
            cleaned,
            hs256_secret=secret or None,
            public_key_pem=pem or None,
        )
      else:
        claims = await self._verify_via_google_oidc(cleaned)

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

    iss = _normalize_url(str(claims.get("iss") or ""))
    if not iss or iss != self._normalized_issuer:
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

  async def _verify_via_google_oidc(
      self,
      token: str,
  ) -> Optional[dict[str, Any]]:
    try:
      from google.auth.transport import requests as google_requests
      from google.oauth2 import id_token as google_id_token

      verified = await asyncio.to_thread(
          google_id_token.verify_oauth2_token,
          token,
          google_requests.Request(),
          audience=self.resource_server_url,
      )
      return dict(verified) if isinstance(verified, dict) else None
    except Exception as exc:
      logger.debug("Google OIDC token verification failed: %s", exc)
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
      required_scopes=scopes,
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


def build_gti_apps_extensions() -> list[Apps]:
  if not is_apps_enabled():
    return []
  apps = Apps()
  apps.add_html_resource(
      GTI_IOC_VERDICT_URI,
      IOC_VERDICT_HTML,
      name="gti_ioc_verdict",
      title="Google Threat Intelligence IOC Verdict",
      description=(
          "Interactive dark-mode Google Threat Intelligence indicator verdict, "
          "detection ratio, MITRE ATT&CK techniques, and graph relationships."
      ),
      csp=build_strict_csp(),
      prefers_border=True,
  )
  return [apps]


def ui_tool_meta(resource_uri: str) -> Optional[dict[str, Any]]:
  if not is_apps_enabled():
    return None
  return {"ui": {"resourceUri": resource_uri}}
