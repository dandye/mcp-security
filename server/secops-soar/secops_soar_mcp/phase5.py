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
"""Phase 5 helpers for SecOps SOAR MCP: MRTR elicitation and OAuth 2.1 RS."""

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

logger = logging.getLogger("secops-soar-mcp")

_EPHEMERAL_STATE_KEY: bytes = os.urandom(32)
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})


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
    """Confirmation schema for destructive MCP operations."""

    confirm: bool = Field(
        description="Set true to confirm and execute the operation, or false to abort."
    )
    reason: str = Field(
        default="",
        description="Optional operator justification or audit note.",
    )


class CloseCaseConfirmation(BaseModel):
    """Confirmation schema for closing a Google Security Operations SOAR case."""

    confirm: bool = Field(
        description="Set true to confirm closing the SOAR case, or false to abort."
    )
    close_reason: str = Field(
        default="",
        description="Optional close reason override (Malicious, NotMalicious, Maintenance, Inconclusive).",
    )
    root_cause: str = Field(
        default="",
        description="Optional root cause override or confirmation note.",
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
