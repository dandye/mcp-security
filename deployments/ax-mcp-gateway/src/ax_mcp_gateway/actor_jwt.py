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
"""Agent Substrate actorJwt verification for out-of-sandbox MCP gateways.

Matches the Agent Substrate (ate.dev) wire contract implemented in:
- internal/actoridjwt/actoridjwt.go (KindActor subject and actor.ate.dev claims)
- internal/localjwtauthority/jwks.go (RFC 7517 JWKS with ES256 / RS256 / RS384 / RS512)
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, Optional

import httpx
import jwt
from jwt import algorithms as jwt_algorithms
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

# Matches localjwtauthority/jwks.go algorithmFits: P-256 ES256 and RSA RS256/384/512.
ALLOWED_JWT_ALGORITHMS: tuple[str, ...] = (
    "ES256",
    "RS256",
    "RS384",
    "RS512",
)

ACTOR_CLAIM_KEY = "actor.ate.dev"
WORKER_FOR_ACTOR_CLAIM_KEY = "worker-for-actor.ate.dev"
_RFC1123_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ActorJwtAuthError(Exception):
  """Raised when an inbound request fails actorJwt authentication or authorization."""

  def __init__(self, message: str, status_code: int = 401) -> None:
    super().__init__(message)
    self.status_code = status_code


@dataclass(frozen=True)
class ActorIdentity:
  """Verified Agent Substrate KindActor caller identity."""

  atespace: str
  actor_name: str
  actor_uid: str
  subject: str
  issuer: str
  audiences: tuple[str, ...]
  jti: str = ""


@dataclass(frozen=True)
class ActorJwtConfig:
  """Configuration for verifying Agent Substrate actorJwt bearer tokens."""

  require_actor_jwt: bool = True
  expected_issuer: Optional[str] = None
  expected_audience: Optional[str] = None
  jwks_path: Optional[str] = None
  jwks_url: Optional[str] = None
  jwks_json: Optional[str] = None
  allowed_atespaces: frozenset[str] = field(default_factory=frozenset)
  allowed_actors: frozenset[str] = field(default_factory=frozenset)
  leeway_seconds: float = 5.0
  jwks_cache_ttl_seconds: float = 60.0

  @classmethod
  def from_env(
      cls, environ: Optional[Mapping[str, str]] = None
  ) -> "ActorJwtConfig":
    """Loads ActorJwtConfig from environment variables."""
    env = os.environ if environ is None else environ
    raw_require = (env.get("GATEWAY_REQUIRE_ACTOR_JWT", "true") or "").strip().lower()
    if raw_require in {"1", "true", "yes", "on"}:
      require_jwt = True
    elif raw_require in {"0", "false", "no", "off"}:
      require_jwt = False
    else:
      raise ValueError(
          f"Invalid GATEWAY_REQUIRE_ACTOR_JWT value {raw_require!r}; "
          "expected 'true' or 'false'."
      )

    allowed_atespaces = _parse_csv_set(env.get("GATEWAY_ALLOWED_ATESPACES"))
    allowed_actors = _parse_csv_set(env.get("GATEWAY_ALLOWED_ACTORS"))
    leeway = float((env.get("GATEWAY_JWT_LEEWAY_SECONDS") or "5.0").strip())

    return cls(
        require_actor_jwt=require_jwt,
        expected_issuer=_clean_optional(env.get("GATEWAY_EXPECTED_ISSUER")),
        expected_audience=_clean_optional(env.get("GATEWAY_EXPECTED_AUDIENCE")),
        jwks_path=_clean_optional(env.get("GATEWAY_JWKS_PATH")),
        jwks_url=_clean_optional(env.get("GATEWAY_JWKS_URL")),
        jwks_json=_clean_optional(env.get("GATEWAY_JWKS_JSON")),
        allowed_atespaces=allowed_atespaces,
        allowed_actors=allowed_actors,
        leeway_seconds=leeway,
    )


def _clean_optional(value: Optional[str]) -> Optional[str]:
  if value is None:
    return None
  stripped = value.strip()
  return stripped if stripped else None


def _parse_csv_set(raw: Optional[str]) -> frozenset[str]:
  if not raw:
    return frozenset()
  return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _is_valid_rfc1123_label(value: str) -> bool:
  return bool(_RFC1123_LABEL_RE.match(value))


class ActorJwtVerifier:
  """Verifies Agent Substrate KindActor JWTs against an RFC 7517 JWKS source."""

  def __init__(self, config: ActorJwtConfig) -> None:
    self.config = config
    self._cached_keys: dict[str, tuple[str, Any]] = {}
    self._cache_expires_at: float = 0.0

    if self.config.require_actor_jwt:
      has_jwks = any(
          (self.config.jwks_path, self.config.jwks_url, self.config.jwks_json)
      )
      if not has_jwks:
        raise ValueError(
            "ActorJwtVerifier requires one of jwks_path, jwks_url, or jwks_json "
            "when require_actor_jwt=True."
        )
      if not self.config.expected_audience:
        raise ValueError(
            "ActorJwtVerifier requires expected_audience when "
            "require_actor_jwt=True."
        )

  def is_ready(self) -> bool:
    """Returns True if JWKS keys can be loaded (or auth is explicitly disabled)."""
    if not self.config.require_actor_jwt:
      return True
    try:
      keys = self._load_keys()
      return bool(keys)
    except Exception as exc:
      logger.error("JWKS readiness check failed: %s", exc)
      return False

  def _parse_jwks_payload(
      self, payload: Mapping[str, Any]
  ) -> dict[str, tuple[str, Any]]:
    raw_keys = payload.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
      raise ActorJwtAuthError("JWKS document contains no verification keys.", 503)

    parsed: dict[str, tuple[str, Any]] = {}
    for entry in raw_keys:
      if not isinstance(entry, Mapping):
        continue
      kid = entry.get("kid")
      alg = entry.get("alg")
      kty = entry.get("kty")
      if not isinstance(kid, str) or not kid:
        continue
      if alg not in ALLOWED_JWT_ALGORITHMS:
        logger.warning(
            "Skipping JWK kid=%s with unsupported algorithm %s", kid, alg
        )
        continue
      if kty == "EC" and alg == "ES256" and entry.get("crv") == "P-256":
        pub_key = jwt_algorithms.ECAlgorithm.from_jwk(json.dumps(dict(entry)))
      elif kty == "RSA" and alg in {"RS256", "RS384", "RS512"}:
        pub_key = jwt_algorithms.RSAAlgorithm.from_jwk(json.dumps(dict(entry)))
      else:
        logger.warning(
            "Skipping JWK kid=%s with mismatched kty=%s alg=%s", kid, kty, alg
        )
        continue
      parsed[kid] = (alg, pub_key)

    if not parsed:
      raise ActorJwtAuthError(
          "JWKS document contained no usable ES256/RS256/RS384/RS512 keys.", 503
      )
    return parsed

  def _load_keys(self, force_refresh: bool = False) -> dict[str, tuple[str, Any]]:
    now = time.monotonic()
    if (
        not force_refresh
        and self._cached_keys
        and now < self._cache_expires_at
    ):
      return self._cached_keys

    if self.config.jwks_json:
      doc = json.loads(self.config.jwks_json)
    elif self.config.jwks_path:
      jwks_file = Path(self.config.jwks_path)
      if not jwks_file.is_file():
        raise ActorJwtAuthError(
            f"Configured JWKS file not found: {self.config.jwks_path}", 503
        )
      doc = json.loads(jwks_file.read_text(encoding="utf-8"))
    elif self.config.jwks_url:
      try:
        resp = httpx.get(self.config.jwks_url, timeout=5.0)
        resp.raise_for_status()
        doc = resp.json()
      except Exception as exc:
        raise ActorJwtAuthError("Failed to fetch JWKS from upstream.", 503) from exc
    else:
      raise ActorJwtAuthError("No JWKS source configured.", 503)

    if not isinstance(doc, Mapping):
      raise ActorJwtAuthError("JWKS root must be a JSON object.", 503)

    self._cached_keys = self._parse_jwks_payload(doc)
    self._cache_expires_at = now + self.config.jwks_cache_ttl_seconds
    return self._cached_keys

  def verify_authorization_header(
      self, auth_header: Optional[str]
  ) -> ActorIdentity:
    """Verifies an HTTP Authorization: Bearer <jwt> header and returns ActorIdentity."""
    if not auth_header or not auth_header.strip():
      raise ActorJwtAuthError("Missing Authorization header.", 401)

    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
      raise ActorJwtAuthError("Authorization header must use Bearer scheme.", 401)

    return self.verify_token(parts[1].strip())

  def verify_token(self, token: str) -> ActorIdentity:
    """Verifies a raw JWT string against Agent Substrate KindActor invariants."""
    try:
      unverified_header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
      raise ActorJwtAuthError("Malformed JWT header.", 401) from exc

    alg = unverified_header.get("alg")
    kid = unverified_header.get("kid")
    if alg not in ALLOWED_JWT_ALGORITHMS:
      raise ActorJwtAuthError(
          f"Unsupported or disallowed JWT algorithm: {alg!r}.", 401
      )
    if not isinstance(kid, str) or not kid:
      raise ActorJwtAuthError("JWT header is missing required 'kid'.", 401)

    keys = self._load_keys()
    if kid not in keys:
      keys = self._load_keys(force_refresh=True)
    if kid not in keys:
      raise ActorJwtAuthError("Unknown signing key ID ('kid').", 401)

    key_alg, pub_key = keys[kid]
    if alg != key_alg:
      raise ActorJwtAuthError(
          "JWT header algorithm does not match JWK algorithm.", 401
      )

    decode_options = {
        "require": ["exp", "sub", "aud"],
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_aud": bool(self.config.expected_audience),
        "verify_iss": bool(self.config.expected_issuer),
    }

    try:
      claims: dict[str, Any] = jwt.decode(
          token,
          key=pub_key,
          algorithms=[key_alg],
          audience=self.config.expected_audience,
          issuer=self.config.expected_issuer,
          leeway=self.config.leeway_seconds,
          options=decode_options,
      )
    except jwt.ExpiredSignatureError as exc:
      raise ActorJwtAuthError("Actor JWT has expired.", 401) from exc
    except jwt.InvalidAudienceError as exc:
      raise ActorJwtAuthError("Actor JWT audience mismatch.", 403) from exc
    except jwt.InvalidIssuerError as exc:
      raise ActorJwtAuthError("Actor JWT issuer mismatch.", 403) from exc
    except jwt.PyJWTError as exc:
      raise ActorJwtAuthError("Actor JWT verification failed.", 401) from exc

    # Reject worker-for-actor tokens or ambiguous dual-kind tokens
    # (matches actoridjwt.go WireClaims.Substrate).
    if WORKER_FOR_ACTOR_CLAIM_KEY in claims:
      raise ActorJwtAuthError(
          "worker-for-actor tokens are not permitted on actor MCP gateways.",
          403,
      )

    actor_claim = claims.get(ACTOR_CLAIM_KEY)
    if not isinstance(actor_claim, Mapping):
      raise ActorJwtAuthError(
          f"Missing required {ACTOR_CLAIM_KEY!r} claim.", 403
      )

    if actor_claim.get("node"):
      raise ActorJwtAuthError(
          "KindActor token must not carry a worker node claim.", 403
      )

    atespace = actor_claim.get("atespace")
    actor_name = actor_claim.get("actorName")
    actor_uid = actor_claim.get("actorUID")
    if (
        not isinstance(atespace, str)
        or not _is_valid_rfc1123_label(atespace)
        or not isinstance(actor_name, str)
        or not _is_valid_rfc1123_label(actor_name)
        or not isinstance(actor_uid, str)
        or not actor_uid.strip()
    ):
      raise ActorJwtAuthError(
          "Invalid atespace, actorName, or actorUID in actor.ate.dev claim.",
          403,
      )

    expected_subject = f"actor/{atespace}/{actor_name}"
    subject = claims.get("sub")
    if subject != expected_subject:
      raise ActorJwtAuthError(
          "JWT subject does not match actor/<atespace>/<actorName>.", 403
      )

    if (
        self.config.allowed_atespaces
        and atespace not in self.config.allowed_atespaces
    ):
      raise ActorJwtAuthError(
          f"Atespace {atespace!r} is not authorized for this MCP gateway.", 403
      )

    qualified_actor = f"{atespace}/{actor_name}"
    if self.config.allowed_actors and (
        actor_name not in self.config.allowed_actors
        and qualified_actor not in self.config.allowed_actors
    ):
      raise ActorJwtAuthError(
          f"Actor {qualified_actor!r} is not authorized for this MCP gateway.",
          403,
      )

    raw_aud = claims.get("aud")
    if isinstance(raw_aud, str):
      audiences: tuple[str, ...] = (raw_aud,)
    elif isinstance(raw_aud, Iterable):
      audiences = tuple(str(item) for item in raw_aud)
    else:
      audiences = ()

    return ActorIdentity(
        atespace=atespace,
        actor_name=actor_name,
        actor_uid=actor_uid.strip(),
        subject=subject,
        issuer=str(claims.get("iss") or ""),
        audiences=audiences,
        jti=str(claims.get("jti") or ""),
    )


class ActorJwtMiddleware:
  """ASGI middleware enforcing Agent Substrate actorJwt authentication on MCP routes."""

  def __init__(
      self,
      app: ASGIApp,
      verifier: ActorJwtVerifier,
      exempt_paths: Iterable[str] = ("/healthz", "/readyz"),
  ) -> None:
    self.app = app
    self.verifier = verifier
    self.exempt_paths = frozenset(exempt_paths)

  async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] != "http":
      await self.app(scope, receive, send)
      return

    path = scope.get("path", "")
    if path in self.exempt_paths or not self.verifier.config.require_actor_jwt:
      await self.app(scope, receive, send)
      return

    auth_header: Optional[str] = None
    for raw_name, raw_val in scope.get("headers", ()):
      if raw_name.lower() == b"authorization":
        auth_header = raw_val.decode("latin-1")
        break

    try:
      identity = self.verifier.verify_authorization_header(auth_header)
    except ActorJwtAuthError as exc:
      logger.warning(
          "Rejected MCP gateway request on %s (status=%s): %s",
          path,
          exc.status_code,
          exc,
      )
      headers = {}
      if exc.status_code == 401:
        headers["WWW-Authenticate"] = 'Bearer realm="ate-mcp-gateway"'
      response = JSONResponse(
          {"error": "unauthorized", "detail": str(exc)},
          status_code=exc.status_code,
          headers=headers,
      )
      await response(scope, receive, send)
      return

    scope.setdefault("state", {})["actor_identity"] = identity
    logger.info(
        "Authorized MCP request on %s for actor=%s/%s uid=%s",
        path,
        identity.atespace,
        identity.actor_name,
        identity.actor_uid,
    )
    await self.app(scope, receive, send)
