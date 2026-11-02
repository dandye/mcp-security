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
"""Zero-secret Agent Substrate atenet-egress environment and TLS helpers."""

from collections.abc import Mapping
import logging
import os
import re
import ssl
from typing import Any, Optional, Union

logger = logging.getLogger(__name__)

ZERO_SECRET_EGRESS_ENV = "GTI_ZERO_SECRET_EGRESS"
ZERO_SECRET_PLACEHOLDER_APIKEY = "ate-egress-injected"

__all__ = [
    "FORBIDDEN_SANDBOX_SECRET_ENV_VARS",
    "FORBIDDEN_SECRET_VALUE_PATTERNS",
    "ZERO_SECRET_EGRESS_ENV",
    "ZERO_SECRET_PLACEHOLDER_APIKEY",
    "build_sanitized_repl_env",
    "build_vt_ssl_context",
    "is_zero_secret_egress_enabled",
    "verify_zero_secret_sandbox_env",
]

_TRUTHY_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSY_VALUES = frozenset({"", "0", "false", "no", "off"})

FORBIDDEN_SANDBOX_SECRET_ENV_VARS: tuple[str, ...] = (
    "VT_APIKEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "OAUTH_BEARER_TOKEN",
    "BEARER_TOKEN",
    "AUTHORIZATION",
    "GH_TOKEN",
    "GITHUB_TOKEN",
)

_FORBIDDEN_SANDBOX_KEYS_UPPER = frozenset(
    key.upper() for key in FORBIDDEN_SANDBOX_SECRET_ENV_VARS
)

FORBIDDEN_SECRET_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("oauth_bearer_token", re.compile(r"^Bearer\s+\S+", re.IGNORECASE)),
    ("google_oauth_access_token", re.compile(r"^ya29\.[0-9A-Za-z\-_]+")),
    ("google_api_key", re.compile(r"^AIza[0-9A-Za-z\-_]{30,}")),
    ("llm_secret_key", re.compile(r"^sk-(?:ant-|proj-)?[0-9A-Za-z\-_]{20,}")),
    ("github_pat", re.compile(r"^gh[pousr]_[0-9A-Za-z]{20,}")),
)

_REPL_SCRUB_SUFFIXES: tuple[str, ...] = (
    "_APIKEY",
    "_API_KEY",
    "_SECRET",
    "_SECRET_KEY",
    "_ACCESS_TOKEN",
    "_SESSION_TOKEN",
    "_BEARER_TOKEN",
    "_PRIVATE_KEY",
    "_PASSWORD",
)


def is_zero_secret_egress_enabled(
    environ: Optional[Mapping[str, str]] = None,
) -> bool:
  """Returns True when GTI_ZERO_SECRET_EGRESS is enabled."""
  env = os.environ if environ is None else environ
  raw_val = (env.get(ZERO_SECRET_EGRESS_ENV) or "").strip().lower()
  if raw_val in _TRUTHY_VALUES:
    return True
  if raw_val in _FALSY_VALUES:
    return False
  raise ValueError(
      f"Invalid {ZERO_SECRET_EGRESS_ENV} value {raw_val!r}; "
      "expected one of 'true', 'false', '1', or '0'."
  )


def _read_proc_environ(
    proc_environ_path: str = "/proc/self/environ",
    *,
    strict_missing: bool = False,
) -> Optional[dict[str, str]]:
  """Parses NUL-delimited KEY=VALUE pairs from a Linux /proc/*/environ file."""
  if not os.path.exists(proc_environ_path):
    if strict_missing:
      raise FileNotFoundError(
          f"Configured proc_environ_path does not exist: {proc_environ_path}"
      )
    return None
  try:
    with open(proc_environ_path, "rb") as proc_file:
      raw_bytes = proc_file.read()
  except OSError as exc:
    if strict_missing:
      raise
    logger.debug("Skipping unreadable %s: %s", proc_environ_path, exc)
    return None

  parsed: dict[str, str] = {}
  for entry in raw_bytes.split(b"\x00"):
    if not entry or b"=" not in entry:
      continue
    key_bytes, val_bytes = entry.split(b"=", 1)
    key = key_bytes.decode("utf-8", errors="replace")
    val = val_bytes.decode("utf-8", errors="replace")
    parsed[key] = val
  return parsed


def _find_secret_leaks_in_mapping(mapping: Mapping[str, str]) -> list[str]:
  """Returns sorted descriptions of forbidden credential variables or token values."""
  findings: set[str] = set()
  for key, raw_value in mapping.items():
    stripped = (raw_value or "").strip()
    if not stripped:
      continue
    if key.upper() in _FORBIDDEN_SANDBOX_KEYS_UPPER:
      findings.add(key)
      continue
    for pattern_label, pattern in FORBIDDEN_SECRET_VALUE_PATTERNS:
      if pattern.search(stripped):
        findings.add(f"{key} ({pattern_label})")
        break
  return sorted(findings)


def verify_zero_secret_sandbox_env(
    environ: Optional[Mapping[str, str]] = None,
    proc_environ_path: Optional[str] = "/proc/self/environ",
) -> dict[str, Any]:
  """Verifies no raw credentials exist in os.environ or /proc/self/environ.

  When GTI_ZERO_SECRET_EGRESS is enabled, outbound requests must carry only the
  non-secret placeholder token while Agent Substrate atenet-egress injects real
  credentials outside the sandbox via replaceHeaders. If raw API keys, cloud
  credential paths, or OAuth bearer tokens leaked into the sandbox environment,
  this function fails closed with a ValueError without logging secret values.
  """
  if not is_zero_secret_egress_enabled(environ):
    return {
        "zero_secret_egress": False,
        "verified": False,
        "placeholder_token": None,
        "inspected_sources": [],
    }

  os_env = dict(os.environ if environ is None else environ)
  inspected_sources: list[str] = ["os.environ"]
  violations: list[str] = []

  os_leaks = _find_secret_leaks_in_mapping(os_env)
  if os_leaks:
    violations.extend(f"os.environ:{item}" for item in os_leaks)

  if proc_environ_path:
    explicit_proc_path = proc_environ_path != "/proc/self/environ"
    if environ is None or explicit_proc_path:
      proc_map = _read_proc_environ(
          proc_environ_path, strict_missing=explicit_proc_path
      )
      if proc_map is not None:
        inspected_sources.append(proc_environ_path)
        proc_booted_zero_secret = False
        try:
          proc_booted_zero_secret = is_zero_secret_egress_enabled(proc_map)
        except ValueError:
          proc_booted_zero_secret = True

        if explicit_proc_path or proc_booted_zero_secret:
          candidate_proc_map = proc_map
        else:
          candidate_proc_map = {
              k: v for k, v in proc_map.items() if k in os_env
          }

        proc_leaks = _find_secret_leaks_in_mapping(candidate_proc_map)
        if proc_leaks:
          violations.extend(
              f"{proc_environ_path}:{item}" for item in proc_leaks
          )

  if violations:
    joined = ", ".join(violations)
    logger.error(
        "Zero-secret sandbox verification failed (%s=true); "
        "raw credentials leaked into sandbox environment: %s",
        ZERO_SECRET_EGRESS_ENV,
        joined,
    )
    raise ValueError(
        f"Zero-secret egress violation ({ZERO_SECRET_EGRESS_ENV}=true): "
        f"raw credentials must not be present in the sandbox environment ({joined}). "
        "Remove sandbox secret env vars and inject credentials at atenet-egress "
        "via EgressPolicy replaceHeaders."
    )

  return {
      "zero_secret_egress": True,
      "verified": True,
      "placeholder_token": ZERO_SECRET_PLACEHOLDER_APIKEY,
      "inspected_sources": inspected_sources,
  }


def build_vt_ssl_context(
    environ: Optional[Mapping[str, str]] = None,
) -> Union[bool, ssl.SSLContext]:
  """Builds an SSLContext honoring SSL_CERT_FILE and SSL_CERT_DIR for aiohttp.

  aiohttp caches its default verified SSLContext at module import time, so
  projected CA trust bundles mounted via SSL_CERT_FILE (such as Agent Substrate
  atenet-egress TLS interception CAs or corporate proxies) must be loaded into
  an explicit ssl.SSLContext per client creation.
  """
  env = os.environ if environ is None else environ
  cafile = (env.get("SSL_CERT_FILE") or "").strip() or None
  capath = (env.get("SSL_CERT_DIR") or "").strip() or None
  if not cafile and not capath:
    return True

  ssl_ctx = ssl.create_default_context(cafile=cafile, capath=capath)
  ssl_ctx.set_alpn_protocols(("http/1.1",))
  return ssl_ctx


def build_sanitized_repl_env(
    environ: Optional[Mapping[str, str]] = None,
) -> dict[str, str]:
  """Returns a credential-scrubbed environment dict for GuardedRLMInterpreter."""
  source_env = os.environ if environ is None else environ
  sanitized: dict[str, str] = {}
  for key, value in source_env.items():
    upper_key = key.upper()
    if upper_key in _FORBIDDEN_SANDBOX_KEYS_UPPER:
      continue
    if any(upper_key.endswith(suffix) for suffix in _REPL_SCRUB_SUFFIXES):
      continue
    stripped = (value or "").strip()
    if stripped and any(
        pattern.search(stripped)
        for _label, pattern in FORBIDDEN_SECRET_VALUE_PATTERNS
    ):
      continue
    sanitized[key] = value
  return sanitized
