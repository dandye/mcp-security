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
"""AX (ax.io/v1alpha1) Workspace MCP endpoint discovery and zero-secret sandbox guard."""

from collections.abc import Mapping
import logging
import os
from pathlib import Path
import re
from typing import Any, Optional
import urllib.error
import urllib.parse
import urllib.request

import yaml

logger = logging.getLogger(__name__)

ZERO_SECRET_SANDBOX_ENV = "AX_ZERO_SECRET_SANDBOX"
DEFAULT_GATEWAY_AUTH_PLACEHOLDER = "Bearer ate-egress-injected"

FORBIDDEN_SANDBOX_SECRET_ENV_VARS: tuple[str, ...] = (
    "VT_APIKEY",
    "SOAR_APP_KEY",
    "SECOPS_SA_PATH",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
)

_FORBIDDEN_SANDBOX_KEYS_UPPER = frozenset(
    key.upper() for key in FORBIDDEN_SANDBOX_SECRET_ENV_VARS
)

FORBIDDEN_SECRET_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_oauth_access_token", re.compile(r"^ya29\.[0-9A-Za-z\-_]+")),
    ("google_api_key", re.compile(r"^AIza[0-9A-Za-z\-_]{30,}")),
    ("llm_secret_key", re.compile(r"^sk-(?:ant-|proj-)?[0-9A-Za-z\-_]{20,}")),
    ("github_pat", re.compile(r"^gh[pousr]_[0-9A-Za-z]{20,}")),
)

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

# Maps canonical Workspace.spec.mcp.servers[].name aliases to AgentSettings fields.
_WORKSPACE_SERVER_ALIASES: dict[str, str] = {
    "secops": "secops",
    "secops-mcp": "secops",
    "secops_mcp": "secops",
    "google-secops-mcp": "secops",
    "chronicle": "secops",
    "gti": "gti",
    "gti-mcp": "gti",
    "gti_mcp": "gti",
    "secops-soar": "secops_soar",
    "secops-soar-mcp": "secops_soar",
    "secops_soar_mcp": "secops_soar",
    "soar": "secops_soar",
    "soar-mcp": "secops_soar",
    "scc": "scc",
    "scc-mcp": "scc",
    "scc_mcp": "scc",
}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
  """Blocks HTTP 30x redirects when querying loopback AX metadata."""

  def redirect_request(
      self,
      req: urllib.request.Request,
      fp: Any,
      code: int,
      msg: str,
      headers: Any,
      newurl: str,
  ) -> None:
    raise urllib.error.HTTPError(
        req.full_url,
        code,
        f"Redirects are not permitted on AX_METADATA_URL ({msg})",
        headers,
        fp,
    )


def is_valid_http_endpoint(url: str) -> bool:
  """Returns True when `url` is a well-formed `http://` or `https://` endpoint."""
  parsed = urllib.parse.urlparse(url.strip())
  return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _is_valid_loopback_metadata_url(url: str) -> bool:
  parsed = urllib.parse.urlparse(url.strip())
  if parsed.scheme != "http" or not parsed.hostname:
    return False
  return parsed.hostname.lower() in _LOOPBACK_HOSTS


def is_ax_zero_secret_sandbox(
    environ: Optional[Mapping[str, str]] = None,
) -> bool:
  """Returns True when AX_ZERO_SECRET_SANDBOX is enabled."""
  env = os.environ if environ is None else environ
  raw = (env.get(ZERO_SECRET_SANDBOX_ENV) or "").strip().lower()
  if raw in {"1", "true", "yes", "on", "y"}:
    return True
  if raw in {"", "0", "false", "no", "off", "n"}:
    return False
  raise ValueError(
      f"Invalid {ZERO_SECRET_SANDBOX_ENV} value {raw!r}; "
      "expected 'true' or 'false'."
  )


def _read_proc_environ(proc_environ_path: str) -> Optional[dict[str, str]]:
  if not os.path.exists(proc_environ_path):
    return None
  try:
    with open(proc_environ_path, "rb") as proc_file:
      raw_bytes = proc_file.read()
  except OSError:
    return None

  parsed: dict[str, str] = {}
  for entry in raw_bytes.split(b"\x00"):
    if not entry or b"=" not in entry:
      continue
    key_b, val_b = entry.split(b"=", 1)
    parsed[key_b.decode("utf-8", errors="replace")] = val_b.decode(
        "utf-8", errors="replace"
    )
  return parsed


def _scan_secret_violations(mapping: Mapping[str, str]) -> list[str]:
  findings: set[str] = set()
  for key, raw_value in mapping.items():
    stripped = (raw_value or "").strip()
    if not stripped:
      continue
    if key.upper() == "MCP_GATEWAY_AUTH_HEADER":
      if any(p.search(stripped) for _, p in FORBIDDEN_SECRET_VALUE_PATTERNS):
        findings.add(f"{key} (secret_pattern)")
      elif stripped != DEFAULT_GATEWAY_AUTH_PLACEHOLDER:
        findings.add(f"{key} (non_placeholder_auth_header)")
      continue
    if key.upper() in _FORBIDDEN_SANDBOX_KEYS_UPPER:
      findings.add(key)
      continue
    for label, pattern in FORBIDDEN_SECRET_VALUE_PATTERNS:
      if pattern.search(stripped):
        findings.add(f"{key} ({label})")
        break
  return sorted(findings)


def _scan_mounted_credential_files(
    env: Mapping[str, str],
    *,
    k8s_sa_token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token",
) -> list[str]:
  """Checks for mounted credential files inside the sandbox without echoing contents."""
  violations: list[str] = []
  if k8s_sa_token_path and Path(k8s_sa_token_path).is_file():
    violations.append(f"file:{k8s_sa_token_path}")

  cwd_adc = Path.cwd() / ".gcloud" / "application_default_credentials.json"
  if cwd_adc.is_file():
    violations.append("file:.gcloud/application_default_credentials.json")

  cloudsdk_cfg = (env.get("CLOUDSDK_CONFIG") or "").strip()
  if cloudsdk_cfg:
    cfg_adc = Path(cloudsdk_cfg) / "application_default_credentials.json"
    if cfg_adc.is_file():
      violations.append("file:CLOUDSDK_CONFIG/application_default_credentials.json")

  explicit_home = (env.get("HOME") or "").strip()
  if explicit_home:
    home_adc = (
        Path(explicit_home)
        / ".config"
        / "gcloud"
        / "application_default_credentials.json"
    )
    if home_adc.is_file():
      violations.append(
          "file:$HOME/.config/gcloud/application_default_credentials.json"
      )
  return violations


def verify_zero_secret_sandbox(
    environ: Optional[Mapping[str, str]] = None,
    proc_environ_path: Optional[str] = "/proc/self/environ",
    *,
    check_files: bool = True,
    k8s_sa_token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token",
) -> dict[str, Any]:
  """Verifies fail-closed that no cloud or API secrets leaked into the AX sandbox."""
  if not is_ax_zero_secret_sandbox(environ):
    return {"zero_secret_sandbox": False, "verified": False}

  os_env = dict(os.environ if environ is None else environ)
  violations: list[str] = [
      f"os.environ:{item}" for item in _scan_secret_violations(os_env)
  ]

  if proc_environ_path:
    explicit_proc = proc_environ_path != "/proc/self/environ"
    if environ is None or explicit_proc:
      proc_map = _read_proc_environ(proc_environ_path)
      if proc_map is not None:
        proc_booted_zero_secret = False
        try:
          proc_booted_zero_secret = is_ax_zero_secret_sandbox(proc_map)
        except ValueError:
          proc_booted_zero_secret = True

        candidate_map = (
            proc_map
            if (explicit_proc or proc_booted_zero_secret)
            else {k: v for k, v in proc_map.items() if k in os_env}
        )
        violations.extend(
            f"{proc_environ_path}:{item}"
            for item in _scan_secret_violations(candidate_map)
        )

  if check_files:
    violations.extend(
        _scan_mounted_credential_files(
            os_env, k8s_sa_token_path=k8s_sa_token_path
        )
    )

  if violations:
    joined = ", ".join(violations)
    logger.error(
        "Zero-secret AX sandbox check failed (%s=true): %s",
        ZERO_SECRET_SANDBOX_ENV,
        joined,
    )
    raise ValueError(
        f"Zero-secret sandbox violation ({ZERO_SECRET_SANDBOX_ENV}=true): "
        f"raw credentials must not be present inside the AX task sandbox ({joined}). "
        "Keep credentials in out-of-sandbox MCP gateways and inject actorJwt at "
        "atenet-egress."
    )

  return {"zero_secret_sandbox": True, "verified": True}


def _extract_endpoints_from_workspace_doc(
    doc: Mapping[str, Any]
) -> dict[str, str]:
  """Extracts validated `{server_key: endpoint_url}` entries from an AX Workspace."""
  spec = doc.get("spec")
  if not isinstance(spec, Mapping):
    return {}
  mcp_cfg = spec.get("mcp")
  if not isinstance(mcp_cfg, Mapping):
    return {}

  entries: list[Mapping[str, Any]] = []
  raw_servers = mcp_cfg.get("servers")
  if isinstance(raw_servers, list):
    entries.extend(item for item in raw_servers if isinstance(item, Mapping))

  raw_registries = mcp_cfg.get("registries")
  if isinstance(raw_registries, list):
    for reg in raw_registries:
      if isinstance(reg, Mapping) and isinstance(reg.get("servers"), list):
        entries.extend(
            item for item in reg["servers"] if isinstance(item, Mapping)
        )

  discovered: dict[str, str] = {}
  for srv in entries:
    raw_name = (srv.get("name") or "").strip().lower()
    endpoint = (srv.get("endpoint") or "").strip()
    if not raw_name or not endpoint:
      continue
    if not is_valid_http_endpoint(endpoint):
      logger.warning(
          "Ignoring AX Workspace MCP server %s with non-HTTP(S) endpoint %r",
          raw_name,
          endpoint,
      )
      continue
    canonical = _WORKSPACE_SERVER_ALIASES.get(raw_name)
    if canonical and canonical not in discovered:
      discovered[canonical] = endpoint
  return discovered


def discover_ax_workspace_mcp_endpoints(
    environ: Optional[Mapping[str, str]] = None,
    metadata_timeout_seconds: float = 1.5,
) -> dict[str, str]:
  """Discovers Streamable HTTP MCP endpoints from AX_WORKSPACE_YAML or loopback AX_METADATA_URL."""
  env = os.environ if environ is None else environ
  raw_ws_yaml = (env.get("AX_WORKSPACE_YAML") or "").strip()
  if raw_ws_yaml:
    try:
      doc = yaml.safe_load(raw_ws_yaml)
      if isinstance(doc, Mapping):
        return _extract_endpoints_from_workspace_doc(doc)
    except Exception as exc:
      logger.warning("Failed to parse AX_WORKSPACE_YAML: %s", exc)

  metadata_base = (env.get("AX_METADATA_URL") or "").strip().rstrip("/")
  if metadata_base:
    if not _is_valid_loopback_metadata_url(metadata_base):
      raise ValueError(
          f"AX_METADATA_URL must target a loopback http:// endpoint; got {metadata_base!r}."
      )
    ws_url = f"{metadata_base}/metadata/v1alpha1/ax/workspace"
    try:
      opener = urllib.request.build_opener(_NoRedirectHandler())
      req = urllib.request.Request(
          ws_url, headers={"Accept": "application/yaml"}
      )
      with opener.open(req, timeout=metadata_timeout_seconds) as resp:
        if resp.status == 200:
          body = resp.read().decode("utf-8", errors="replace")
          doc = yaml.safe_load(body)
          if isinstance(doc, Mapping):
            return _extract_endpoints_from_workspace_doc(doc)
    except Exception as exc:
      logger.debug(
          "AX workspace metadata endpoint %s unavailable: %s", ws_url, exc
      )

  return {}
