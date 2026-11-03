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
"""Strict schema validation tests for AX, Agent Substrate, and K8s manifests."""

from pathlib import Path
import re

import yaml

MANIFESTS_DIR = Path(__file__).resolve().parents[1] / "manifests"
_RFC1123_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def test_ax_manifest_conforms_to_ax_v1alpha1_strict_protojson() -> None:
  raw = (MANIFESTS_DIR / "ax-secops-gateway-task.yaml").read_text(encoding="utf-8")
  rendered = raw.replace("${PROJECT_ID}", "my-secops-project").replace(
      "${GOOGLE_CLOUD_LOCATION}", "global"
  )
  assert len(rendered.encode("utf-8")) <= 31 * 1024

  docs = list(yaml.safe_load_all(rendered))
  assert [d["kind"] for d in docs] == ["Workspace", "Task"]

  for doc in docs:
    assert doc["apiVersion"] == "ax.io/v1alpha1"
    meta = doc["metadata"]
    assert set(meta.keys()) <= {"name", "atespace"}
    assert _RFC1123_LABEL_RE.match(meta["name"])
    assert _RFC1123_LABEL_RE.match(meta["atespace"])

  ws_doc, task_doc = docs
  assert set(ws_doc["spec"].keys()) <= {"git", "files", "mcp", "skills"}
  mcp_servers = ws_doc["spec"]["mcp"]["servers"]
  assert len(mcp_servers) == 4
  expected_endpoints = {
      "secops": "http://secops-mcp.secops-gateways.svc.cluster.local:8080/mcp",
      "gti": "http://gti-mcp.secops-gateways.svc.cluster.local:8080/mcp",
      "secops-soar": "http://secops-soar-mcp.secops-gateways.svc.cluster.local:8080/mcp",
      "scc": "http://scc-mcp.secops-gateways.svc.cluster.local:8080/mcp",
  }
  assert {s["name"]: s["endpoint"] for s in mcp_servers} == expected_endpoints

  task_spec = task_doc["spec"]
  assert set(task_spec.keys()) <= {
      "image",
      "command",
      "env",
      "resources",
      "workspace",
      "debug",
      "config",
  }
  assert "@sha256:" in task_spec["image"]
  digest = task_spec["image"].split("@sha256:", 1)[1]
  assert _SHA256_RE.match(digest)

  # Substrate rejects requests; only limits are permitted on Task.spec.resources.
  assert "requests" not in task_spec["resources"]
  assert set(task_spec["resources"]["limits"].keys()) == {"cpu", "memory"}
  # spec.config is runner-defined; this runner reads none, so the manifest omits it.
  assert "config" not in task_spec
  assert task_spec["debug"] is False

  env_map = {item["name"]: item["value"] for item in task_spec["env"]}
  assert env_map["AX_ZERO_SECRET_SANDBOX"] == "true"
  assert env_map["MCP_GATEWAY_AUTH_HEADER"] == "Bearer ate-egress-injected"
  assert (
      env_map["LLM_GATEWAY_URL"]
      == "http://llm-gateway.secops-gateways.svc.cluster.local:8080/vertex"
  )
  assert env_map["GOOGLE_CLOUD_PROJECT"] == "my-secops-project"
  assert env_map["GOOGLE_CLOUD_LOCATION"] == "global"


def test_egress_policy_conforms_to_ateapi_v1_single_doc_protojson() -> None:
  raw = (MANIFESTS_DIR / "egress-policy.yaml").read_text(encoding="utf-8")
  docs = list(yaml.safe_load_all(raw))
  assert len(docs) == 1, "EgressPolicy must be a single protojson document (no ---)"

  policy = docs[0]
  assert "apiVersion" not in policy
  assert "kind" not in policy
  assert set(policy.keys()) == {"metadata", "rules"}
  assert policy["metadata"] == {"atespace": "secops", "name": "default"}

  rules = policy["rules"]
  assert len(rules) == 5
  seen_audiences: set[str] = set()
  for rule in rules:
    assert set(rule.keys()) == {"http"}
    http_cfg = rule["http"]
    assert set(http_cfg.keys()) == {"hostnames", "ports", "effects"}
    assert http_cfg["ports"] == {"numbers": [8080]}
    rep = http_cfg["effects"]["replaceHeaders"]
    assert len(rep) == 1
    entry = rep[0]
    assert entry["header"] == "Authorization"
    assert entry["prefix"] == "Bearer "
    assert "credentialUri" not in entry
    actor_jwt = entry["actorJwt"]
    assert 300 <= actor_jwt["expirationSeconds"] <= 3600
    assert len(actor_jwt["audiences"]) == 1
    seen_audiences.update(actor_jwt["audiences"])

  assert seen_audiences == {
      "http://secops-mcp.secops-gateways.svc.cluster.local:8080",
      "http://gti-mcp.secops-gateways.svc.cluster.local:8080",
      "http://secops-soar-mcp.secops-gateways.svc.cluster.local:8080",
      "http://scc-mcp.secops-gateways.svc.cluster.local:8080",
      "http://llm-gateway.secops-gateways.svc.cluster.local:8080",
  }


def test_substrate_crds_conform_to_ate_dev_v1_strict_schema() -> None:
  raw = (MANIFESTS_DIR / "sandbox-and-workerpool.yaml").read_text(encoding="utf-8")
  rendered = raw.replace(
      "${ATEWORKER_GVISOR_IMAGE}",
      "us-docker.pkg.dev/my-secops-project/ate-system/ateworker-gvisor@sha256:"
      + ("7" * 64),
  )
  docs = list(yaml.safe_load_all(rendered))
  assert [d["kind"] for d in docs] == ["WorkerPool"]

  wp = docs[0]
  assert wp["apiVersion"] == "ate.dev/v1"
  assert wp["metadata"]["namespace"] == "ate-workloads"
  assert "@sha256:" in wp["spec"]["workerImage"]
  assert wp["spec"]["sandboxClasses"] == [
      {"name": "gvisor", "configRef": {"name": "gvisor-default"}}
  ]
  for k in wp["spec"]["template"].get("labels", {}):
    assert not k.startswith("ate.dev/") and ".ate.dev/" not in k


def test_kubernetes_gateways_enforce_network_policy_live_jwks_and_audiences() -> None:
  raw = (MANIFESTS_DIR / "mcp-gateways-k8s.yaml").read_text(encoding="utf-8")
  rendered = (
      raw.replace("${PROJECT_ID}", "my-secops-project")
      .replace("${GOOGLE_CLOUD_LOCATION}", "global")
      .replace("${CHRONICLE_PROJECT_ID}", "my-secops-project")
      .replace("${CHRONICLE_CUSTOMER_ID}", "00000000-0000-0000-0000-000000000000")
      .replace("${CHRONICLE_REGION}", "us")
      .replace("${SOAR_URL}", "https://example.siemplify-soar.com")
      .replace("${SOAR_INTEGRATIONS}", "Siemplify")
      .replace("${ACTOR_JWT_ISSUER}", "https://idp.ate-system.svc")
  )
  docs = list(yaml.safe_load_all(rendered))

  netpols = [d for d in docs if d["kind"] == "NetworkPolicy"]
  assert len(netpols) == 1
  ingress_from = netpols[0]["spec"]["ingress"][0]["from"][0]
  assert ingress_from["namespaceSelector"]["matchLabels"] == {
      "kubernetes.io/metadata.name": "ate-system"
  }
  assert ingress_from["podSelector"]["matchLabels"] == {"app": "atenet-egress"}

  deployments = {d["metadata"]["name"]: d for d in docs if d["kind"] == "Deployment"}
  services = {d["metadata"]["name"]: d for d in docs if d["kind"] == "Service"}
  expected_gateways = {
      "secops-mcp",
      "gti-mcp",
      "secops-soar-mcp",
      "scc-mcp",
      "llm-gateway",
  }
  assert set(deployments.keys()) == expected_gateways
  assert set(services.keys()) == expected_gateways

  for name, dep in deployments.items():
    pod_spec = dep["spec"]["template"]["spec"]
    assert pod_spec["securityContext"]["runAsNonRoot"] is True
    container = pod_spec["containers"][0]
    assert "@sha256:" in container["image"]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["livenessProbe"]["timeoutSeconds"] == 5
    assert container["readinessProbe"]["timeoutSeconds"] == 5

    env_map = {e["name"]: e.get("value") for e in container["env"]}
    assert env_map["GATEWAY_REQUIRE_ACTOR_JWT"] == "true"
    assert env_map["GATEWAY_EXPECTED_ISSUER"] == "https://idp.ate-system.svc"
    assert (
        env_map["GATEWAY_JWKS_URL"]
        == "https://idp.ate-system.svc/openid/v1/jwks"
    )
    assert (
        env_map["GATEWAY_JWKS_CA_FILE"]
        == "/run/servicedns-ca/trust-bundle.pem"
    )
    assert env_map["GATEWAY_ALLOWED_ATESPACES"] == "secops"
    assert env_map["GATEWAY_ALLOWED_ACTORS"] == "secops/secops-triage-agent"
    assert (
        env_map["GATEWAY_EXPECTED_AUDIENCE"]
        == f"http://{name}.secops-gateways.svc.cluster.local:8080"
    )

    vol_map = {v["name"]: v for v in pod_spec["volumes"]}
    assert "servicedns-ca" in vol_map
    ctb = vol_map["servicedns-ca"]["projected"]["sources"][0]["clusterTrustBundle"]
    assert ctb["signerName"] == "servicedns.podcert.ate.dev/identity"

  soar_env = {
      e["name"]: e.get("value")
      for e in deployments["secops-soar-mcp"]["spec"]["template"]["spec"][
          "containers"
      ][0]["env"]
  }
  assert soar_env["SOAR_INTEGRATIONS"] == "Siemplify"
