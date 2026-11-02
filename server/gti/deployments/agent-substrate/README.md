# Zero-Secret Agent Substrate and AX Deployment for `gti-mcp`

This directory deploys the Google Threat Intelligence MCP server (`gti-mcp`) and its DSPy 3.4+ `GuardedRLMInterpreter` inside an [Agent Substrate](https://github.com/agent-substrate/substrate) (`ateworker-gvisor`) sandbox orchestrated by [AX](https://github.com/google/ax) (`ax.io/v1alpha1`) with zero credentials in the sandbox.

## Architecture

1. **Zero Ambient Credentials in the Sandbox**: `gti-mcp` runs with `GTI_ZERO_SECRET_EGRESS=true` and no `VT_APIKEY`, `GOOGLE_APPLICATION_CREDENTIALS`, or OAuth bearer tokens in `os.environ` or `/proc/self/environ`. Startup calls `verify_zero_secret_sandbox_env()` and fails closed if raw secrets leaked into the sandbox, while `GuardedRLMInterpreter` additionally scrubs worker subprocess environments before executing RLM Python turns.
2. **Projected CA Trust Bundle (`SSL_CERT_FILE`)**: The actor mounts the `atenet-egress` CA trust bundle at `/var/run/ate/egress-ca/ca-bundle.crt` and sets `SSL_CERT_FILE` so `vt.Client` (`aiohttp` with `trust_env=True`) trusts TLS interception at the egress gateway.
3. **Out-of-Sandbox `replaceHeaders` Injection (`atenet-egress`)**: `vt.Client` sends `x-apikey: ate-egress-injected`. `atenet-egress` terminates TLS, enforces a fail-closed default-deny `EgressPolicy`, resolves `ate-secret://secretmanager.googleapis.com/projects/${PROJECT_ID}/secrets/vt-apikey/versions/latest` over SPIFFE mTLS via `CredentialProvider.FetchSecret`, and overwrites `x-apikey` on the wire exclusively for `www.virustotal.com`.
4. **GKE Node Compatibility (`ateworker-gvisor`)**: `sandbox-and-egress.yaml` selects the `gvisor` sandbox class (`runsc` user-space Sentry kernel with `CAP_NET_RAW` stripped), so pools schedule on standard GKE Linux nodes even when `/dev/kvm` nested virtualization is disabled.

## Prerequisites

- A GKE cluster with Agent Substrate installed in `ate-system` and `atenet-egress` configured with `--credential-provider='{"name":"secretmanager.googleapis.com","address":"gcp-sm-credential-provider.ate-system.svc:50051"}'`.
- AX (`ax-server` and `ax` CLI) installed in `ax-system`.
- `kubectl`, `kubectl-ate`, `ax`, `gcloud`, and `envsubst` on `PATH`.

## Deployment Steps

### 1. Define Environment Variables

```bash
export PROJECT_ID="my-secops-project"
export ATESPACE="secops"
export WORKLOAD_NAMESPACE="ate-workloads"
```

### 2. Provision Secrets Outside the Sandbox

Store the real VirusTotal/GTI API key in Google Cloud Secret Manager (read exclusively by the out-of-sandbox `CredentialProvider` pod in `ate-system`) and create the Kubernetes Secret referenced by the `ax.io/v1alpha1` `Model` resource:

```bash
export PROJECT_ID="my-secops-project"
export VT_SECRET_NAME="vt-apikey"
export GEMINI_SECRET_NAME="gemini-api-key"
export REAL_VT_APIKEY="<your-virustotal-apikey>"
export REAL_GEMINI_API_KEY="<your-gemini-api-key>"

printf "%s" "$REAL_VT_APIKEY" | gcloud secrets create "$VT_SECRET_NAME" \
  --project="$PROJECT_ID" \
  --replication-policy="automatic" \
  --data-file=-

printf "%s" "$REAL_GEMINI_API_KEY" | gcloud secrets create "$GEMINI_SECRET_NAME" \
  --project="$PROJECT_ID" \
  --replication-policy="automatic" \
  --data-file=-

kubectl create secret generic gemini-api-secret \
  --namespace="ax-system" \
  --from-literal=GEMINI_API_KEY="$REAL_GEMINI_API_KEY"
```

### 3. Apply Agent Substrate `SandboxConfig`, `WorkerPool`, and `EgressPolicy`

Render `${PROJECT_ID}` and apply the Kubernetes CRDs (`SandboxConfig`, `WorkerPool`) and Substrate control-plane resources (`ActorTemplate`, `EgressPolicy`):

```bash
export PROJECT_ID="my-secops-project"
export ATESPACE="secops"
export WORKLOAD_NAMESPACE="ate-workloads"

kubectl create namespace "$WORKLOAD_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl ate create atespace "$ATESPACE"

envsubst '${PROJECT_ID}' < sandbox-and-egress.yaml > /tmp/rendered-sandbox-and-egress.yaml
kubectl apply -f /tmp/rendered-sandbox-and-egress.yaml
```

### 4. Apply AX `Model`, `Workspace`, and `Task`

Deploy the digest-pinned `ax.io/v1alpha1` resources (matching `google/ax` `b82f57ee` with `Model`, `Workspace`, and `Task` kinds only):

```bash
export PROJECT_ID="my-secops-project"
export ATESPACE="secops"

envsubst '${PROJECT_ID}' < ax-gti-rlm.yaml | ax apply -a "$ATESPACE" -f -
ax get tasks -a "$ATESPACE"
ax describe task gti-rlm-file-investigator -a "$ATESPACE"
```

## Verification

Confirm that `atenet-egress` denies non-allowlisted outbound hosts fail-closed and that no raw secrets exist inside the sandbox environment:

```bash
export ATESPACE="secops"

kubectl -n ate-system rollout status deployment/atenet-egress
kubectl -n ate-system logs deployment/atenet-egress -c ext-proc | grep "egress denied" || true
```
