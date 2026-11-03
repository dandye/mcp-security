# Zero-Secret Agent Substrate and AX Deployment for `gti-mcp`

This directory deploys the Google Threat Intelligence MCP server (`gti-mcp`) and its DSPy 3.4+ `GuardedRLMInterpreter` inside an [Agent Substrate](https://github.com/agent-substrate/substrate) (`ateworker-gvisor`) sandbox orchestrated by [AX](https://github.com/google/ax) (`ax.io/v1alpha1`) with zero credentials in the sandbox.

## Architecture

1. **Zero Ambient Credentials in the Sandbox**: `gti-mcp` runs with `GTI_ZERO_SECRET_EGRESS=true` and no `VT_APIKEY`, `GOOGLE_APPLICATION_CREDENTIALS`, or OAuth bearer tokens in `os.environ` or `/proc/self/environ`. Startup calls `verify_zero_secret_sandbox_env()` and fails closed if raw secrets leaked into the sandbox, while `GuardedRLMInterpreter` additionally scrubs worker subprocess environments before executing RLM Python turns.
2. **Projected CA Trust Bundle (`SSL_CERT_FILE`)**: The actor mounts the `atenet-egress` CA trust bundle (`egress-mitm.ate.dev` and `system-roots.ate.dev` via `systemInfo.dataSources[].trustBundle`) at `/run/ate/egress-ca/ca-bundle.crt` (avoiding `/var/run`, which is an absolute symlink to `/run` in Debian/Ubuntu images and rejected by `ateworker-gvisor` rootfs composition) and sets `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` so `vt.Client` (`aiohttp` with `trust_env=True`) and `dspy.LM` trust TLS interception at the egress gateway.
3. **Out-of-Sandbox `replaceHeaders` Injection (`atenet-egress`)**: `vt.Client` sends `x-apikey: ate-egress-injected` and `dspy.LM` sends `x-goog-api-key: ate-egress-injected`. `atenet-egress` terminates TLS, enforces a fail-closed default-deny `EgressPolicy`, resolves `ate-secret://secretmanager.googleapis.com/projects/${PROJECT_ID}/secrets/vt-apikey/versions/latest` and `.../gemini-api-key/versions/latest` over SPIFFE mTLS via `CredentialProvider.FetchSecret`, and overwrites `x-apikey` and `x-goog-api-key` on the wire exclusively for `www.virustotal.com` and `generativelanguage.googleapis.com`.
4. **GKE Node Compatibility (`ateworker-gvisor`)**: `sandbox-and-egress.yaml` configures the cluster-scoped `SandboxConfig` (`sandboxClass: gvisor`, gVisor `20261026.0`) and `WorkerPool` (`ateworker-gvisor`, with `metadata.labels.workload: gti-rlm-gvisor` so `ate-controller` propagates the label onto `Worker` resources for `ActorTemplate.workerSelector`), allowing pools to schedule on standard GKE Linux nodes even when `/dev/kvm` nested virtualization is disabled. On GKE Workload Identity clusters, mirror `gvisor.tar.zstd` into a Uniform Bucket-Level Access (UBLA) GCS bucket readable by `atelet` and add a `NetworkPolicy` in `ate-system` allowing `app: atenet-egress` to reach `app: gsm-credential-provider` on TCP port `50051` when GKE Dataplane V2 is enabled. `actor-template.yaml` and `egress-policy.yaml` are single-document `ateapi.v1` protojson manifests applied to `ate-api-server` via `kubectl-ate`.

## Prerequisites

- A GKE cluster with Agent Substrate (`v1.0.0-rc.1` or newer) installed in `ate-system`, `credprovider-gcp-secret-manager` (`gsm-credential-provider`) deployed with `gsm-credential-provider-project-policy` granting `atespace: secops` access to `${PROJECT_ID}`, and `atenet-egress` configured with `--credential-provider='{"name":"secretmanager.googleapis.com","address":"gsm-credential-provider.ate-system.svc:50051"}'`.
- AX (`ax-server` and `ax` CLI at `google/ax` commit `1dd2e92` or newer for Substrate `v1.0+` `substrate.ateapi.v1.Control` compatibility) installed in `ax-system`, and `ax-task-runner` present at `/usr/local/bin/ax-task-runner` in the task image.
- `kubectl`, `kubectl-ate`, `ax`, `gcloud`, and `envsubst` on `PATH`.

## Deployment Steps

### 1. Define Environment Variables

```bash
export PROJECT_ID="my-secops-project"
export ATESPACE="secops"
export WORKLOAD_NAMESPACE="ate-workloads"
export ACTOR_NAME="gti-mcp-rlm"
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

### 3. Apply Agent Substrate `SandboxConfig`, `WorkerPool`, `ActorTemplate`, and `EgressPolicy`

Apply the Kubernetes CRDs (`SandboxConfig`, `WorkerPool`) with `kubectl apply`, then register the `ate-api-server` `ActorTemplate` and singleton actor `EgressPolicy` via `kubectl ate`:

```bash
export PROJECT_ID="my-secops-project"
export ATESPACE="secops"
export WORKLOAD_NAMESPACE="ate-workloads"
export ACTOR_NAME="gti-mcp-rlm"

kubectl create namespace "$WORKLOAD_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f sandbox-and-egress.yaml

kubectl ate create atespace "$ATESPACE"
envsubst '${PROJECT_ID}' < actor-template.yaml | kubectl ate create actor-template -f -
kubectl ate create actor "$ACTOR_NAME" --atespace "$ATESPACE" --template gti-mcp-rlm
envsubst '${PROJECT_ID}' < egress-policy.yaml | kubectl ate create egress-policy "$ACTOR_NAME" --atespace "$ATESPACE" -f -
```

### 4. Apply AX `Model`, `Workspace`, and `Task`

Deploy the digest-pinned `ax.io/v1alpha1` resources (matching `google/ax` `1dd2e92` with `Model`, `Workspace`, and `Task` kinds only), attach the actor `EgressPolicy`, and resume the task:

```bash
export PROJECT_ID="my-secops-project"
export ATESPACE="secops"

envsubst '${PROJECT_ID}' < ax-gti-rlm.yaml | ax apply -a "$ATESPACE" -f -
envsubst '${PROJECT_ID}' < egress-policy.yaml | kubectl ate create egress-policy gti-rlm-file-investigator --atespace "$ATESPACE" -f -
ax get tasks -a "$ATESPACE"
ax describe task gti-rlm-file-investigator -a "$ATESPACE"
```

> Note: At `google/ax` `1dd2e92`, `BuildActorTemplate` mounts only `/workspace` by default. Before running `ax resume task gti-rlm-file-investigator -a "$ATESPACE"`, attach the `systemInfo` `trustBundle` volume (`egress-mitm.ate.dev` and `system-roots.ate.dev`) at `/run/ate/egress-ca` on the generated `<task>-<digest>` `ActorTemplate` so `SSL_CERT_FILE` resolves inside the task container.

## Verification

Confirm that `atenet-egress` denies non-allowlisted outbound hosts fail-closed and that no raw secrets exist inside the sandbox environment:

```bash
export ATESPACE="secops"
export ACTOR_NAME="gti-mcp-rlm"

kubectl ate get egress-policy "$ACTOR_NAME" --atespace "$ATESPACE" -o yaml
kubectl -n ate-system rollout status deployment/atenet-egress
kubectl -n ate-system logs deployment/atenet-egress -c ext-proc | grep "egress denied" || true
```
