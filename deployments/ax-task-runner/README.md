# ax-task-runner (Python)

Minimal-dependency (`pyyaml` only) implementation of the
[google/ax runner contract](https://github.com/google/ax/blob/main/docs/runner.md)
for custom AX `Task` container images. It is installed inside the untrusted
sandbox image (`deployments/ax-mcp-gateway/Dockerfile.ax-agent`), so it has no
cloud SDKs, JWT, or HTTP client dependencies.

Implemented:

- `/usr/local/bin/ax-task-runner` console script.
- `GET /healthz` (200) and `GET /readyz` (503 until the workspace is prepared) on port 80.
- `GET /metadata/v1alpha1/ax/task` and `/workspace` on loopback `127.0.0.1:8099`,
  exported to the command as `AX_METADATA_URL`.
- Idempotent materialization of `Workspace.spec.files` and `spec.skills.path`
  using a marker file on the durable `/workspace` volume.
- `Task.spec.command` supervision in its own process group, PID 1 zombie
  reaping, stay-alive after exit, and `SIGTERM` forwarding with a 10s grace period.

Not implemented (set `spec.debug: false` and do not rely on `spec.git`):

- `spec.debug` guest gRPC services (`ax ssh`).
- `Workspace.spec.git` cloning and MCP config file generation.

If you need either of those, extend the upstream `ax-task-runner` image instead
(runner.md, option 1) and keep its entrypoint.

```bash
uv run --directory deployments/ax-task-runner --extra test pytest ../ax-mcp-gateway/tests/test_ax_task_runner.py
```
