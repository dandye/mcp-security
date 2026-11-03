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
"""PID 1 runner implementing the google/ax `/usr/local/bin/ax-task-runner` contract.

Implements the runner checklist documented in `google/ax/docs/runner.md`:
- Reads `AX_TASK_YAML` and `AX_WORKSPACE_YAML` (or `--task-file` / `--workspace-file`).
- Serves `/healthz` (`200`) and `/readyz` (`503` until workspace setup finishes, then `200`)
  on port `80` (configurable via `--port`).
- Serves `/metadata/v1alpha1/ax/task` and `/metadata/v1alpha1/ax/workspace` (`404` when
  unbound) on loopback (`127.0.0.1:8099`, configurable via `--metadata-port`) and exports
  `AX_METADATA_URL` to the child command.
- Materializes `Workspace.spec.files` once per durable `/workspace` volume using a marker
  file so suspend/resume cycles preserve agent workspace state.
- Supervises `Task.spec.command` in its own process group, stays alive after the child
  exits, and forwards `SIGTERM`/`SIGINT` cleanly with a bounded grace period.
"""

import argparse
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import logging
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_PROBE_PORT = 80
DEFAULT_METADATA_PORT = 8099
WORKSPACE_INIT_MARKER = ".ax-workspace-initialized"


class RunnerState:
  """Thread-safe state shared between the runner supervisor and HTTP servers."""

  def __init__(
      self,
      raw_task_yaml: str,
      raw_workspace_yaml: Optional[str],
  ) -> None:
    self.raw_task_yaml = raw_task_yaml
    self.raw_workspace_yaml = raw_workspace_yaml
    self.workspace_ready = threading.Event()
    self.stop_requested = threading.Event()


def _make_probe_handler(state: RunnerState) -> type[BaseHTTPRequestHandler]:
  class _ProbeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
      if self.path == "/healthz":
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return
      if self.path == "/readyz":
        if state.workspace_ready.is_set():
          body = b"ready\n"
          self.send_response(200)
        else:
          body = b"initializing\n"
          self.send_response(503)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return
      self.send_response(404)
      self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
      return

  return _ProbeHandler


def _make_metadata_handler(state: RunnerState) -> type[BaseHTTPRequestHandler]:
  class _MetadataHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
      if self.path == "/metadata/v1alpha1/ax/task":
        body = state.raw_task_yaml.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/yaml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return
      if self.path == "/metadata/v1alpha1/ax/workspace":
        if not state.raw_workspace_yaml:
          self.send_response(404)
          self.end_headers()
          return
        body = state.raw_workspace_yaml.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/yaml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return
      self.send_response(404)
      self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
      return

  return _MetadataHandler


def prepare_workspace_once(
    workspace_dir: Path,
    workspace_doc: Optional[Mapping[str, Any]],
) -> bool:
  """Materializes `Workspace.spec.files` idempotently once per durable volume.

  Returns:
    True if initialization ran on this boot, False if skipped via marker file.
  """
  workspace_dir.mkdir(parents=True, exist_ok=True)
  marker = workspace_dir / WORKSPACE_INIT_MARKER
  if marker.exists():
    logger.info(
        "Workspace marker %s exists; preserving restored workspace state.",
        marker,
    )
    return False

  if isinstance(workspace_doc, Mapping):
    spec = workspace_doc.get("spec")
    if isinstance(spec, Mapping):
      files = spec.get("files")
      if isinstance(files, list):
        root_resolved = workspace_dir.resolve()
        for entry in files:
          if not isinstance(entry, Mapping):
            continue
          rel_path = (entry.get("path") or "").strip()
          content = entry.get("content")
          if not rel_path or not isinstance(content, str):
            continue
          target = (workspace_dir / rel_path).resolve()
          if target != root_resolved and root_resolved not in target.parents:
            raise ValueError(
                f"Workspace file path {rel_path!r} escapes {workspace_dir}."
            )
          target.parent.mkdir(parents=True, exist_ok=True)
          target.write_text(content, encoding="utf-8")

      skills_cfg = spec.get("skills")
      if isinstance(skills_cfg, Mapping):
        skills_rel = (skills_cfg.get("path") or ".agents/skills").strip().lstrip("/")
        skills_target = (workspace_dir / skills_rel).resolve()
        root_resolved = workspace_dir.resolve()
        if skills_target == root_resolved or root_resolved in skills_target.parents:
          skills_target.mkdir(parents=True, exist_ok=True)

  marker.write_text("initialized\n", encoding="utf-8")
  return True


def _terminate_process_group(
    proc: subprocess.Popen[bytes], grace_seconds: float
) -> None:
  if proc.poll() is not None:
    return
  try:
    os.killpg(proc.pid, signal.SIGTERM)
  except ProcessLookupError:
    return

  deadline = time.monotonic() + grace_seconds
  while time.monotonic() < deadline:
    if proc.poll() is not None:
      return
    time.sleep(0.05)

  if proc.poll() is None:
    try:
      os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
      pass
    proc.wait(timeout=2.0)


def run_runner(
    *,
    raw_task_yaml: str,
    raw_workspace_yaml: Optional[str],
    probe_host: str = "0.0.0.0",
    probe_port: int = DEFAULT_PROBE_PORT,
    metadata_port: int = DEFAULT_METADATA_PORT,
    workspace_override: Optional[Path] = None,
    grace_seconds: float = 5.0,
    exit_after_command: bool = False,
) -> tuple[int, int, int]:
  """Starts the probe + loopback metadata servers, prepares `/workspace`, and supervises `spec.command`."""
  task_doc = yaml.safe_load(raw_task_yaml) if raw_task_yaml.strip() else {}
  if not isinstance(task_doc, Mapping):
    task_doc = {}
  ws_doc = (
      yaml.safe_load(raw_workspace_yaml)
      if raw_workspace_yaml and raw_workspace_yaml.strip()
      else None
  )

  spec = task_doc.get("spec") if isinstance(task_doc.get("spec"), Mapping) else {}
  ws_binding = spec.get("workspace") if isinstance(spec.get("workspace"), Mapping) else {}
  configured_ws_path = str(ws_binding.get("path") or "/workspace").strip() or "/workspace"
  workspace_dir = (
      workspace_override
      if workspace_override is not None
      else Path(configured_ws_path)
  )

  state = RunnerState(
      raw_task_yaml=raw_task_yaml,
      raw_workspace_yaml=raw_workspace_yaml,
  )

  probe_srv = ThreadingHTTPServer(
      (probe_host, probe_port), _make_probe_handler(state)
  )
  bound_probe_port = int(probe_srv.server_address[1])
  metadata_srv = ThreadingHTTPServer(
      ("127.0.0.1", metadata_port), _make_metadata_handler(state)
  )
  bound_metadata_port = int(metadata_srv.server_address[1])

  probe_thread = threading.Thread(target=probe_srv.serve_forever, daemon=True)
  meta_thread = threading.Thread(target=metadata_srv.serve_forever, daemon=True)
  probe_thread.start()
  meta_thread.start()

  child_proc: Optional[subprocess.Popen[bytes]] = None
  child_exit_code = 0

  def _handle_signal(signum: int, _frame: Any) -> None:
    logger.info("Received signal %s; initiating runner shutdown.", signum)
    state.stop_requested.set()

  prev_sigterm = signal.getsignal(signal.SIGTERM)
  prev_sigint = signal.getsignal(signal.SIGINT)
  if threading.current_thread() is threading.main_thread():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

  try:
    prepare_workspace_once(workspace_dir, ws_doc if isinstance(ws_doc, Mapping) else None)
    state.workspace_ready.set()

    raw_cmd = spec.get("command")
    command: list[str] = (
        [str(item) for item in raw_cmd if str(item)]
        if isinstance(raw_cmd, list)
        else []
    )

    child_env = dict(os.environ)
    child_env["AX_METADATA_URL"] = f"http://127.0.0.1:{bound_metadata_port}"
    raw_env_entries = spec.get("env")
    if isinstance(raw_env_entries, list):
      for item in raw_env_entries:
        if isinstance(item, Mapping) and item.get("name"):
          child_env[str(item["name"])] = str(item.get("value") or "")

    if command:
      logger.info("Starting AX task command %s in %s", command, workspace_dir)
      child_proc = subprocess.Popen(
          command,
          cwd=str(workspace_dir),
          env=child_env,
          start_new_session=True,
      )
      while not state.stop_requested.is_set():
        polled = child_proc.poll()
        if polled is not None:
          child_exit_code = polled
          logger.info(
              "Task command exited with status %s; keeping runner alive until SIGTERM.",
              child_exit_code,
          )
          break
        state.stop_requested.wait(timeout=0.1)

    if not exit_after_command:
      while not state.stop_requested.is_set():
        state.stop_requested.wait(timeout=0.25)

    if child_proc is not None:
      _terminate_process_group(child_proc, grace_seconds=grace_seconds)
      if child_proc.returncode is not None:
        child_exit_code = child_proc.returncode
  finally:
    if threading.current_thread() is threading.main_thread():
      signal.signal(signal.SIGTERM, prev_sigterm)
      signal.signal(signal.SIGINT, prev_sigint)
    probe_srv.shutdown()
    probe_srv.server_close()
    metadata_srv.shutdown()
    metadata_srv.server_close()

  return child_exit_code, bound_probe_port, bound_metadata_port


def _build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
      description="AX task runner for mcp-security-agent sandboxes."
  )
  parser.add_argument(
      "--task-file",
      default=None,
      help="Optional path to a Task YAML file (overrides AX_TASK_YAML).",
  )
  parser.add_argument(
      "--workspace-file",
      default=None,
      help="Optional path to a Workspace YAML file (overrides AX_WORKSPACE_YAML).",
  )
  parser.add_argument(
      "--port",
      type=int,
      default=int(os.environ.get("AX_RUNNER_PORT", str(DEFAULT_PROBE_PORT))),
      help="HTTP port for /healthz and /readyz wakeup probes (default: 80).",
  )
  parser.add_argument(
      "--metadata-port",
      type=int,
      default=int(
          os.environ.get("AX_RUNNER_METADATA_PORT", str(DEFAULT_METADATA_PORT))
      ),
      help="Loopback port for /metadata/v1alpha1/ax/* (default: 8099).",
  )
  parser.add_argument(
      "--workspace-dir",
      default=None,
      help="Optional override directory for workspace preparation.",
  )
  return parser


def main(argv: Optional[list[str]] = None) -> None:
  logging.basicConfig(level=logging.INFO)
  args = _build_parser().parse_args(argv)

  if args.task_file:
    raw_task = Path(args.task_file).read_text(encoding="utf-8")
  else:
    raw_task = os.environ.get("AX_TASK_YAML", "")

  if args.workspace_file:
    raw_ws: Optional[str] = Path(args.workspace_file).read_text(encoding="utf-8")
  else:
    raw_ws = os.environ.get("AX_WORKSPACE_YAML") or None

  ws_override = Path(args.workspace_dir) if args.workspace_dir else None
  run_runner(
      raw_task_yaml=raw_task,
      raw_workspace_yaml=raw_ws,
      probe_port=args.port,
      metadata_port=args.metadata_port,
      workspace_override=ws_override,
  )


if __name__ == "__main__":
  main()
