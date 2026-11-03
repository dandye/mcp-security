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
"""Contract tests for the Python ax-task-runner (deployments/ax-task-runner)."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request

import pytest

from ax_task_runner import prepare_workspace_once, run_runner


def _free_port() -> int:
  import socket

  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    return int(sock.getsockname()[1])


def _wait_status(url: str, timeout_s: float = 10.0) -> int:
  deadline = time.monotonic() + timeout_s
  last = 0
  while time.monotonic() < deadline:
    try:
      with urllib.request.urlopen(url, timeout=1.0) as resp:
        return resp.status
    except urllib.error.HTTPError as exc:
      last = exc.code
      if last == 503:
        return last
    except Exception:
      pass
    time.sleep(0.05)
  return last


def test_ax_task_runner_contract_probes_metadata_and_idempotent_workspace(
    tmp_path: Path,
) -> None:
  ws_dir = tmp_path / "workspace"
  ws_doc = {
      "apiVersion": "ax.io/v1alpha1",
      "kind": "Workspace",
      "spec": {
          "files": [{"path": "AGENTS.md", "content": "initial-workspace\n"}]
      },
  }
  assert prepare_workspace_once(ws_dir, ws_doc) is True
  assert (ws_dir / "AGENTS.md").read_text(encoding="utf-8") == "initial-workspace\n"

  # Simulate agent modifying AGENTS.md before gVisor suspend/resume
  (ws_dir / "AGENTS.md").write_text("agent-mutated\n", encoding="utf-8")
  assert prepare_workspace_once(ws_dir, ws_doc) is False
  assert (ws_dir / "AGENTS.md").read_text(encoding="utf-8") == "agent-mutated\n"

  # Path traversal in Workspace.spec.files is rejected
  bad_ws_dir = tmp_path / "bad_ws"
  with pytest.raises(ValueError, match="escapes"):
    prepare_workspace_once(
        bad_ws_dir,
        {"spec": {"files": [{"path": "../escaped.txt", "content": "bad"}]}},
    )

  # Full run_runner execution verifies AX_METADATA_URL and command supervision
  run_ws_dir = tmp_path / "runner_ws"
  out_file = tmp_path / "child_meta.txt"
  task_yaml = json.dumps(
      {
          "apiVersion": "ax.io/v1alpha1",
          "kind": "Task",
          "metadata": {"name": "test-task", "atespace": "secops"},
          "spec": {
              "command": [
                  sys.executable,
                  "-P",
                  "-c",
                  (
                      "import os, urllib.request, pathlib; "
                      "u = os.environ['AX_METADATA_URL'] + '/metadata/v1alpha1/ax/workspace'; "
                      "data = urllib.request.urlopen(u).read().decode('utf-8'); "
                      f"pathlib.Path({str(out_file)!r}).write_text(data, encoding='utf-8')"
                  ),
              ],
              "workspace": {"name": "ws", "path": str(run_ws_dir)},
          },
      }
  )
  ws_yaml = json.dumps(ws_doc)
  code, _, _ = run_runner(
      raw_task_yaml=task_yaml,
      raw_workspace_yaml=ws_yaml,
      probe_host="127.0.0.1",
      probe_port=0,
      metadata_port=0,
      workspace_override=run_ws_dir,
      exit_after_command=True,
  )
  assert code == 0
  assert "initial-workspace" in out_file.read_text(encoding="utf-8")




def test_ax_task_runner_stays_alive_after_command_exit_and_forwards_sigterm(
    tmp_path: Path,
) -> None:
  """PID 1 contract: keep serving after the child exits; SIGTERM reaches the child's process group."""
  ws_dir = tmp_path / "ws"
  child_marker = tmp_path / "child_got_sigterm.txt"
  # Child: writes its pid, then sleeps until SIGTERM, then records the signal.
  child_src = (
      "import os, signal, sys, time, pathlib\n"
      f"marker = pathlib.Path({str(child_marker)!r})\n"
      "def h(s, f):\n"
      "  marker.write_text('sigterm')\n"
      "  sys.exit(0)\n"
      "signal.signal(signal.SIGTERM, h)\n"
      "while True:\n"
      "  time.sleep(0.05)\n"
  )
  probe_port = _free_port()
  meta_port = _free_port()
  task_yaml = json.dumps(
      {
          "apiVersion": "ax.io/v1alpha1",
          "kind": "Task",
          "metadata": {"name": "t", "atespace": "secops"},
          "spec": {
              "command": [sys.executable, "-P", "-c", child_src],
              "workspace": {"name": "ws", "path": str(ws_dir)},
              "env": [{"name": "FROM_SPEC_ENV", "value": "1"}],
          },
      }
  )
  runner_proc = subprocess.Popen(
      [
          sys.executable,
          "-P",
          "-m",
          "ax_task_runner",
          "--port",
          str(probe_port),
          "--metadata-port",
          str(meta_port),
          "--workspace-dir",
          str(ws_dir),
      ],
      env={**os.environ, "AX_TASK_YAML": task_yaml},
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT,
  )
  try:
    assert _wait_status(f"http://127.0.0.1:{probe_port}/readyz") == 200
    assert _wait_status(f"http://127.0.0.1:{probe_port}/healthz") == 200
    # Workspace metadata is 404 when no workspace is bound.
    assert _wait_status(f"http://127.0.0.1:{meta_port}/metadata/v1alpha1/ax/workspace") == 404
    time.sleep(0.3)
    assert runner_proc.poll() is None

    runner_proc.send_signal(signal.SIGTERM)
    out, _ = runner_proc.communicate(timeout=15)
    assert runner_proc.returncode == 0, out.decode("utf-8", errors="replace")
    assert child_marker.read_text() == "sigterm"
  finally:
    if runner_proc.poll() is None:
      runner_proc.kill()


def test_ax_task_runner_workspace_failure_stays_not_ready_instead_of_crashing(
    tmp_path: Path,
) -> None:
  """Matches upstream: workspace prep failure logs and leaves /readyz at 503; PID 1 keeps serving."""
  ws_dir = tmp_path / "ws"
  task_yaml = json.dumps({"spec": {"workspace": {"name": "ws", "path": str(ws_dir)}}})
  bad_ws_yaml = json.dumps(
      {"spec": {"files": [{"path": "../escape.txt", "content": "bad"}]}}
  )
  probe_port = _free_port()
  runner_proc = subprocess.Popen(
      [
          sys.executable,
          "-P",
          "-m",
          "ax_task_runner",
          "--port",
          str(probe_port),
          "--metadata-port",
          "0",
          "--workspace-dir",
          str(ws_dir),
      ],
      env={**os.environ, "AX_TASK_YAML": task_yaml, "AX_WORKSPACE_YAML": bad_ws_yaml},
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT,
  )
  try:
    assert _wait_status(f"http://127.0.0.1:{probe_port}/healthz") == 200
    assert _wait_status(f"http://127.0.0.1:{probe_port}/readyz") == 503
    time.sleep(0.3)
    assert runner_proc.poll() is None, "runner must not crashloop on workspace failure"
    assert not (tmp_path / "escape.txt").exists()
    runner_proc.send_signal(signal.SIGTERM)
    out, _ = runner_proc.communicate(timeout=15)
    assert b"Workspace preparation failed" in out
  finally:
    if runner_proc.poll() is None:
      runner_proc.kill()
