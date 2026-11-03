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
"""Pytest configuration: fail fast with a clear message when test deps are missing.

The gateway tests import the four real google/mcp-security server packages and
the sibling ax-task-runner package. They are declared in the `test` extra of
`pyproject.toml` (resolved from this checkout via `[tool.uv.sources]`), so the
supported invocation is:

    uv run --directory deployments/ax-mcp-gateway --extra test pytest tests
"""

import importlib.util

import pytest

_REQUIRED_TEST_MODULES = {
    "ax_mcp_gateway": "deployments/ax-mcp-gateway",
    "ax_task_runner": "deployments/ax-task-runner",
    "gti_mcp": "server/gti",
    "scc_mcp": "server/scc",
    "secops_mcp": "server/secops",
    "secops_soar_mcp": "server/secops-soar",
}


def pytest_sessionstart(session: pytest.Session) -> None:
  missing = [
      f"{mod} ({src})"
      for mod, src in _REQUIRED_TEST_MODULES.items()
      if importlib.util.find_spec(mod) is None
  ]
  if missing:
    raise pytest.UsageError(
        "Missing test dependencies: "
        + ", ".join(missing)
        + ". Run: uv run --directory deployments/ax-mcp-gateway --extra test pytest tests"
    )
