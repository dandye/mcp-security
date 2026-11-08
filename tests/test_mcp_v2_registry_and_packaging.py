# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Phase 6 contract suite for Official MCP Registry server.json manifests and package sync."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any
import unicodedata

from mcp.client import Client
from mcp.server.mcpserver import MCPServer
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _pkg_dir in (
    REPO_ROOT / "server" / "secops",
    REPO_ROOT / "server" / "gti",
    REPO_ROOT / "server" / "secops-soar",
    REPO_ROOT / "server" / "scc",
    REPO_ROOT / "run-with-google-adk" / "src",
):
    _pkg_str = str(_pkg_dir)
    if _pkg_str not in sys.path:
        sys.path.insert(0, _pkg_str)

from gti_mcp.server import server as gti_server  # noqa: E402
import mcp_security_agent  # noqa: E402
from scc_mcp import mcp as scc_server  # noqa: E402
from secops_mcp.server import server as secops_server  # noqa: E402
from secops_soar_mcp import server as soar_server_mod  # noqa: E402

REGISTRY_SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
REGISTRY_NAME_RE = re.compile(r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

SERVER_MANIFEST_CONTRACTS: list[tuple[str, str, str, str, MCPServer]] = [
    (
        "secops",
        "io.github.google/google-secops-mcp",
        "google-secops-mcp",
        "0.9.0",
        secops_server,
    ),
    (
        "gti",
        "io.github.google/gti-mcp",
        "gti-mcp",
        "0.2.0",
        gti_server,
    ),
    (
        "secops-soar",
        "io.github.google/secops-soar-mcp",
        "secops-soar-mcp",
        "0.3.0",
        soar_server_mod.mcp,
    ),
    (
        "scc",
        "io.github.google/scc-mcp",
        "scc-mcp",
        "0.3.0",
        scc_server,
    ),
]


def _extract_setup_py_metadata(setup_path: Path) -> dict[str, Any]:
    """Extract literal name, version, and install_requires from setup(...) in setup.py."""
    tree = ast.parse(setup_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            func_name = (
                func.id
                if isinstance(func, ast.Name)
                else (func.attr if isinstance(func, ast.Attribute) else None)
            )
            if func_name == "setup":
                extracted: dict[str, Any] = {}
                for kw in node.keywords:
                    if kw.arg in ("name", "version") and isinstance(kw.value, ast.Constant):
                        extracted[kw.arg] = kw.value.value
                    elif kw.arg == "install_requires" and isinstance(
                        kw.value, (ast.List, ast.Tuple)
                    ):
                        extracted["install_requires"] = [
                            elt.value
                            for elt in kw.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        ]
                return extracted
    return {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("subdir", "expected_registry_name", "expected_pypi_name", "expected_version", "mcp_server"),
    SERVER_MANIFEST_CONTRACTS,
    ids=[entry[0] for entry in SERVER_MANIFEST_CONTRACTS],
)
async def test_server_registry_manifest_and_version_synchronization(
    subdir: str,
    expected_registry_name: str,
    expected_pypi_name: str,
    expected_version: str,
    mcp_server: MCPServer,
) -> None:
    """Assert pyproject.toml, setup.py, server.json, and runtime MCPServer.version match 100%."""
    pkg_dir = REPO_ROOT / "server" / subdir
    pyproject_path = pkg_dir / "pyproject.toml"
    setup_path = pkg_dir / "setup.py"
    manifest_path = pkg_dir / "server.json"

    assert pyproject_path.is_file(), f"Missing {pyproject_path}"
    assert manifest_path.is_file(), f"Missing {manifest_path}"

    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    py_name = pyproject["project"]["name"]
    py_version = pyproject["project"]["version"]
    py_deps = pyproject["project"]["dependencies"]
    assert py_name == expected_pypi_name
    assert py_version == expected_version
    assert SEMVER_RE.fullmatch(py_version)
    assert "mcp[cli]>=2.3.0,<3.0.0" in py_deps, (
        f"{subdir}: pyproject.toml missing mcp[cli]>=2.3.0,<3.0.0 floor"
    )

    assert setup_path.is_file(), f"Missing {setup_path}"
    setup_meta = _extract_setup_py_metadata(setup_path)
    assert setup_meta.get("name") == py_name, (
        f"{subdir}: setup.py name {setup_meta.get('name')} != pyproject.toml {py_name}"
    )
    assert setup_meta.get("version") == py_version, (
        f"{subdir}: setup.py version {setup_meta.get('version')} != pyproject.toml {py_version}"
    )
    assert "mcp[cli]>=2.3.0,<3.0.0" in setup_meta.get("install_requires", []), (
        f"{subdir}: setup.py missing mcp[cli]>=2.3.0,<3.0.0 floor"
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest.get("$schema") == REGISTRY_SCHEMA_URL
    assert manifest.get("name") == expected_registry_name
    assert REGISTRY_NAME_RE.fullmatch(manifest["name"])
    assert manifest.get("version") == py_version

    description = manifest.get("description", "")
    assert isinstance(description, str)
    assert 1 <= len(description) <= 100, (
        f"{subdir}: server.json description length {len(description)} violates 1..100 schema bound"
    )

    repo = manifest.get("repository", {})
    assert repo.get("url") == "https://github.com/google/mcp-security"
    assert repo.get("source") == "github"
    assert repo.get("subfolder") == f"server/{subdir}"

    packages = manifest.get("packages", [])
    assert isinstance(packages, list) and len(packages) >= 1
    pypi_pkg = packages[0]
    assert pypi_pkg.get("registryType") == "pypi"
    assert pypi_pkg.get("identifier") == py_name
    assert pypi_pkg.get("version") == py_version
    assert pypi_pkg.get("transport") == {"type": "stdio"}
    env_vars = pypi_pkg.get("environmentVariables", [])
    assert isinstance(env_vars, list) and len(env_vars) >= 1

    remotes = manifest.get("remotes", [])
    assert isinstance(remotes, list) and len(remotes) >= 1
    assert any(r.get("type") == "streamable-http" for r in remotes)

    async with Client(mcp_server) as client:
        info = client.server_info
        assert info is not None
        assert info.version == py_version
        assert info.title == manifest.get("title")


def test_adk_agent_package_version_synchronization() -> None:
    """Verify run-with-google-adk pyproject.toml version, __version__, and dependency floors."""
    adk_pyproject = tomllib.loads(
        (REPO_ROOT / "run-with-google-adk" / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert adk_pyproject["project"]["name"] == "mcp-security-agent"
    assert adk_pyproject["project"]["version"] == "0.3.0"
    assert mcp_security_agent.__version__ == adk_pyproject["project"]["version"]
    adk_deps = adk_pyproject["project"]["dependencies"]
    assert "mcp[cli]>=2.3.0,<3.0.0" in adk_deps
    assert "google-adk[mcp]>=2.13.0,<3.0.0" in adk_deps


def test_workflows_pin_pip_installs_and_sync_server_json() -> None:
    """Ensure publish-packages.yml and ci-mcp-tests.yml pin pip installs and check server.json."""
    publish_wf = (REPO_ROOT / ".github" / "workflows" / "publish-packages.yml").read_text(
        encoding="utf-8"
    )
    ci_wf = (REPO_ROOT / ".github" / "workflows" / "ci-mcp-tests.yml").read_text(encoding="utf-8")

    assert "server.json" in publish_wf
    assert "test_mcp_v2_registry_and_packaging.py" in ci_wf
    assert "pip install --upgrade pip" not in publish_wf
    assert "pip install packaging build twine" not in publish_wf
    assert "pip install build twine" not in publish_wf

    for wf_name, content in (("publish-packages.yml", publish_wf), ("ci-mcp-tests.yml", ci_wf)):
        for ch in content:
            code = ord(ch)
            assert not (
                code > 0x1F000
                or (0x2600 <= code <= 0x27BF)
                or (code > 0x2000 and unicodedata.category(ch) == "So")
            ), f"Found emoji/symbol {ch!r} in {wf_name}"


def test_setup_py_extractor_detects_version_and_name_drift(tmp_path: Path) -> None:
    """Verify _extract_setup_py_metadata parses setup(...) literals accurately."""
    sample_setup = tmp_path / "setup.py"
    sample_setup.write_text(
        'from setuptools import setup\n'
        'setup(name="sample-mcp", version="1.2.3", install_requires=["mcp[cli]>=2.3.0,<3.0.0"])\n',
        encoding="utf-8",
    )
    meta = _extract_setup_py_metadata(sample_setup)
    assert meta == {
        "name": "sample-mcp",
        "version": "1.2.3",
        "install_requires": ["mcp[cli]>=2.3.0,<3.0.0"],
    }
    assert meta["version"] != "1.2.4"
