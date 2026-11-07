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
"""Phase 2 suite: Stateless 2026-07-28 Streamable HTTP, SEP-2549 CacheHint, and OpenTelemetry."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from httpx2 import ASGITransport, AsyncClient
from mcp.client import Client
from mcp.server._otel import OpenTelemetryMiddleware
from mcp.server.mcpserver import MCPServer
from mcp_types.jsonrpc import UNSUPPORTED_PROTOCOL_VERSION
import opentelemetry.trace as otel_trace
from opentelemetry.trace import SpanKind
import pytest
from starlette.applications import Starlette

REPO_ROOT = Path(__file__).resolve().parent.parent
for _pkg_dir in (
    REPO_ROOT / "server" / "secops",
    REPO_ROOT / "server" / "gti",
    REPO_ROOT / "server" / "secops-soar",
    REPO_ROOT / "server" / "scc",
):
    _pkg_str = str(_pkg_dir)
    if _pkg_str not in sys.path:
        sys.path.insert(0, _pkg_str)

from gti_mcp import server as gti_server_mod  # noqa: E402
import scc_mcp as scc_server_mod  # noqa: E402
from secops_mcp import server as secops_server_mod  # noqa: E402
from secops_soar_mcp import bindings as soar_bindings  # noqa: E402
from secops_soar_mcp import server as soar_server_mod  # noqa: E402


@dataclass(frozen=True)
class RecordedSpan:
    """Normalized view of an OpenTelemetry server span across SDK or API providers."""

    name: str
    kind: SpanKind
    trace_id_hex: str
    parent_span_id_hex: str | None
    attributes: dict[str, Any]


@dataclass(frozen=True)
class ServerTarget:
    """Descriptor for each of the 4 MCP servers under test."""

    name: str
    title: str
    version: str
    module: Any
    server: MCPServer
    build_http_app: Callable[..., Starlette]
    mock_tool_name: str
    mock_tool_args: dict[str, Any]


SERVER_TARGETS: list[ServerTarget] = [
    ServerTarget(
        name="secops-mcp",
        title="Google Security Operations SIEM MCP Server",
        version="0.9.0",
        module=secops_server_mod,
        server=secops_server_mod.server,
        build_http_app=secops_server_mod.build_streamable_http_app,
        mock_tool_name="search_udm",
        mock_tool_args={"query": 'metadata.event_type = "USER_LOGIN"'},
    ),
    ServerTarget(
        name="gti-mcp",
        title="Google Threat Intelligence MCP Server",
        version="0.2.0",
        module=gti_server_mod,
        server=gti_server_mod.server,
        build_http_app=gti_server_mod.build_streamable_http_app,
        mock_tool_name="get_threat_profile",
        mock_tool_args={"profile_id": "prof-fin7"},
    ),
    ServerTarget(
        name="secops-soar-mcp",
        title="Google Security Operations SOAR MCP Server",
        version="0.3.0",
        module=soar_server_mod,
        server=soar_server_mod.mcp,
        build_http_app=soar_server_mod.build_streamable_http_app,
        mock_tool_name="list_cases",
        mock_tool_args={"next_page_token": None},
    ),
    ServerTarget(
        name="scc-mcp",
        title="Google Cloud Security Command Center MCP Server",
        version="0.3.0",
        module=scc_server_mod,
        server=scc_server_mod.mcp,
        build_http_app=scc_server_mod.build_streamable_http_app,
        mock_tool_name="top_vulnerability_findings",
        mock_tool_args={"project_id": "demo-project", "max_findings": 1},
    ),
]


@pytest.fixture(scope="module", autouse=True)
def _register_soar_sample_integrations() -> None:
    """Ensure sample SOAR marketplace tools are registered alongside built-in case tools."""
    soar_server_mod.register_tools("CSV,Siemplify")


@asynccontextmanager
async def _asgi_http_client(
    app: Starlette,
    *,
    base_url: str = "http://127.0.0.1:8000",
) -> AsyncIterator[AsyncClient]:
    """Enter Starlette lifespan (StreamableHTTPSessionManager) and yield an ASGI AsyncClient."""
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=base_url) as client:
            yield client


@contextmanager
def _mock_backend_for_server(server_name: str) -> Iterator[None]:
    """Patch external API clients so tool execution over HTTP stays 100% offline."""
    if server_name == "secops-mcp":
        mock_chronicle = MagicMock()
        mock_chronicle.search_udm.return_value = {
            "total_events": 1,
            "events": [{"id": "evt-1001"}],
        }
        with patch(
            "secops_mcp.tools.search.get_chronicle_client",
            return_value=mock_chronicle,
        ):
            yield
    elif server_name == "gti-mcp":
        fake_vt_client = AsyncMock()
        fake_vt_client.close_async = AsyncMock()
        with (
            patch(
                "gti_mcp.server.vt_client_factory",
                return_value=fake_vt_client,
            ),
            patch(
                "gti_mcp.tools.threat_profiles.utils.fetch_object",
                new=AsyncMock(
                    return_value={
                        "id": "prof-fin7",
                        "type": "threat_profile",
                        "attributes": {"name": "FIN7"},
                    }
                ),
            ),
        ):
            yield
    elif server_name == "secops-soar-mcp":
        fake_soar_http = AsyncMock()
        fake_soar_http.get.return_value = {
            "cases": [{"id": "101", "title": "Suspicious Outbound Beacon"}]
        }
        with patch.object(soar_bindings, "http_client", fake_soar_http):
            yield
    elif server_name == "scc-mcp":
        mock_scc = MagicMock()
        mock_page = MagicMock()
        mock_page.list_findings_results = []
        mock_scc.list_findings.return_value.pages = [mock_page]
        with patch.object(scc_server_mod, "scc_client", mock_scc):
            yield
    else:  # pragma: no cover
        raise ValueError(f"Unknown server target: {server_name}")


def _decode_jsonrpc_http_body(content_type: str, text: str) -> dict[str, Any]:
    """Decode a JSON-RPC payload from either application/json or SSE text/event-stream."""
    if "text/event-stream" in content_type:
        for line in text.splitlines():
            if line.startswith("data: "):
                return json.loads(line[len("data: ") :])
        raise AssertionError(f"No SSE data frame found in body: {text!r}")
    return json.loads(text)


_ACTIVE_SPAN_SINK: list[RecordedSpan] | None = None
_OTEL_CONFIGURED = False


def _ensure_otel_span_capture() -> None:
    """Install a reusable span recorder once via opentelemetry-sdk or opentelemetry-api."""
    global _OTEL_CONFIGURED
    if _OTEL_CONFIGURED:
        return

    try:
        from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider

        class _SinkSpanProcessor(SpanProcessor):
            def on_end(self, span: ReadableSpan) -> None:
                if _ACTIVE_SPAN_SINK is None:
                    return
                parent_hex = (
                    f"{span.parent.span_id:016x}"
                    if span.parent is not None and span.parent.is_valid
                    else None
                )
                _ACTIVE_SPAN_SINK.append(
                    RecordedSpan(
                        name=span.name,
                        kind=span.kind,
                        trace_id_hex=f"{span.context.trace_id:032x}",
                        parent_span_id_hex=parent_hex,
                        attributes=dict(span.attributes or {}),
                    )
                )

        current = otel_trace.get_tracer_provider()
        if not isinstance(current, TracerProvider):
            provider = TracerProvider()
            otel_trace.set_tracer_provider(provider)
            current = provider
        current.add_span_processor(_SinkSpanProcessor())
        _OTEL_CONFIGURED = True
        return
    except ImportError:  # pragma: no cover
        pass

    # Lightweight opentelemetry-api fallback when opentelemetry-sdk is not installed.
    from contextlib import contextmanager as _cm
    from opentelemetry import context as otel_context
    from opentelemetry.trace.span import NonRecordingSpan, SpanContext, TraceFlags

    class _RecordingSpan(NonRecordingSpan):
        def __init__(
            self,
            name: str,
            kind: SpanKind,
            ctx: SpanContext,
            parent_span_id_hex: str | None,
            attributes: dict[str, Any],
        ) -> None:
            super().__init__(ctx)
            self._name = name
            self._kind = kind
            self._parent_hex = parent_span_id_hex
            self._attrs = dict(attributes)

        def is_recording(self) -> bool:
            return True

        def set_attribute(self, key: str, value: Any) -> None:
            self._attrs[key] = value

        def set_attributes(self, attributes: dict[str, Any]) -> None:
            self._attrs.update(attributes)

        def end(self, end_time: int | None = None) -> None:
            if _ACTIVE_SPAN_SINK is not None:
                _ACTIVE_SPAN_SINK.append(
                    RecordedSpan(
                        name=self._name,
                        kind=self._kind,
                        trace_id_hex=f"{self.get_span_context().trace_id:032x}",
                        parent_span_id_hex=self._parent_hex,
                        attributes=dict(self._attrs),
                    )
                )

    class _RecordingTracer(otel_trace.Tracer):
        def start_span(
            self,
            name: str,
            context: Any = None,
            kind: SpanKind = SpanKind.INTERNAL,
            attributes: Any = None,
            links: Any = None,
            start_time: int | None = None,
            record_exception: bool = True,
            set_status_on_exception: bool = True,
        ) -> otel_trace.Span:
            parent_span = otel_trace.get_current_span(context)
            parent_ctx = parent_span.get_span_context()
            if parent_ctx.is_valid:
                trace_id = parent_ctx.trace_id
                parent_hex = f"{parent_ctx.span_id:016x}"
            else:
                trace_id = 0x11111111111111111111111111111111
                parent_hex = None
            span_ctx = SpanContext(
                trace_id=trace_id,
                span_id=0x2222222222222222,
                is_remote=False,
                trace_flags=TraceFlags(0x01),
            )
            return _RecordingSpan(name, kind, span_ctx, parent_hex, dict(attributes or {}))

        @_cm
        def start_as_current_span(
            self,
            name: str,
            context: Any = None,
            kind: SpanKind = SpanKind.INTERNAL,
            attributes: Any = None,
            links: Any = None,
            start_time: int | None = None,
            record_exception: bool = True,
            set_status_on_exception: bool = True,
            end_on_exit: bool = True,
        ) -> Iterator[otel_trace.Span]:
            span = self.start_span(name, context=context, kind=kind, attributes=attributes)
            token = otel_context.attach(otel_trace.set_span_in_context(span, context))
            try:
                yield span
            finally:
                if end_on_exit:
                    span.end()
                otel_context.detach(token)

    class _RecordingProvider(otel_trace.TracerProvider):
        def get_tracer(self, *args: Any, **kwargs: Any) -> otel_trace.Tracer:
            return _RecordingTracer()

    otel_trace.set_tracer_provider(_RecordingProvider())
    _OTEL_CONFIGURED = True


@contextmanager
def _capture_otel_spans() -> Iterator[list[RecordedSpan]]:
    """Capture finished OpenTelemetry spans emitted within the context block."""
    global _ACTIVE_SPAN_SINK
    _ensure_otel_span_capture()
    captured: list[RecordedSpan] = []
    _ACTIVE_SPAN_SINK = captured
    try:
        yield captured
    finally:
        _ACTIVE_SPAN_SINK = None


# ---------------------------------------------------------------------------
# 1. Health & Readiness Probes Outside Host-Header Rejection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("target", SERVER_TARGETS, ids=[t.name for t in SERVER_TARGETS])
async def test_health_and_readiness_probes_bypass_host_rebinding_rejection(
    target: ServerTarget,
) -> None:
    """Verify /healthz and /readyz return 200 OK on Pod-IP Host while /mcp rejects evil Host."""
    app = target.build_http_app(target.server, host="127.0.0.1", stateless_http=True)
    async with _asgi_http_client(app) as client:
        for probe_path in ("/healthz", "/readyz"):
            resp = await client.get(
                probe_path,
                headers={"Host": "10.128.0.42:8080"},
            )
            assert resp.status_code == 200
            assert resp.json() == {
                "status": "ok",
                "server": target.name,
                "protocol_version": "2026-07-28",
            }

        evil_resp = await client.post(
            "/mcp",
            headers={
                "Host": "evil.example.com",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert evil_resp.status_code in (421, 400, 403)
        assert evil_resp.status_code == 421


@pytest.mark.asyncio
async def test_mcp_allowed_hosts_env_permits_configured_service_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify MCP_ALLOWED_HOSTS permits matching Host and same-origin Origin while blocking evil Origin."""
    monkeypatch.setenv(
        "MCP_ALLOWED_HOSTS",
        "secops-mcp.run.app,secops-mcp.secops.svc.cluster.local:*",
    )
    app = secops_server_mod.build_streamable_http_app(
        secops_server_mod.server,
        host="0.0.0.0",
        stateless_http=True,
    )
    tools_list_body = {
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    async with _asgi_http_client(app) as client:
        ok_resp = await client.post(
            "/mcp",
            headers={
                "Host": "secops-mcp.secops.svc.cluster.local:8080",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
            },
            json=tools_list_body,
        )
        assert ok_resp.status_code == 200
        assert len(ok_resp.json()["result"]["tools"]) > 0

        same_origin_resp = await client.post(
            "/mcp",
            headers={
                "Host": "secops-mcp.run.app",
                "Origin": "https://secops-mcp.run.app",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
            },
            json=tools_list_body,
        )
        assert same_origin_resp.status_code == 200
        assert len(same_origin_resp.json()["result"]["tools"]) > 0

        evil_origin_resp = await client.post(
            "/mcp",
            headers={
                "Host": "secops-mcp.run.app",
                "Origin": "https://evil.example",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
            },
            json=tools_list_body,
        )
        assert evil_origin_resp.status_code == 403

        blocked_resp = await client.post(
            "/mcp",
            headers={
                "Host": "untrusted.attacker.example",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            json={"jsonrpc": "2.0", "id": 12, "method": "tools/list", "params": {}},
        )
        assert blocked_resp.status_code == 421


@pytest.mark.asyncio
@pytest.mark.parametrize("target", SERVER_TARGETS, ids=[t.name for t in SERVER_TARGETS])
async def test_allowed_origins_derived_from_bind_host_loopback_and_env(
    target: ServerTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify same-origin requests on non-loopback --host, portless localhost, and MCP_ALLOWED_ORIGINS."""
    monkeypatch.setenv("MCP_ALLOWED_ORIGINS", "https://inspector.internal.example:8443")
    app = target.build_http_app(target.server, host="10.10.0.5", stateless_http=True)
    tools_list_body = {
        "jsonrpc": "2.0",
        "id": 15,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    base_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }
    async with _asgi_http_client(app) as client:
        bind_origin_resp = await client.post(
            "/mcp",
            headers={
                **base_headers,
                "Host": "10.10.0.5:8000",
                "Origin": "http://10.10.0.5:8000",
            },
            json=tools_list_body,
        )
        assert bind_origin_resp.status_code == 200

        portless_loopback_resp = await client.post(
            "/mcp",
            headers={
                **base_headers,
                "Host": "localhost",
                "Origin": "http://localhost",
            },
            json=tools_list_body,
        )
        assert portless_loopback_resp.status_code == 200

        explicit_origin_resp = await client.post(
            "/mcp",
            headers={
                **base_headers,
                "Host": "10.10.0.5:8000",
                "Origin": "https://inspector.internal.example:8443",
            },
            json=tools_list_body,
        )
        assert explicit_origin_resp.status_code == 200

        bad_origin_resp = await client.post(
            "/mcp",
            headers={
                **base_headers,
                "Host": "10.10.0.5:8000",
                "Origin": "https://evil.example",
            },
            json=tools_list_body,
        )
        assert bad_origin_resp.status_code == 403


# ---------------------------------------------------------------------------
# 2. Stateless 2026-07-28 Single-Exchange Streamable HTTP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("target", SERVER_TARGETS, ids=[t.name for t in SERVER_TARGETS])
async def test_stateless_2026_07_28_single_exchange_tools_list_and_call(
    target: ServerTarget,
) -> None:
    """Verify single-POST tools/list and tools/call succeed with zero initialize or session ID."""
    app = target.build_http_app(target.server, host="127.0.0.1", stateless_http=True)
    with _mock_backend_for_server(target.name):
        async with _asgi_http_client(app) as client:
            list_resp = await client.post(
                "/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "MCP-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "tools/list",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 101,
                    "method": "tools/list",
                    "params": {
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        }
                    },
                },
            )
            assert list_resp.status_code == 200
            assert "mcp-session-id" not in {k.lower() for k in list_resp.headers.keys()}
            list_payload = list_resp.json()
            assert list_payload["jsonrpc"] == "2.0"
            assert list_payload["id"] == 101
            assert len(list_payload["result"]["tools"]) > 0
            assert list_payload["result"]["ttlMs"] == 300_000
            assert list_payload["result"]["cacheScope"] == "public"

            call_resp = await client.post(
                "/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "MCP-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "tools/call",
                    "Mcp-Name": target.mock_tool_name,
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 102,
                    "method": "tools/call",
                    "params": {
                        "name": target.mock_tool_name,
                        "arguments": target.mock_tool_args,
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                    },
                },
            )
            assert call_resp.status_code == 200
            assert "mcp-session-id" not in {k.lower() for k in call_resp.headers.keys()}
            call_payload = call_resp.json()
            assert call_payload["id"] == 102
            assert call_payload["result"]["isError"] is False
            assert len(call_payload["result"]["content"]) >= 1


# ---------------------------------------------------------------------------
# 3. server/discover, -32022 UNSUPPORTED_PROTOCOL_VERSION, and 2025-11-25 Compat
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("target", SERVER_TARGETS, ids=[t.name for t in SERVER_TARGETS])
async def test_server_discover_and_unsupported_protocol_version_rejection(
    target: ServerTarget,
) -> None:
    """Verify server/discover metadata and -32022 error on unknown protocol version."""
    app = target.build_http_app(target.server, host="127.0.0.1", stateless_http=True)
    async with _asgi_http_client(app) as client:
        disc_resp = await client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "server/discover",
            },
            json={
                "jsonrpc": "2.0",
                "id": 201,
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            },
        )
        assert disc_resp.status_code == 200
        disc_result = disc_resp.json()["result"]
        assert "2026-07-28" in disc_result["supportedVersions"]
        assert "tools" in disc_result["capabilities"]
        assert isinstance(disc_result["instructions"], str) and disc_result["instructions"].strip()
        server_info = disc_result["_meta"]["io.modelcontextprotocol/serverInfo"]
        assert server_info["name"] == target.name
        assert server_info["title"] == target.title
        assert server_info["version"] == target.version

        unsupported_resp = await client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2099-01-01",
                "Mcp-Method": "tools/list",
            },
            json={
                "jsonrpc": "2.0",
                "id": 202,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2099-01-01",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            },
        )
        assert unsupported_resp.status_code == 400
        err = unsupported_resp.json()["error"]
        assert err["code"] == UNSUPPORTED_PROTOCOL_VERSION
        assert err["code"] == -32022
        assert err["data"]["requested"] == "2099-01-01"
        assert "2026-07-28" in err["data"]["supported"]


@pytest.mark.asyncio
@pytest.mark.parametrize("target", SERVER_TARGETS, ids=[t.name for t in SERVER_TARGETS])
async def test_backward_compatible_2025_11_25_stateful_initialize_and_tools_list(
    target: ServerTarget,
) -> None:
    """Verify 2025-11-25 stateful initialize + Mcp-Session-Id + tools/list continues to work."""
    app = target.build_http_app(target.server, host="127.0.0.1", stateless_http=False)
    async with _asgi_http_client(app) as client:
        init_resp = await client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "legacy-2025-client", "version": "1.0.0"},
                },
            },
        )
        assert init_resp.status_code == 200
        session_id = init_resp.headers.get("mcp-session-id")
        assert isinstance(session_id, str) and len(session_id) > 0
        init_msg = _decode_jsonrpc_http_body(
            init_resp.headers.get("content-type", ""), init_resp.text
        )
        assert init_msg["result"]["protocolVersion"] == "2025-11-25"
        assert init_msg["result"]["serverInfo"]["name"] == target.name

        notif_resp = await client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "Mcp-Session-Id": session_id,
                "MCP-Protocol-Version": "2025-11-25",
            },
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert notif_resp.status_code == 202

        tools_resp = await client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "Mcp-Session-Id": session_id,
                "MCP-Protocol-Version": "2025-11-25",
            },
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert tools_resp.status_code == 200
        tools_msg = _decode_jsonrpc_http_body(
            tools_resp.headers.get("content-type", ""), tools_resp.text
        )
        assert len(tools_msg["result"]["tools"]) > 0


# ---------------------------------------------------------------------------
# 4. Request Body Size Cap (4 MiB / CVE-2026-109527 Protection)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("target", SERVER_TARGETS, ids=[t.name for t in SERVER_TARGETS])
async def test_request_body_over_4_mib_rejected_with_413(
    target: ServerTarget,
) -> None:
    """Verify HTTP POST bodies exceeding 4,194,304 bytes receive 413 Payload Too Large."""
    app = target.build_http_app(target.server, host="127.0.0.1", stateless_http=True)
    oversized_body = (
        b'{"jsonrpc":"2.0","id":999,"method":"ping","padding":"'
        + (b"A" * 4_194_305)
        + b'"}'
    )
    assert len(oversized_body) > 4_194_304

    async with _asgi_http_client(app) as client:
        resp = await client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            content=oversized_body,
        )
        assert resp.status_code == 413


# ---------------------------------------------------------------------------
# 5. SEP-2549 CacheHint Wire Verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("target", SERVER_TARGETS, ids=[t.name for t in SERVER_TARGETS])
async def test_sep2549_cache_hints_on_tools_prompts_and_resources(
    target: ServerTarget,
) -> None:
    """Verify ListToolsResult, ListPromptsResult, and ListResourcesResult carry SEP-2549 hints."""
    async with Client(target.server) as client:
        tools_res = await client.list_tools()
        prompts_res = await client.list_prompts()
        resources_res = await client.list_resources()

    assert tools_res.ttl_ms == 300_000
    assert tools_res.cache_scope == "public"
    tools_wire = tools_res.model_dump(by_alias=True, exclude_none=True)
    assert tools_wire["ttlMs"] == 300_000
    assert tools_wire["cacheScope"] == "public"

    assert prompts_res.ttl_ms == 300_000
    assert prompts_res.cache_scope == "public"
    prompts_wire = prompts_res.model_dump(by_alias=True, exclude_none=True)
    assert prompts_wire["ttlMs"] == 300_000
    assert prompts_wire["cacheScope"] == "public"

    assert resources_res.ttl_ms == 60_000
    assert resources_res.cache_scope == "private"
    resources_wire = resources_res.model_dump(by_alias=True, exclude_none=True)
    assert resources_wire["ttlMs"] == 60_000
    assert resources_wire["cacheScope"] == "private"


def test_mcp_tools_cache_ttl_ms_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify MCP_TOOLS_CACHE_TTL_MS overrides tools/list TTL across all 4 server builders."""
    monkeypatch.setenv("MCP_TOOLS_CACHE_TTL_MS", "45000")
    for target in SERVER_TARGETS:
        hints = target.module._build_cache_hints()
        assert hints["tools/list"].ttl_ms == 45_000
        assert hints["tools/list"].scope == "public"
        assert hints["prompts/list"].ttl_ms == 300_000
        assert hints["resources/list"].ttl_ms == 60_000


# ---------------------------------------------------------------------------
# 6. OpenTelemetry GenAI Span & W3C _meta.traceparent Propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_otel_middleware_noop_without_active_exporter() -> None:
    """Verify OpenTelemetryMiddleware is installed once per server and runs cleanly with no sink."""
    for target in SERVER_TARGETS:
        otel_middlewares = [
            mw
            for mw in target.server._lowlevel_server.middleware
            if isinstance(mw, OpenTelemetryMiddleware)
        ]
        assert len(otel_middlewares) == 1

    with _mock_backend_for_server("secops-mcp"):
        async with Client(secops_server_mod.server) as client:
            res = await client.call_tool(
                "search_udm",
                {'query': 'metadata.event_type = "USER_LOGIN"'},
            )
            assert res.is_error is False


@pytest.mark.asyncio
@pytest.mark.parametrize("target", SERVER_TARGETS, ids=[t.name for t in SERVER_TARGETS])
async def test_otel_genai_span_and_w3c_traceparent_propagation(
    target: ServerTarget,
) -> None:
    """Verify W3C _meta.traceparent links SERVER spans and populates gen_ai.* attributes."""
    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    app = target.build_http_app(target.server, host="127.0.0.1", stateless_http=True)

    with _mock_backend_for_server(target.name), _capture_otel_spans() as spans:
        async with _asgi_http_client(app) as client:
            resp = await client.post(
                "/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "MCP-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "tools/call",
                    "Mcp-Name": target.mock_tool_name,
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 777,
                    "method": "tools/call",
                    "params": {
                        "name": target.mock_tool_name,
                        "arguments": target.mock_tool_args,
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                            "traceparent": traceparent,
                        },
                    },
                },
            )
            assert resp.status_code == 200
            assert resp.json()["result"]["isError"] is False

    tool_spans = [
        s for s in spans if s.attributes.get("mcp.method.name") == "tools/call"
    ]
    assert len(tool_spans) == 1
    span = tool_spans[0]
    assert span.kind == SpanKind.SERVER
    assert span.trace_id_hex == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert span.parent_span_id_hex == "00f067aa0ba902b7"
    assert span.attributes["mcp.method.name"] == "tools/call"
    assert span.attributes["mcp.protocol.version"] == "2026-07-28"
    assert span.attributes["gen_ai.operation.name"] == "execute_tool"
    assert span.attributes["gen_ai.tool.name"] == target.mock_tool_name


# ---------------------------------------------------------------------------
# 7. Standardized Multi-Transport CLI & Env Flag Parsing Across All 4 Servers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", SERVER_TARGETS, ids=[t.name for t in SERVER_TARGETS])
def test_cli_arg_parser_defaults_env_vars_and_http_alias(
    target: ServerTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify --transport, --host, --port, --stateless-http, and http alias across all 4 servers."""
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("GTI_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("MCP_HOST", raising=False)
    monkeypatch.delenv("MCP_PORT", raising=False)
    monkeypatch.delenv("MCP_STATELESS_HTTP", raising=False)
    monkeypatch.delenv("STATELESS", raising=False)

    defaults = target.module.build_arg_parser().parse_args([])
    assert defaults.transport == "stdio"
    assert defaults.host == "127.0.0.1"
    assert defaults.port == 8000
    assert defaults.stateless_http is True

    alias_args = target.module.build_arg_parser().parse_args(
        ["--transport", "http", "--host", "0.0.0.0", "--port", "9090", "--no-stateless-http"]
    )
    assert alias_args.transport == "streamable-http"
    assert target.module._normalize_transport(alias_args.transport) == "streamable-http"
    assert alias_args.host == "0.0.0.0"
    assert alias_args.port == 9090
    assert alias_args.stateless_http is False

    monkeypatch.setenv("MCP_TRANSPORT", "http")
    monkeypatch.setenv("MCP_HOST", "10.10.0.5")
    monkeypatch.setenv("MCP_PORT", "8088")
    monkeypatch.setenv("MCP_STATELESS_HTTP", "false")
    env_args = target.module.build_arg_parser().parse_args([])
    assert env_args.transport == "streamable-http"
    assert env_args.host == "10.10.0.5"
    assert env_args.port == 8088
    assert env_args.stateless_http is False


@pytest.mark.parametrize("target", SERVER_TARGETS, ids=[t.name for t in SERVER_TARGETS])
def test_cli_empty_and_invalid_env_vars_validated_cleanly(
    target: ServerTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify empty MCP_* env vars fall back to defaults and invalid MCP_PORT/MCP_TRANSPORT exit 2."""
    monkeypatch.delenv("GTI_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("GTI_MCP_HOST", raising=False)
    monkeypatch.delenv("GTI_MCP_PORT", raising=False)

    monkeypatch.setenv("MCP_TRANSPORT", "   ")
    monkeypatch.setenv("MCP_HOST", "")
    monkeypatch.setenv("MCP_PORT", "")
    empty_env_args = target.module.build_arg_parser().parse_args([])
    assert empty_env_args.transport == "stdio"
    assert empty_env_args.host == "127.0.0.1"
    assert empty_env_args.port == 8000

    monkeypatch.setenv("MCP_PORT", "bad")
    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    parser_bad_port = target.module.build_arg_parser()
    with pytest.raises(SystemExit) as bad_port_exc:
        parser_bad_port.parse_args([])
    assert bad_port_exc.value.code == 2

    override_port_args = target.module.build_arg_parser().parse_args(["--port", "9091"])
    assert override_port_args.port == 9091

    monkeypatch.setenv("MCP_PORT", "8000")
    monkeypatch.setenv("MCP_TRANSPORT", "sse")
    parser_bad_transport = target.module.build_arg_parser()
    with pytest.raises(SystemExit) as bad_transport_exc:
        parser_bad_transport.parse_args([])
    assert bad_transport_exc.value.code == 2


def test_soar_server_import_safe_with_invalid_mcp_port_and_transport_env() -> None:
    """Verify importing secops_soar_mcp.server never crashes when MCP_PORT or MCP_TRANSPORT is invalid."""
    env = os.environ.copy()
    env["MCP_PORT"] = "bad"
    env["MCP_TRANSPORT"] = "sse"
    soar_pkg_dir = str(REPO_ROOT / "server" / "secops-soar")
    existing_py_path = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{soar_pkg_dir}{os.pathsep}{existing_py_path}" if existing_py_path else soar_pkg_dir
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import secops_soar_mcp.server as m; assert m.mcp.name == 'secops-soar-mcp'",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_soar_cli_preserves_integrations_and_verbose_flags() -> None:
    """Verify secops-soar-mcp preserves --integrations and --verbose CLI flags."""
    args = soar_server_mod.build_arg_parser().parse_args(
        [
            "--integrations",
            "CSV,SiemplifyThreatFuse",
            "--verbose",
            "--transport",
            "streamable-http",
        ]
    )
    assert args.integrations == "CSV,SiemplifyThreatFuse"
    assert args.verbose is True
    assert args.transport == "streamable-http"
