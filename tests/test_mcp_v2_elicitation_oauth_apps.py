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
"""Phase 5 suite: Stateless MRTR elicitation, progress streaming, OAuth 2.1 RS, and MCP Apps."""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
import datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sys
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
from httpx2 import ASGITransport, AsyncClient, MockTransport, Response
from mcp import types
from mcp.client import Client, ClientExtension
from mcp.server.apps import APP_MIME_TYPE, EXTENSION_ID, client_supports_apps
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.request_state import (
    AESGCMRequestStateCodec,
    InvalidRequestState,
    RequestStateBoundary,
)
from mcp_types.jsonrpc import INVALID_PARAMS
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

from gti_mcp import phase5 as gti_phase5  # noqa: E402
from gti_mcp import server as gti_server_mod  # noqa: E402
import scc_mcp as scc_server_mod  # noqa: E402
from secops_mcp import phase5 as secops_phase5  # noqa: E402
from secops_mcp import server as secops_server_mod  # noqa: E402
from secops_soar_mcp import bindings as soar_bindings  # noqa: E402
from secops_soar_mcp import phase5 as soar_phase5  # noqa: E402
from secops_soar_mcp import server as soar_server_mod  # noqa: E402


@dataclass(frozen=True)
class ServerEntry:
    """Descriptor for each of the 4 MCP servers under Phase 5 contract testing."""

    name: str
    module: Any
    server: MCPServer
    build_http_app: Callable[..., Starlette]
    build_arg_parser: Callable[[], Any]
    resource_url: str
    sample_tool: str
    sample_args: dict[str, Any]


SERVER_ENTRIES: list[ServerEntry] = [
    ServerEntry(
        name="secops-mcp",
        module=secops_server_mod,
        server=secops_server_mod.server,
        build_http_app=secops_server_mod.build_streamable_http_app,
        build_arg_parser=secops_server_mod.build_arg_parser,
        resource_url="https://secops-mcp.example.com/mcp",
        sample_tool="search_udm",
        sample_args={"query": 'metadata.event_type = "USER_LOGIN"'},
    ),
    ServerEntry(
        name="gti-mcp",
        module=gti_server_mod,
        server=gti_server_mod.server,
        build_http_app=gti_server_mod.build_streamable_http_app,
        build_arg_parser=gti_server_mod.build_arg_parser,
        resource_url="https://gti-mcp.example.com/mcp",
        sample_tool="get_threat_profile",
        sample_args={"profile_id": "prof-apt29"},
    ),
    ServerEntry(
        name="secops-soar-mcp",
        module=soar_server_mod,
        server=soar_server_mod.mcp,
        build_http_app=soar_server_mod.build_streamable_http_app,
        build_arg_parser=soar_server_mod.build_arg_parser,
        resource_url="https://soar-mcp.example.com/mcp",
        sample_tool="list_cases",
        sample_args={"next_page_token": None},
    ),
    ServerEntry(
        name="scc-mcp",
        module=scc_server_mod,
        server=scc_server_mod.mcp,
        build_http_app=scc_server_mod.build_streamable_http_app,
        build_arg_parser=scc_server_mod.build_arg_parser,
        resource_url="https://scc-mcp.example.com/mcp",
        sample_tool="top_vulnerability_findings",
        sample_args={"project_id": "demo-project", "max_findings": 1},
    ),
]


class _McpAppsUiClientExtension(ClientExtension):
    """Test ClientExtension advertising io.modelcontextprotocol/ui support."""

    identifier = EXTENSION_ID

    def settings(self) -> dict[str, Any]:
        return {"mimeTypes": [APP_MIME_TYPE]}


@asynccontextmanager
async def _asgi_http_client(
    app: Starlette,
    *,
    base_url: str = "http://127.0.0.1:8000",
) -> AsyncIterator[AsyncClient]:
    """Enter Starlette lifespan and yield an offline ASGI HTTP client."""
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url=base_url) as client:
            yield client


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _mint_hs256_jwt(claims: dict[str, Any], secret: str) -> str:
    header_seg = _b64url_encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8")
    )
    payload_seg = _b64url_encode(
        json.dumps(claims, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_seg}.{payload_seg}.{_b64url_encode(sig)}"


def _mint_rs256_jwt(
    claims: dict[str, Any],
    private_key: rsa.RSAPrivateKey,
    *,
    kid: str | None = None,
) -> str:
    header: dict[str, Any] = {"alg": "RS256", "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    header_seg = _b64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_seg = _b64url_encode(
        json.dumps(claims, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_seg}.{payload_seg}.{_b64url_encode(sig)}"


def _mint_es256_jwt(
    claims: dict[str, Any],
    private_key: ec.EllipticCurvePrivateKey,
    *,
    kid: str | None = None,
) -> str:
    header: dict[str, Any] = {"alg": "ES256", "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    header_seg = _b64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_seg = _b64url_encode(
        json.dumps(claims, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    der_sig = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r_int, s_int = decode_dss_signature(der_sig)
    raw_sig = r_int.to_bytes(32, "big") + s_int.to_bytes(32, "big")
    return f"{header_seg}.{payload_seg}.{_b64url_encode(raw_sig)}"


def _rsa_public_jwk(public_key: rsa.RSAPublicKey, kid: str) -> dict[str, Any]:
    nums = public_key.public_numbers()
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_encode(n_bytes),
        "e": _b64url_encode(e_bytes),
    }


def _ec_p256_public_jwk(
    public_key: ec.EllipticCurvePublicKey,
    kid: str,
) -> dict[str, Any]:
    nums = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": _b64url_encode(nums.x.to_bytes(32, "big")),
        "y": _b64url_encode(nums.y.to_bytes(32, "big")),
    }


def _decode_http_jsonrpc(resp: Any) -> dict[str, Any]:
    content_type = resp.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        for line in resp.text.splitlines():
            if line.startswith("data: "):
                return json.loads(line[len("data: ") :])
        raise AssertionError(f"Missing SSE data frame: {resp.text!r}")
    return resp.json()


# ---------------------------------------------------------------------------
# 1. RequestStateSecurity & AESGCMRequestStateCodec Unit + Tamper Tests
# ---------------------------------------------------------------------------


def test_request_state_codec_roundtrip_key_formats_and_tamper_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify AES-GCM sealing across hex/base64/passphrase secrets and fail-closed tamper checks."""
    hex_secret = secrets.token_hex(32)
    b64_secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    passphrase_secret = "chronicle-soar-shared-cluster-passphrase-2026"

    for raw_secret in (hex_secret, b64_secret, passphrase_secret):
        monkeypatch.setenv("MCP_REQUEST_STATE_SECRET", raw_secret)
        for mod in (secops_phase5, gti_phase5, soar_phase5, scc_server_mod):
            derived = mod.derive_request_state_key()
            assert isinstance(derived, bytes)
            assert len(derived) == 32
            codec = mod.EnvAwareAESGCMCodec()
            sealed = codec.seal(b'{"v":1,"action":"delete_rule"}')
            first_cached = codec._cached_codec
            assert first_cached is not None
            assert sealed.startswith("v1.")
            assert codec.unseal(sealed) == b'{"v":1,"action":"delete_rule"}'
            assert codec._cached_codec is first_cached

            # Flip last character in authentication tag -> InvalidRequestState
            flipped_char = "A" if sealed[-1] != "A" else "B"
            tampered = sealed[:-1] + flipped_char
            with pytest.raises(InvalidRequestState):
                codec.unseal(tampered)

    # Wrong key ring must also fail closed with InvalidRequestState
    codec_a = AESGCMRequestStateCodec([secrets.token_bytes(32)])
    codec_b = AESGCMRequestStateCodec([secrets.token_bytes(32)])
    token_a = codec_a.seal(b"state-payload")
    with pytest.raises(InvalidRequestState):
        codec_b.unseal(token_a)


@pytest.mark.parametrize("entry", SERVER_ENTRIES, ids=[e.name for e in SERVER_ENTRIES])
def test_all_four_servers_configure_request_state_security_boundary(
    entry: ServerEntry,
) -> None:
    """Verify all 4 MCPServer instances wire RequestStateSecurity with principal binding."""
    boundaries = [
        mw
        for mw in entry.server._lowlevel_server.middleware
        if isinstance(mw, RequestStateBoundary)
    ]
    assert len(boundaries) == 1
    security = boundaries[0]._security
    assert security is not None
    assert security.bind_principal is not None
    sample_sealed = security.codec.seal(b'{"probe":true}')
    assert security.codec.unseal(sample_sealed) == b'{"probe":true}'


# ---------------------------------------------------------------------------
# 2. Multi-Round-Trip Elicitation Across GTI, SOAR, SecOps, and SCC
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gti_analyse_file_elicitation_accept_and_decline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify analyse_file displays basename/size/SHA-256 and gates external VT upload."""
    monkeypatch.setenv("MCP_ELICIT_DESTRUCTIVE", "true")
    sample_bytes = b"MZ-benign-pe-sample-payload-for-gti-elicitation-test"
    expected_sha256 = hashlib.sha256(sample_bytes).hexdigest()
    sample_file = tmp_path / "suspicious_dropper.bin"
    sample_file.write_bytes(sample_bytes)

    fake_vt_client = AsyncMock()
    fake_vt_client.scan_file_async = AsyncMock(return_value=MagicMock(id="an-101"))
    fake_completed = MagicMock()
    fake_completed.id = "an-101"
    fake_completed.to_dict.return_value = {
        "id": "an-101",
        "type": "analysis",
        "attributes": {"status": "completed", "stats": {"malicious": 12, "harmless": 58}},
    }
    fake_vt_client.wait_for_analysis_completion = AsyncMock(return_value=fake_completed)
    fake_vt_client.close_async = AsyncMock()

    seen_prompts: list[str] = []

    async def _accept_cb(
        context: Any,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        seen_prompts.append(params.message)
        return types.ElicitResult(
            action="accept",
            content={"confirm": True, "reason": "Approved sandbox submission"},
        )

    async def _decline_cb(
        context: Any,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        seen_prompts.append(params.message)
        return types.ElicitResult(action="decline")

    async def _confirm_false_cb(
        context: Any,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        return types.ElicitResult(
            action="accept",
            content={"confirm": False, "reason": "Contains sensitive memory dump"},
        )

    with patch("gti_mcp.tools.files.vt_client") as mock_vt_cm:
        mock_vt_cm.return_value.__aenter__.return_value = fake_vt_client
        mock_vt_cm.return_value.__aexit__.return_value = False

        # Case 1: Operator declines -> external upload MUST NOT happen
        async with Client(
            gti_server_mod.server,
            elicitation_callback=_decline_cb,
        ) as decline_client:
            declined_res = await decline_client.call_tool(
                "analyse_file",
                {"file_path": str(sample_file)},
            )
            assert declined_res.is_error is False
            assert declined_res.structured_content is not None
            assert declined_res.structured_content["cancelled"] is True
            assert declined_res.structured_content["uploaded"] is False
            assert declined_res.structured_content["sha256"] == expected_sha256
            assert declined_res.structured_content["size_bytes"] == len(sample_bytes)
            fake_vt_client.scan_file_async.assert_not_called()

        assert len(seen_prompts) == 1
        assert "suspicious_dropper.bin" in seen_prompts[0]
        assert str(len(sample_bytes)) in seen_prompts[0]
        assert expected_sha256 in seen_prompts[0]

        # Case 2: Operator accepts form with confirm=False -> external upload MUST NOT happen
        async with Client(
            gti_server_mod.server,
            elicitation_callback=_confirm_false_cb,
        ) as false_client:
            false_res = await false_client.call_tool(
                "analyse_file",
                {"file_path": str(sample_file)},
            )
            assert false_res.is_error is False
            assert false_res.structured_content is not None
            assert false_res.structured_content["cancelled"] is True
            assert false_res.structured_content["uploaded"] is False
            fake_vt_client.scan_file_async.assert_not_called()

        # Case 3: Operator confirms -> external upload executes cleanly
        async with Client(
            gti_server_mod.server,
            elicitation_callback=_accept_cb,
        ) as accept_client:
            accepted_res = await accept_client.call_tool(
                "analyse_file",
                {"file_path": str(sample_file)},
            )
            assert accepted_res.is_error is False
            assert accepted_res.structured_content is not None
            assert accepted_res.structured_content["id"] == "an-101"
            fake_vt_client.scan_file_async.assert_awaited_once()
            fake_vt_client.wait_for_analysis_completion.assert_awaited_once()


@pytest.mark.asyncio
async def test_soar_close_case_elicitation_accept_override_and_decline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify close_case gates closure and honors elicited close_reason/root_cause overrides."""
    monkeypatch.setenv("MCP_ELICIT_DESTRUCTIVE", "true")
    fake_soar_http = AsyncMock()
    fake_soar_http.post = AsyncMock(return_value={"caseId": "4412", "status": "Closed"})

    async def _decline_cb(
        context: Any,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        assert "4412" in params.message
        return types.ElicitResult(action="cancel")

    async def _override_accept_cb(
        context: Any,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        return types.ElicitResult(
            action="accept",
            content={
                "confirm": True,
                "close_reason": "Maintenance",
                "root_cause": "Authorized red-team simulation",
            },
        )

    with patch.object(soar_bindings, "http_client", fake_soar_http):
        async with Client(
            soar_server_mod.mcp,
            elicitation_callback=_decline_cb,
        ) as decline_client:
            cancelled = await decline_client.call_tool(
                "close_case",
                {
                    "case_id": "4412",
                    "root_cause": "Initial triage hypothesis",
                    "comment": "Closing case",
                    "reason": "NotMalicious",
                },
            )
            assert cancelled.is_error is False
            assert cancelled.structured_content is not None
            assert cancelled.structured_content["cancelled"] is True
            assert cancelled.structured_content["closed"] is False
            fake_soar_http.post.assert_not_called()

        async with Client(
            soar_server_mod.mcp,
            elicitation_callback=_override_accept_cb,
        ) as accept_client:
            closed = await accept_client.call_tool(
                "close_case",
                {
                    "case_id": "4412",
                    "root_cause": "Initial triage hypothesis",
                    "comment": "Closing after purple-team verification",
                    "reason": "NotMalicious",
                },
            )
            assert closed.is_error is False
            fake_soar_http.post.assert_awaited_once()
            posted_req = fake_soar_http.post.await_args.kwargs["req"]
            assert posted_req["CaseId"] == "4412"
            assert posted_req["Reason"] == "Maintenance"
            assert posted_req["RootCause"] == "Authorized red-team simulation"


@pytest.mark.asyncio
async def test_secops_delete_rule_elicits_while_delete_watchlist_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify delete_rule gates Chronicle SIEM rule deletion while delete_watchlist has no elicitation gate."""
    monkeypatch.setenv("MCP_ELICIT_DESTRUCTIVE", "true")
    mock_chronicle = MagicMock()
    mock_chronicle.delete_rule.return_value = {}
    mock_chronicle.delete_watchlist.return_value = {"deleted": True}

    elicit_messages: list[str] = []

    async def _decline_cb(
        context: Any,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        elicit_messages.append(params.message)
        return types.ElicitResult(action="decline")

    async def _accept_cb(
        context: Any,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        elicit_messages.append(params.message)
        return types.ElicitResult(
            action="accept",
            content={"confirm": True, "reason": "Confirmed obsolete rule cleanup"},
        )

    with (
        patch(
            "secops_mcp.tools.security_rules.get_chronicle_client",
            return_value=mock_chronicle,
        ),
        patch(
            "secops_mcp.tools.watchlist_management.get_chronicle_client",
            return_value=mock_chronicle,
        ),
    ):
        async with Client(
            secops_server_mod.server,
            elicitation_callback=_decline_cb,
        ) as decline_client:
            rule_declined = await decline_client.call_tool(
                "delete_rule",
                {"rule_id": "ru_a1b2c3d4-e5f6-4321-abcd-ef1234567890", "force": True},
            )
            assert rule_declined.is_error is False
            assert rule_declined.structured_content is not None
            assert rule_declined.structured_content["cancelled"] is True
            assert rule_declined.structured_content["deleted"] is False
            mock_chronicle.delete_rule.assert_not_called()
            assert len(elicit_messages) == 1

            # delete_watchlist is NOT one of the 4 gated tools and executes directly
            wl_res = await decline_client.call_tool(
                "delete_watchlist",
                {"watchlist_id": "wl-high-risk-contractors", "force": False},
            )
            assert wl_res.is_error is False
            assert len(elicit_messages) == 1
            mock_chronicle.delete_watchlist.assert_called_once_with(
                "wl-high-risk-contractors",
                force=False,
            )

        async with Client(
            secops_server_mod.server,
            elicitation_callback=_accept_cb,
        ) as accept_client:
            rule_deleted = await accept_client.call_tool(
                "delete_rule",
                {"rule_id": "ru_a1b2c3d4-e5f6-4321-abcd-ef1234567890", "force": True},
            )
            assert rule_deleted.is_error is False
            assert rule_deleted.structured_content is not None
            assert rule_deleted.structured_content["deleted"] is True
            mock_chronicle.delete_rule.assert_called_once_with(
                "ru_a1b2c3d4-e5f6-4321-abcd-ef1234567890",
                force=True,
            )


@pytest.mark.asyncio
async def test_scc_set_finding_mute_elicits_only_on_muted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify set_finding_mute elicits confirmation when mute==MUTED, not UNMUTED."""
    monkeypatch.setenv("MCP_ELICIT_DESTRUCTIVE", "true")

    mock_scc = MagicMock()
    mock_finding = MagicMock()
    mock_finding.name = "organizations/123456789/sources/999/locations/global/findings/f-881"
    mock_result_item = MagicMock()
    mock_result_item.finding = mock_finding
    mock_page = MagicMock()
    mock_page.list_findings_results = [mock_result_item]
    mock_scc.list_findings.return_value.pages = [mock_page]
    mock_scc.set_mute.return_value = MagicMock(_pb=MagicMock())

    elicit_calls: list[str] = []

    async def _decline_cb(
        context: Any,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        elicit_calls.append(params.message)
        return types.ElicitResult(action="decline")

    async def _accept_cb(
        context: Any,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult:
        elicit_calls.append(params.message)
        return types.ElicitResult(
            action="accept",
            content={"confirm": True, "reason": "Accepted compensating control"},
        )

    with (
        patch.object(scc_server_mod, "scc_client", mock_scc),
        patch.object(
            scc_server_mod,
            "proto_message_to_dict",
            return_value={"name": mock_finding.name, "mute": "MUTED"},
        ),
    ):
        # 1. mute="MUTED" declined -> set_mute NOT called
        async with Client(
            scc_server_mod.mcp,
            elicitation_callback=_decline_cb,
        ) as decline_client:
            declined = await decline_client.call_tool(
                "set_finding_mute",
                {
                    "organization_id": "123456789",
                    "finding_id": "f-881",
                    "mute": "MUTED",
                },
            )
            assert declined.is_error is False
            assert declined.structured_content is not None
            assert declined.structured_content["cancelled"] is True
            assert declined.structured_content["muted"] is False
            mock_scc.set_mute.assert_not_called()
            assert len(elicit_calls) == 1
            assert "organizations/123456789/sources/-/locations/global/findings/f-881" in elicit_calls[0]

        # 2. mute="UNMUTED" -> executes without triggering elicitation even on client without callback
        async with Client(scc_server_mod.mcp) as unmute_client:
            unmuted = await unmute_client.call_tool(
                "set_finding_mute",
                {
                    "organization_id": "123456789",
                    "finding_id": "f-881",
                    "mute": "UNMUTED",
                },
            )
            assert unmuted.is_error is False
            assert unmuted.structured_content is not None
            assert unmuted.structured_content["mute_state"] == "UNMUTED"
            assert mock_scc.set_mute.call_count == 1
            assert len(elicit_calls) == 1

        # 3. mute="MUTED" accepted -> set_mute executes
        async with Client(
            scc_server_mod.mcp,
            elicitation_callback=_accept_cb,
        ) as accept_client:
            muted = await accept_client.call_tool(
                "set_finding_mute",
                {
                    "organization_id": "123456789",
                    "finding_id": "f-881",
                    "mute": "MUTED",
                },
            )
            assert muted.is_error is False
            assert muted.structured_content is not None
            assert muted.structured_content["mute_state"] == "MUTED"
            assert mock_scc.set_mute.call_count == 2
            assert len(elicit_calls) == 2


@pytest.mark.asyncio
async def test_unattended_client_without_elicitation_rejected_on_http_and_configurable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify HTTP unattended clients fail closed by default unless MCP_UNATTENDED_DESTRUCTIVE_POLICY=allow."""
    monkeypatch.setenv("MCP_ELICIT_DESTRUCTIVE", "true")
    monkeypatch.delenv("MCP_UNATTENDED_DESTRUCTIVE_POLICY", raising=False)

    mock_chronicle = MagicMock()
    mock_chronicle.delete_rule.return_value = {}

    app = secops_server_mod.build_streamable_http_app(
        secops_server_mod.server,
        host="127.0.0.1",
        stateless_http=True,
    )
    unattended_call = {
        "jsonrpc": "2.0",
        "id": 77,
        "method": "tools/call",
        "params": {
            "name": "delete_rule",
            "arguments": {"rule_id": "ru_unattended_check"},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    headers = {
        "Host": "127.0.0.1:8000",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "delete_rule",
    }

    with patch(
        "secops_mcp.tools.security_rules.get_chronicle_client",
        return_value=mock_chronicle,
    ):
        async with _asgi_http_client(app) as http_client:
            # Default on HTTP is deny -> tool call fails closed without mutating backend
            denied_resp = await http_client.post("/mcp", headers=headers, json=unattended_call)
            assert denied_resp.status_code == 200
            denied_payload = _decode_http_jsonrpc(denied_resp)
            assert denied_payload["result"]["isError"] is True
            assert "elicitation" in denied_payload["result"]["content"][0]["text"]
            mock_chronicle.delete_rule.assert_not_called()

            # Explicit override MCP_UNATTENDED_DESTRUCTIVE_POLICY=allow -> permits unattended automation
            monkeypatch.setenv("MCP_UNATTENDED_DESTRUCTIVE_POLICY", "allow")
            allowed_resp = await http_client.post("/mcp", headers=headers, json=unattended_call)
            assert allowed_resp.status_code == 200
            allowed_payload = _decode_http_jsonrpc(allowed_resp)
            assert allowed_payload["result"].get("isError", False) is False
            mock_chronicle.delete_rule.assert_called_once_with(
                "ru_unattended_check",
                force=False,
            )


@pytest.mark.asyncio
async def test_stateless_http_mrtr_roundtrip_tamper_principal_and_stripped_state_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify stateless HTTP MRTR seals requestState, binds OAuth principal, and blocks forgery."""
    issuer = "https://auth.example.com"
    resource_url = "https://secops-mcp.example.com/mcp"
    jwt_secret = "phase5-mrtr-principal-binding-hs256-secret-key"
    monkeypatch.setenv("MCP_ELICIT_DESTRUCTIVE", "true")
    monkeypatch.setenv("MCP_REQUEST_STATE_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("MCP_OAUTH_HS256_SECRET", jwt_secret)

    now = int(time.time())
    alice_token = _mint_hs256_jwt(
        {
            "iss": issuer,
            "sub": "alice@secops.example.com",
            "client_id": "soc-workstation",
            "aud": resource_url,
            "scope": "secops:admin",
            "exp": now + 600,
        },
        jwt_secret,
    )
    mallory_token = _mint_hs256_jwt(
        {
            "iss": issuer,
            "sub": "mallory@secops.example.com",
            "client_id": "soc-workstation",
            "aud": resource_url,
            "scope": "secops:admin",
            "exp": now + 600,
        },
        jwt_secret,
    )

    mock_chronicle = MagicMock()
    mock_chronicle.delete_rule.return_value = {}

    app = secops_server_mod.build_streamable_http_app(
        secops_server_mod.server,
        host="0.0.0.0",
        stateless_http=True,
        oauth_issuer_url=issuer,
        resource_server_url=resource_url,
        required_scopes=["secops:admin"],
    )

    def _headers(bearer: str) -> dict[str, str]:
        return {
            "Host": "secops-mcp.example.com",
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/call",
            "Mcp-Name": "delete_rule",
        }

    meta_caps = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
    }

    with patch(
        "secops_mcp.tools.security_rules.get_chronicle_client",
        return_value=mock_chronicle,
    ):
        async with _asgi_http_client(
            app, base_url="https://secops-mcp.example.com"
        ) as http_client:
            # Round 1 (Alice): returns input_required + encrypted requestState
            r1 = await http_client.post(
                "/mcp",
                headers=_headers(alice_token),
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "delete_rule",
                        "arguments": {"rule_id": "ru_mrtr_001", "force": False},
                        "_meta": meta_caps,
                    },
                },
            )
            assert r1.status_code == 200
            r1_body = _decode_http_jsonrpc(r1)
            assert r1_body["result"]["resultType"] == "input_required"
            assert "confirm_destructive" in r1_body["result"]["inputRequests"]
            sealed_state = r1_body["result"]["requestState"]
            assert isinstance(sealed_state, str) and sealed_state.startswith("v1.")
            mock_chronicle.delete_rule.assert_not_called()

            # Attack 1: Tampered ciphertext/tag in requestState -> -32602 INVALID_PARAMS
            bad_char = "X" if sealed_state[-1] != "X" else "Y"
            tampered_state = sealed_state[:-1] + bad_char
            tampered_resp = await http_client.post(
                "/mcp",
                headers=_headers(alice_token),
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "delete_rule",
                        "arguments": {"rule_id": "ru_mrtr_001", "force": False},
                        "requestState": tampered_state,
                        "inputResponses": {
                            "confirm_destructive": {
                                "action": "accept",
                                "content": {"confirm": True, "reason": "ok"},
                            }
                        },
                        "_meta": meta_caps,
                    },
                },
            )
            tampered_body = _decode_http_jsonrpc(tampered_resp)
            assert tampered_body["error"]["code"] == INVALID_PARAMS
            mock_chronicle.delete_rule.assert_not_called()

            # Attack 2: Cross-principal replay (Mallory replays Alice's sealed requestState) -> -32602
            mallory_resp = await http_client.post(
                "/mcp",
                headers=_headers(mallory_token),
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "delete_rule",
                        "arguments": {"rule_id": "ru_mrtr_001", "force": False},
                        "requestState": sealed_state,
                        "inputResponses": {
                            "confirm_destructive": {
                                "action": "accept",
                                "content": {"confirm": True, "reason": "hijack"},
                            }
                        },
                        "_meta": meta_caps,
                    },
                },
            )
            mallory_body = _decode_http_jsonrpc(mallory_resp)
            assert mallory_body["error"]["code"] == INVALID_PARAMS
            mock_chronicle.delete_rule.assert_not_called()

            # Attack 3: Argument swap (Alice changes force=False -> force=True on Round 2) -> -32602
            arg_swap_resp = await http_client.post(
                "/mcp",
                headers=_headers(alice_token),
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "delete_rule",
                        "arguments": {"rule_id": "ru_mrtr_001", "force": True},
                        "requestState": sealed_state,
                        "inputResponses": {
                            "confirm_destructive": {
                                "action": "accept",
                                "content": {"confirm": True, "reason": "swap"},
                            }
                        },
                        "_meta": meta_caps,
                    },
                },
            )
            arg_swap_body = _decode_http_jsonrpc(arg_swap_resp)
            assert arg_swap_body["error"]["code"] == INVALID_PARAMS
            mock_chronicle.delete_rule.assert_not_called()

            # Attack 4: Stripped requestState (forged inputResponses with requestState=None) -> ToolError
            stripped_resp = await http_client.post(
                "/mcp",
                headers=_headers(alice_token),
                json={
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "delete_rule",
                        "arguments": {"rule_id": "ru_mrtr_001", "force": False},
                        "inputResponses": {
                            "confirm_destructive": {
                                "action": "accept",
                                "content": {"confirm": True, "reason": "forged"},
                            }
                        },
                        "_meta": meta_caps,
                    },
                },
            )
            stripped_body = _decode_http_jsonrpc(stripped_resp)
            assert stripped_body["result"]["isError"] is True
            assert "requestState" in stripped_body["result"]["content"][0]["text"]
            mock_chronicle.delete_rule.assert_not_called()

            # Legitimate Round 2 (Alice with unmodified arguments + valid sealed requestState) -> succeeds
            r2 = await http_client.post(
                "/mcp",
                headers=_headers(alice_token),
                json={
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "delete_rule",
                        "arguments": {"rule_id": "ru_mrtr_001", "force": False},
                        "requestState": sealed_state,
                        "inputResponses": {
                            "confirm_destructive": {
                                "action": "accept",
                                "content": {"confirm": True, "reason": "verified"},
                            }
                        },
                        "_meta": meta_caps,
                    },
                },
            )
            r2_body = _decode_http_jsonrpc(r2)
            assert r2_body["result"].get("isError", False) is False
            assert r2_body["result"]["structuredContent"]["deleted"] is True
            mock_chronicle.delete_rule.assert_called_once_with("ru_mrtr_001", force=False)


# ---------------------------------------------------------------------------
# 3. Incremental Progress Notifications (ctx.report_progress)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_progress_notifications_emitted_on_long_running_secops_and_gti_tools(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Verify test_rule, export_udm_search_csv, analyse_file, and analyse_url stream >= 2 progress updates."""
    monkeypatch.setenv("MCP_ELICIT_DESTRUCTIVE", "false")

    # 1. SecOps: test_rule and export_udm_search_csv
    mock_chronicle = MagicMock()
    mock_chronicle.run_rule_test.return_value = [
        {"type": "progress", "percentDone": 45},
        {"type": "progress", "percentDone": 85},
        {
            "type": "detection",
            "detection": {
                "rule_id": "ru_test_01",
                "detection_time": "2026-11-07T12:00:00Z",
            },
        },
    ]
    mock_chronicle.fetch_udm_search_csv.return_value = (
        "metadata.event_timestamp,principal.hostname\n2026-11-07T12:00:00Z,wkstn-01\n"
    )

    test_rule_events: list[tuple[float, float | None, str | None]] = []
    csv_events: list[tuple[float, float | None, str | None]] = []

    async def _on_rule_progress(
        progress: float,
        total: float | None,
        message: str | None,
    ) -> None:
        test_rule_events.append((progress, total, message))

    async def _on_csv_progress(
        progress: float,
        total: float | None,
        message: str | None,
    ) -> None:
        csv_events.append((progress, total, message))

    with (
        patch(
            "secops_mcp.tools.security_rules.get_chronicle_client",
            return_value=mock_chronicle,
        ),
        patch(
            "secops_mcp.tools.udm_search.get_chronicle_client",
            return_value=mock_chronicle,
        ),
    ):
        async with Client(secops_server_mod.server) as secops_client:
            rule_res = await secops_client.call_tool(
                "test_rule",
                {
                    "rule_text": "rule sample { meta: author = \"soc\" events: $e.metadata.event_type = \"USER_LOGIN\" condition: $e }",
                    "hours_back": 24,
                },
                progress_callback=_on_rule_progress,
            )
            assert rule_res.is_error is False
            assert len(test_rule_events) >= 4
            progress_values = [p for p, _, _ in test_rule_events]
            assert progress_values == sorted(progress_values)
            assert progress_values[-1] == 100.0
            assert all(t == 100.0 for _, t, _ in test_rule_events)
            assert all(bool(m) for _, _, m in test_rule_events)

            csv_res = await secops_client.call_tool(
                "export_udm_search_csv",
                {
                    "query": 'metadata.event_type = "USER_LOGIN"',
                    "fields": ["metadata.event_timestamp", "principal.hostname"],
                    "hours_back": 12,
                },
                progress_callback=_on_csv_progress,
            )
            assert csv_res.is_error is False
            assert len(csv_events) >= 3
            csv_progress = [p for p, _, _ in csv_events]
            assert csv_progress == sorted(csv_progress)
            assert csv_progress[-1] == 3.0
            assert all(t == 3.0 for _, t, _ in csv_events)

    # 2. GTI: analyse_file and analyse_url
    sample_file = tmp_path / "telemetry_artifact.bin"
    sample_file.write_bytes(b"sample-binary-bytes")

    fake_vt_client = AsyncMock()
    fake_vt_client.scan_file_async = AsyncMock(return_value=MagicMock(id="an-file-1"))
    fake_vt_client.scan_url_async = AsyncMock(return_value=MagicMock(id="an-url-1"))
    fake_done = MagicMock()
    fake_done.id = "an-done"
    fake_done.to_dict.return_value = {
        "id": "an-done",
        "type": "analysis",
        "attributes": {"status": "completed", "stats": {"malicious": 0, "harmless": 70}},
    }
    fake_vt_client.wait_for_analysis_completion = AsyncMock(return_value=fake_done)
    fake_vt_client.close_async = AsyncMock()

    file_events: list[tuple[float, float | None, str | None]] = []
    url_events: list[tuple[float, float | None, str | None]] = []

    async def _on_file_progress(
        progress: float,
        total: float | None,
        message: str | None,
    ) -> None:
        file_events.append((progress, total, message))

    async def _on_url_progress(
        progress: float,
        total: float | None,
        message: str | None,
    ) -> None:
        url_events.append((progress, total, message))

    with (
        patch("gti_mcp.tools.files.vt_client") as mock_files_vt,
        patch("gti_mcp.tools.urls.vt_client") as mock_urls_vt,
    ):
        mock_files_vt.return_value.__aenter__.return_value = fake_vt_client
        mock_files_vt.return_value.__aexit__.return_value = False
        mock_urls_vt.return_value.__aenter__.return_value = fake_vt_client
        mock_urls_vt.return_value.__aexit__.return_value = False

        async with Client(gti_server_mod.server) as gti_client:
            f_res = await gti_client.call_tool(
                "analyse_file",
                {"file_path": str(sample_file)},
                progress_callback=_on_file_progress,
            )
            assert f_res.is_error is False
            assert [p for p, _, _ in file_events] == [0.0, 1.0, 2.0, 3.0, 4.0]
            assert all(t == 4.0 for _, t, _ in file_events)

            u_res = await gti_client.call_tool(
                "analyse_url",
                {"url": "https://suspicious-login.example.net/auth"},
                progress_callback=_on_url_progress,
            )
            assert u_res.is_error is False
            assert [p for p, _, _ in url_events] == [0.0, 1.0, 2.0, 3.0]
            assert all(t == 3.0 for _, t, _ in url_events)


# ---------------------------------------------------------------------------
# 4. OAuth 2.1 Resource Server Mode (RFC 9728 Metadata + RFC 8707 Audience)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("entry", SERVER_ENTRIES, ids=[e.name for e in SERVER_ENTRIES])
async def test_oauth_2_1_resource_server_metadata_and_token_enforcement(
    entry: ServerEntry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify RFC 9728 metadata, unauthenticated probes, 401/403 rejections, and HS256/RS256 tokens."""
    issuer = "https://auth.example.com"
    hs256_secret = "shared-hs256-test-signing-key-for-oauth-rs"
    monkeypatch.setenv("MCP_OAUTH_ISSUER_URL", issuer)
    monkeypatch.setenv("MCP_RESOURCE_SERVER_URL", entry.resource_url)
    monkeypatch.setenv("MCP_REQUIRED_SCOPES", "mcp:read,mcp:tools")
    monkeypatch.setenv("MCP_OAUTH_HS256_SECRET", hs256_secret)

    app = entry.build_http_app(entry.server, host="0.0.0.0", stateless_http=True)
    host_header = entry.resource_url.split("://", 1)[1].split("/", 1)[0]
    now = int(time.time())

    unauth_token_wrong_aud = _mint_hs256_jwt(
        {
            "iss": issuer,
            "sub": "analyst@example.com",
            "aud": "https://unrelated-api.example.com/mcp",
            "scope": "mcp:read mcp:tools",
            "exp": now + 600,
        },
        hs256_secret,
    )
    expired_token = _mint_hs256_jwt(
        {
            "iss": issuer,
            "sub": "analyst@example.com",
            "aud": entry.resource_url,
            "scope": "mcp:read mcp:tools",
            "exp": now - 120,
        },
        hs256_secret,
    )
    wrong_issuer_token = _mint_hs256_jwt(
        {
            "iss": "https://untrusted-issuer.example.com",
            "sub": "analyst@example.com",
            "aud": entry.resource_url,
            "scope": "mcp:read mcp:tools",
            "exp": now + 600,
        },
        hs256_secret,
    )
    missing_scope_token = _mint_hs256_jwt(
        {
            "iss": issuer,
            "sub": "analyst@example.com",
            "aud": entry.resource_url,
            "scope": "mcp:read",
            "exp": now + 600,
        },
        hs256_secret,
    )
    valid_token = _mint_hs256_jwt(
        {
            "iss": issuer,
            "sub": "analyst@example.com",
            "client_id": "agy-soc-client",
            "aud": entry.resource_url,
            "scope": "mcp:read mcp:tools",
            "exp": now + 600,
        },
        hs256_secret,
    )

    tools_list_req = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    base_headers = {
        "Host": host_header,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }

    async with _asgi_http_client(app, base_url=f"https://{host_header}") as client:
        # 1. Infrastructure health/readiness probes remain accessible without Authorization
        for probe_path in ("/healthz", "/readyz"):
            probe = await client.get(probe_path, headers={"Host": "10.0.0.15:8000"})
            assert probe.status_code == 200
            assert probe.json()["status"] == "ok"

        # 2. RFC 9728 Protected Resource Metadata served at both root and path-qualified well-known URLs
        for wk_path in (
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ):
            wk_resp = await client.get(wk_path, headers={"Host": host_header})
            assert wk_resp.status_code == 200
            wk_json = wk_resp.json()
            assert wk_json["resource"].rstrip("/") == entry.resource_url.rstrip("/")
            auth_servers = [s.rstrip("/") for s in wk_json["authorization_servers"]]
            assert issuer.rstrip("/") in auth_servers

        # 3. Missing Authorization -> 401 Unauthorized with WWW-Authenticate challenge
        no_auth_resp = await client.post("/mcp", headers=base_headers, json=tools_list_req)
        assert no_auth_resp.status_code == 401
        assert "www-authenticate" in {k.lower() for k in no_auth_resp.headers.keys()}

        # 4. Wrong audience, expired token, or wrong issuer -> 401 Unauthorized
        for bad_tok in (unauth_token_wrong_aud, expired_token, wrong_issuer_token):
            bad_resp = await client.post(
                "/mcp",
                headers={**base_headers, "Authorization": f"Bearer {bad_tok}"},
                json=tools_list_req,
            )
            assert bad_resp.status_code == 401

        # 5. Insufficient scopes -> 403 Forbidden
        scope_resp = await client.post(
            "/mcp",
            headers={**base_headers, "Authorization": f"Bearer {missing_scope_token}"},
            json=tools_list_req,
        )
        assert scope_resp.status_code == 403

        # 6. Valid audience-bound token -> 200 OK
        ok_resp = await client.post(
            "/mcp",
            headers={**base_headers, "Authorization": f"Bearer {valid_token}"},
            json=tools_list_req,
        )
        assert ok_resp.status_code == 200
        ok_payload = _decode_http_jsonrpc(ok_resp)
        assert len(ok_payload["result"]["tools"]) > 0


@pytest.mark.asyncio
async def test_oauth_rs256_asymmetric_jwt_verification_and_cli_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify RS256 public-key JWT verification and Phase 5 CLI argument parsing across all 4 servers."""
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub_pem = (
        rsa_priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    issuer = "https://accounts.google.com"
    resource_url = "https://scc-mcp.example.com/mcp"
    monkeypatch.delenv("MCP_OAUTH_HS256_SECRET", raising=False)
    monkeypatch.setenv("MCP_OAUTH_PUBLIC_KEY_PEM", rsa_pub_pem)

    now = int(time.time())
    rs256_token = _mint_rs256_jwt(
        {
            "iss": issuer,
            "sub": "109876543210",
            "azp": "scc-agent-client",
            "aud": [resource_url],
            "scp": ["scc:findings.read"],
            "exp": now + 600,
        },
        rsa_priv,
    )

    app = scc_server_mod.build_streamable_http_app(
        scc_server_mod.mcp,
        host="0.0.0.0",
        stateless_http=True,
        oauth_issuer_url=issuer,
        resource_server_url=resource_url,
        required_scopes=["scc:findings.read"],
    )
    async with _asgi_http_client(app, base_url="https://scc-mcp.example.com") as client:
        resp = await client.post(
            "/mcp",
            headers={
                "Host": "scc-mcp.example.com",
                "Authorization": f"Bearer {rs256_token}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
            },
            json={
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            },
        )
        assert resp.status_code == 200
        assert len(_decode_http_jsonrpc(resp)["result"]["tools"]) >= 6

    # Verify CLI flags parse cleanly across all 4 servers
    for entry in SERVER_ENTRIES:
        parser = entry.build_arg_parser()
        parsed = parser.parse_args(
            [
                "--transport",
                "streamable-http",
                "--elicit-destructive",
                "--unattended-policy",
                "deny",
                "--oauth-issuer-url",
                issuer,
                "--resource-server-url",
                entry.resource_url,
                "--required-scopes",
                "mcp:read,mcp:write",
                "--disable-apps",
            ]
        )
        assert parsed.elicit_destructive is True
        assert parsed.unattended_policy == "deny"
        assert parsed.oauth_issuer_url == issuer
        assert parsed.resource_server_url == entry.resource_url
        assert parsed.required_scopes == "mcp:read,mcp:write"
        assert parsed.disable_apps is True


@pytest.mark.asyncio
@pytest.mark.parametrize("entry", SERVER_ENTRIES, ids=[e.name for e in SERVER_ENTRIES])
async def test_oauth_inline_jwks_json_rs256_and_es256_kid_selection(
    entry: ServerEntry,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify MCP_OAUTH_JWKS_JSON supports kid-selected RS256 and ES256 keys and rejects bad kids/signatures."""
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    other_ec_priv = ec.generate_private_key(ec.SECP256R1())
    jwks_doc = {
        "keys": [
            _rsa_public_jwk(rsa_priv.public_key(), "rsa-kid-2026"),
            _ec_p256_public_jwk(ec_priv.public_key(), "ec-kid-2026"),
        ]
    }

    issuer = "https://idp.secops.example.com"
    monkeypatch.delenv("MCP_OAUTH_HS256_SECRET", raising=False)
    monkeypatch.delenv("MCP_OAUTH_PUBLIC_KEY_PEM", raising=False)
    monkeypatch.delenv("MCP_OAUTH_JWKS_URL", raising=False)
    monkeypatch.setenv("MCP_OAUTH_ISSUER_URL", issuer)
    monkeypatch.setenv("MCP_RESOURCE_SERVER_URL", entry.resource_url)
    monkeypatch.setenv("MCP_REQUIRED_SCOPES", "mcp:read")
    monkeypatch.setenv("MCP_OAUTH_JWKS_JSON", json.dumps(jwks_doc))

    now = int(time.time())
    rs256_ok = _mint_rs256_jwt(
        {
            "iss": issuer,
            "sub": "rsa-user",
            "aud": entry.resource_url,
            "scope": "mcp:read",
            "exp": now + 600,
        },
        rsa_priv,
        kid="rsa-kid-2026",
    )
    es256_ok = _mint_es256_jwt(
        {
            "iss": issuer,
            "sub": "ec-user",
            "aud": "oauth-gateway-client-id",
            "resource": entry.resource_url,
            "scope": "mcp:read",
            "exp": now + 600,
        },
        ec_priv,
        kid="ec-kid-2026",
    )
    wrong_kid_tok = _mint_es256_jwt(
        {
            "iss": issuer,
            "sub": "ec-user",
            "aud": entry.resource_url,
            "scope": "mcp:read",
            "exp": now + 600,
        },
        ec_priv,
        kid="missing-kid-999",
    )
    wrong_key_tok = _mint_es256_jwt(
        {
            "iss": issuer,
            "sub": "ec-user",
            "aud": entry.resource_url,
            "scope": "mcp:read",
            "exp": now + 600,
        },
        other_ec_priv,
        kid="ec-kid-2026",
    )
    tampered_es256 = es256_ok[:-2] + ("AA" if es256_ok[-2:] != "AA" else "BB")

    app = entry.build_http_app(entry.server, host="0.0.0.0", stateless_http=True)
    host_header = entry.resource_url.split("://", 1)[1].split("/", 1)[0]
    req_body = {
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    base_headers = {
        "Host": host_header,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }

    async with _asgi_http_client(app, base_url=f"https://{host_header}") as client:
        for good_tok in (rs256_ok, es256_ok):
            ok_resp = await client.post(
                "/mcp",
                headers={**base_headers, "Authorization": f"Bearer {good_tok}"},
                json=req_body,
            )
            assert ok_resp.status_code == 200

        for bad_tok in (wrong_kid_tok, wrong_key_tok, tampered_es256):
            bad_resp = await client.post(
                "/mcp",
                headers={**base_headers, "Authorization": f"Bearer {bad_tok}"},
                json=req_body,
            )
            assert bad_resp.status_code == 401


@pytest.mark.asyncio
async def test_oauth_remote_jwks_url_cached_http_fetch_and_rotation_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify MCP_OAUTH_JWKS_URL caches remote JWKS responses and refreshes on unknown kid after cooldown."""
    ec_v1 = ec.generate_private_key(ec.SECP256R1())
    ec_v2 = ec.generate_private_key(ec.SECP256R1())
    issuer = "https://auth.remote-jwks.example.com"
    jwks_url = "https://auth.remote-jwks.example.com/.well-known/jwks.json"
    resource_url = "https://secops-mcp.example.com/mcp"

    monkeypatch.delenv("MCP_OAUTH_HS256_SECRET", raising=False)
    monkeypatch.delenv("MCP_OAUTH_PUBLIC_KEY_PEM", raising=False)
    monkeypatch.delenv("MCP_OAUTH_JWKS_JSON", raising=False)
    monkeypatch.setenv("MCP_OAUTH_JWKS_URL", jwks_url)

    active_keys = [_ec_p256_public_jwk(ec_v1.public_key(), "kid-v1")]
    fetch_count = 0

    def _jwks_handler(request: Any) -> Response:
        nonlocal fetch_count
        assert str(request.url) == jwks_url
        fetch_count += 1
        return Response(
            200,
            headers={"Cache-Control": "public, max-age=300"},
            json={"keys": list(active_keys)},
        )

    mock_http = AsyncClient(transport=MockTransport(_jwks_handler))
    now = int(time.time())
    tok_v1 = _mint_es256_jwt(
        {
            "iss": issuer,
            "sub": "svc-agent",
            "aud": "client-id-abc",
            "resource": resource_url,
            "scope": "secops:read",
            "exp": now + 600,
        },
        ec_v1,
        kid="kid-v1",
    )
    tok_v2 = _mint_es256_jwt(
        {
            "iss": issuer,
            "sub": "svc-agent",
            "aud": resource_url,
            "scope": "secops:read",
            "exp": now + 600,
        },
        ec_v2,
        kid="kid-v2",
    )

    try:
        for mod in (secops_phase5, gti_phase5, soar_phase5, scc_server_mod):
            before = fetch_count
            verifier = mod.GoogleOIDCTokenVerifier(
                issuer_url=issuer,
                resource_server_url=resource_url,
                jwks_http_client=mock_http,
            )
            # 3 consecutive verifications must reuse the cached JWKS document (1 HTTP GET)
            for _ in range(3):
                verified = await verifier.verify_token(tok_v1)
                assert verified is not None
                assert verified.subject == "svc-agent"
            assert fetch_count - before == 1

            # Rotate key set to include kid-v2 after cooldown -> 1 refresh HTTP GET
            active_keys.append(_ec_p256_public_jwk(ec_v2.public_key(), "kid-v2"))
            verifier._last_jwks_fetch_at -= 10.0
            rotated = await verifier.verify_token(tok_v2)
            assert rotated is not None
            assert fetch_count - before == 2
            active_keys[:] = [_ec_p256_public_jwk(ec_v1.public_key(), "kid-v1")]
    finally:
        await mock_http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("entry", "phase5_mod"),
    [
        (SERVER_ENTRIES[0], secops_phase5),
        (SERVER_ENTRIES[1], gti_phase5),
        (SERVER_ENTRIES[2], soar_phase5),
        (SERVER_ENTRIES[3], scc_server_mod),
    ],
    ids=[e.name for e in SERVER_ENTRIES],
)
async def test_google_oidc_rfc8707_resource_only_binding_and_cached_request_session(
    entry: ServerEntry,
    phase5_mod: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify _verify_via_google_oidc accepts RFC 8707 resource-bound tokens when aud is a client ID and caches Request."""
    monkeypatch.delenv("MCP_OAUTH_HS256_SECRET", raising=False)
    monkeypatch.delenv("MCP_OAUTH_PUBLIC_KEY_PEM", raising=False)
    monkeypatch.delenv("MCP_OAUTH_JWKS_JSON", raising=False)
    monkeypatch.delenv("MCP_OAUTH_JWKS_URL", raising=False)

    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "accounts.google.com")]
    )
    cert_pem = (
        x509.CertificateBuilder()
        .subject_name(cert_name)
        .issuer_name(cert_name)
        .public_key(rsa_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(hours=1)
        )
        .sign(rsa_priv, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("utf-8")
    )

    class _FakeCertResponse:
        status = 200
        headers = {"cache-control": "public, max-age=3600"}
        data = json.dumps({"goog-kid-1": cert_pem}).encode("utf-8")

    request_invocations = 0

    def _counting_oidc_request(
        url: str,
        method: str = "GET",
        body: Any = None,
        headers: Any = None,
        timeout: Any = None,
        **kwargs: Any,
    ) -> _FakeCertResponse:
        nonlocal request_invocations
        request_invocations += 1
        assert url == "https://www.googleapis.com/oauth2/v1/certs"
        return _FakeCertResponse()

    issuer = "https://accounts.google.com"
    now = int(time.time())
    rfc8707_token = _mint_rs256_jwt(
        {
            "iss": issuer,
            "sub": "112233445566",
            "aud": "oauth-client-id",
            "resource": entry.resource_url,
            "scope": "mcp:read",
            "iat": now - 5,
            "exp": now + 600,
        },
        rsa_priv,
        kid="goog-kid-1",
    )

    verifier = phase5_mod.GoogleOIDCTokenVerifier(
        issuer_url=issuer,
        resource_server_url=entry.resource_url,
        oidc_request=_counting_oidc_request,
    )
    app = entry.build_http_app(
        entry.server,
        host="0.0.0.0",
        stateless_http=True,
        oauth_issuer_url=issuer,
        resource_server_url=entry.resource_url,
        required_scopes=["mcp:read"],
        token_verifier=verifier,
    )
    host_header = entry.resource_url.split("://", 1)[1].split("/", 1)[0]
    req_body = {
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    headers = {
        "Host": host_header,
        "Authorization": f"Bearer {rfc8707_token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": "tools/list",
    }

    async with _asgi_http_client(app, base_url=f"https://{host_header}") as client:
        r1 = await client.post("/mcp", headers=headers, json=req_body)
        assert r1.status_code == 200
        r2 = await client.post("/mcp", headers=headers, json=req_body)
        assert r2.status_code == 200
        assert verifier._oidc_request is _counting_oidc_request


@pytest.mark.asyncio
async def test_verify_callback_access_token_enforces_expiry_and_resource_and_no_dead_scopes() -> None:
    """Verify GoogleOIDCTokenVerifier drops dead required_scopes and validates AccessToken from verify_callback."""
    issuer = "https://auth.example.com"
    resource_url = "https://secops-mcp.example.com/mcp"
    now = int(time.time())

    for mod in (secops_phase5, gti_phase5, soar_phase5, scc_server_mod):
        with pytest.raises(TypeError):
            mod.GoogleOIDCTokenVerifier(
                issuer_url=issuer,
                resource_server_url=resource_url,
                required_scopes=["mcp:read"],  # type: ignore[call-arg]
            )

        expired_verifier = mod.GoogleOIDCTokenVerifier(
            issuer_url=issuer,
            resource_server_url=resource_url,
            verify_callback=lambda tok: AccessToken(
                token=tok,
                client_id="cb-client",
                scopes=["mcp:read"],
                expires_at=now - 30,
                resource=resource_url,
            ),
        )
        assert not hasattr(expired_verifier, "required_scopes")
        assert await expired_verifier.verify_token("opaque-expired-tok") is None

        wrong_res_verifier = mod.GoogleOIDCTokenVerifier(
            issuer_url=issuer,
            resource_server_url=resource_url,
            verify_callback=lambda tok: AccessToken(
                token=tok,
                client_id="cb-client",
                scopes=["mcp:read"],
                expires_at=now + 600,
                resource="https://unrelated-service.example.com/mcp",
            ),
        )
        assert await wrong_res_verifier.verify_token("opaque-wrong-res") is None

        valid_verifier = mod.GoogleOIDCTokenVerifier(
            issuer_url=issuer,
            resource_server_url=resource_url,
            verify_callback=lambda tok: AccessToken(
                token=tok,
                client_id="cb-client",
                scopes=["mcp:read"],
                expires_at=now + 600,
                resource=resource_url,
            ),
        )
        accepted = await valid_verifier.verify_token("opaque-valid-tok")
        assert accepted is not None
        assert accepted.client_id == "cb-client"

    # End-to-end HTTP 401 when verify_callback returns expired AccessToken
    app = secops_server_mod.build_streamable_http_app(
        secops_server_mod.server,
        host="0.0.0.0",
        stateless_http=True,
        oauth_issuer_url=issuer,
        resource_server_url=resource_url,
        required_scopes=["mcp:read"],
        token_verifier=secops_phase5.GoogleOIDCTokenVerifier(
            issuer_url=issuer,
            resource_server_url=resource_url,
            verify_callback=lambda tok: AccessToken(
                token=tok,
                client_id="cb-client",
                scopes=["mcp:read"],
                expires_at=now - 10,
                resource=resource_url,
            ),
        ),
    )
    async with _asgi_http_client(
        app, base_url="https://secops-mcp.example.com"
    ) as client:
        resp = await client.post(
            "/mcp",
            headers={
                "Host": "secops-mcp.example.com",
                "Authorization": "Bearer expired-callback-token",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
            },
            json={
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            },
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 5. Interactive Dark-Mode MCP Apps (io.modelcontextprotocol/ui) & Craft Audit
# ---------------------------------------------------------------------------


_FONT_SIZE_RE = re.compile(r"font-size\s*:\s*([0-9]+(?:\.[0-9]+)?)\s*(px|rem)", re.IGNORECASE)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("server_obj", "app_uri", "expected_linked_tools"),
    [
        (
            secops_server_mod.server,
            "ui://secops/entity-timeline.html",
            {"search_security_events", "lookup_entity"},
        ),
        (
            gti_server_mod.server,
            "ui://gti/ioc-verdict.html",
            {"get_file_report", "get_domain_report", "get_ip_address_report"},
        ),
        (
            scc_server_mod.mcp,
            "ui://scc/finding-card.html",
            {"top_vulnerability_findings", "get_finding_remediation"},
        ),
    ],
    ids=["secops-entity-timeline", "gti-ioc-verdict", "scc-finding-card"],
)
async def test_mcp_apps_resources_impeccable_dark_mode_craft_and_tool_metadata(
    server_obj: MCPServer,
    app_uri: str,
    expected_linked_tools: set[str],
) -> None:
    """Audit MCP Apps MIME type, <15 KB budget, CSP, dark-mode tokens, >=12px floor, and tool links."""
    async with Client(server_obj, extensions=[_McpAppsUiClientExtension()]) as client:
        resources_res = await client.list_resources()
        by_uri = {str(r.uri): r for r in resources_res.resources}
        assert app_uri in by_uri
        res_entry = by_uri[app_uri]
        assert res_entry.mime_type == APP_MIME_TYPE
        assert res_entry.meta is not None
        ui_meta = res_entry.meta.get("ui") or {}
        csp_meta = ui_meta.get("csp") or {}
        assert csp_meta.get("connectDomains") == []
        assert csp_meta.get("resourceDomains") == []
        assert csp_meta.get("frameDomains") == []
        assert csp_meta.get("baseUriDomains") == []

        read_res = await client.read_resource(app_uri)
        assert len(read_res.contents) == 1
        item = read_res.contents[0]
        assert isinstance(item, types.TextResourceContents)
        assert item.mime_type == "text/html;profile=mcp-app"
        html = item.text

        # Size & ASCII / zero-emoji invariant
        encoded = html.encode("utf-8")
        assert len(encoded) < 15_360, f"{app_uri} exceeded 15 KB ({len(encoded)} bytes)"
        assert html.isascii(), f"{app_uri} must be pure ASCII with zero emojis"

        # Strict inline CSP & zero external URLs
        assert (
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"
            in html
        )
        assert "http://" not in html.lower()
        assert "https://" not in html.lower()

        # Impeccable dark-mode palette & typography floor
        html_upper = html.upper()
        assert "#0E1012" in html_upper
        assert "#15181C" in html_upper
        assert "#262B33" in html_upper
        assert "#ECEFF4" in html_upper
        assert "#9AA4B2" in html_upper
        assert "#000000" not in html_upper
        assert "#FFFFFF" not in html_upper
        assert "tabular-nums" in html
        assert ":focus-visible" in html
        assert "border-left:" not in html.lower()
        assert "ev.source !== window.parent" in html
        if app_uri == "ui://scc/finding-card.html":
            assert 'setAttribute("tabindex", "0")' in html
            assert "keydown" in html
            assert "tr.finding-row:focus-visible" in html

        font_matches = _FONT_SIZE_RE.findall(html)
        assert len(font_matches) >= 5
        for raw_val, unit in font_matches:
            val = float(raw_val)
            px_val = val * 16.0 if unit.lower() == "rem" else val
            assert px_val >= 12.0, f"{app_uri} has sub-12px font-size: {raw_val}{unit}"

        # Linked tools advertise _meta.ui.resourceUri
        tools_res = await client.list_tools()
        tools_by_name = {t.name: t for t in tools_res.tools}
        for tool_name in expected_linked_tools:
            assert tool_name in tools_by_name
            tool_meta = tools_by_name[tool_name].meta or {}
            assert tool_meta.get("ui", {}).get("resourceUri") == app_uri


@pytest.mark.asyncio
async def test_mcp_apps_capability_negotiation_and_graceful_text_fallback() -> None:
    """Verify client_supports_apps toggles on UI extension and non-UI clients degrade cleanly."""
    probe_server = MCPServer(
        name="probe-apps",
        extensions=secops_phase5.build_secops_apps_extensions(),
    )

    @probe_server.tool()
    async def check_ui_support(ctx: Context) -> dict[str, bool]:
        return {"supports_apps": client_supports_apps(ctx)}

    async with Client(probe_server) as text_only_client:
        plain_res = await text_only_client.call_tool("check_ui_support", {})
        assert plain_res.structured_content == {"supports_apps": False}

    async with Client(
        probe_server,
        extensions=[_McpAppsUiClientExtension()],
    ) as ui_capable_client:
        ui_res = await ui_capable_client.call_tool("check_ui_support", {})
        assert ui_res.structured_content == {"supports_apps": True}

    # Invoke real UI-linked tools from a non-UI client -> complete text + structured_content
    fake_vt_client = AsyncMock()
    fake_vt_client.close_async = AsyncMock()
    mock_scc = MagicMock()
    mock_page = MagicMock()
    mock_page.list_findings_results = []
    mock_scc.list_findings.return_value.pages = [mock_page]

    with (
        patch("gti_mcp.tools.files.vt_client") as mock_vt_cm,
        patch(
            "gti_mcp.tools.files.utils.fetch_object",
            new=AsyncMock(
                return_value={
                    "id": "44d88612fea8a8f36de82e1278abb02f",
                    "type": "file",
                    "attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 60}},
                }
            ),
        ),
        patch.object(scc_server_mod, "scc_client", mock_scc),
    ):
        mock_vt_cm.return_value.__aenter__.return_value = fake_vt_client
        mock_vt_cm.return_value.__aexit__.return_value = False

        async with Client(gti_server_mod.server) as non_ui_gti:
            gti_res = await non_ui_gti.call_tool(
                "get_file_report",
                {"hash": "44d88612fea8a8f36de82e1278abb02f"},
            )
            assert gti_res.is_error is False
            assert len(gti_res.content) >= 1
            assert gti_res.structured_content is not None
            assert gti_res.structured_content["id"] == "44d88612fea8a8f36de82e1278abb02f"

        async with Client(scc_server_mod.mcp) as non_ui_scc:
            scc_res = await non_ui_scc.call_tool(
                "top_vulnerability_findings",
                {"project_id": "demo-project", "max_findings": 5},
            )
            assert scc_res.is_error is False
            assert len(scc_res.content) >= 1
            assert scc_res.structured_content is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("server_mod", "server_obj", "app_uri", "expected_linked_tools"),
    [
        (
            secops_server_mod,
            secops_server_mod.server,
            "ui://secops/entity-timeline.html",
            {"search_security_events", "lookup_entity"},
        ),
        (
            gti_server_mod,
            gti_server_mod.server,
            "ui://gti/ioc-verdict.html",
            {"get_file_report", "get_domain_report", "get_ip_address_report"},
        ),
        (
            scc_server_mod,
            scc_server_mod.mcp,
            "ui://scc/finding-card.html",
            {"top_vulnerability_findings", "get_finding_remediation"},
        ),
    ],
    ids=["secops-disable-apps", "gti-disable-apps", "scc-disable-apps"],
)
async def test_mcp_enable_apps_false_and_disable_apps_toggle_and_restore(
    server_mod: Any,
    server_obj: MCPServer,
    app_uri: str,
    expected_linked_tools: set[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify MCP_ENABLE_APPS=false and --disable-apps omit ui:// resources and _meta.ui and restore cleanly."""
    try:
        # 1. Disable via MCP_ENABLE_APPS=false + sync_apps_state (and build_streamable_http_app)
        monkeypatch.setenv("MCP_ENABLE_APPS", "false")
        assert server_mod.sync_apps_state(server_obj) is False
        assert EXTENSION_ID not in server_obj._lowlevel_server.extensions

        async with Client(
            server_obj, extensions=[_McpAppsUiClientExtension()]
        ) as disabled_client:
            disabled_res = await disabled_client.list_resources()
            disabled_uris = {str(r.uri) for r in disabled_res.resources}
            assert app_uri not in disabled_uris
            assert not any(u.startswith("ui://") for u in disabled_uris)

            disabled_tools = await disabled_client.list_tools()
            by_name = {t.name: t for t in disabled_tools.tools}
            for tool_name in expected_linked_tools:
                meta = by_name[tool_name].meta or {}
                assert "ui" not in meta

        # 2. Re-enable MCP_ENABLE_APPS=true -> restores extension, ui:// resource, and _meta.ui
        monkeypatch.setenv("MCP_ENABLE_APPS", "true")
        assert server_mod.sync_apps_state(server_obj) is True
        assert EXTENSION_ID in server_obj._lowlevel_server.extensions

        # 3. Simulate --disable-apps flag via build_arg_parser + build_streamable_http_app
        parsed = server_mod.build_arg_parser().parse_args(["--disable-apps"])
        assert parsed.disable_apps is True
        monkeypatch.setenv("MCP_ENABLE_APPS", "false")
        server_mod.build_streamable_http_app(server_obj)
        assert EXTENSION_ID not in server_obj._lowlevel_server.extensions

        # 4. Restore MCP_ENABLE_APPS=true and verify client sees ui:// resource and _meta.ui.resourceUri again
        monkeypatch.setenv("MCP_ENABLE_APPS", "true")
        assert server_mod.sync_apps_state(server_obj) is True

        async with Client(
            server_obj, extensions=[_McpAppsUiClientExtension()]
        ) as restored_client:
            restored_res = await restored_client.list_resources()
            restored_uris = {str(r.uri) for r in restored_res.resources}
            assert app_uri in restored_uris

            restored_tools = await restored_client.list_tools()
            restored_by_name = {t.name: t for t in restored_tools.tools}
            for tool_name in expected_linked_tools:
                meta = restored_by_name[tool_name].meta or {}
                assert meta.get("ui", {}).get("resourceUri") == app_uri
    finally:
        monkeypatch.setenv("MCP_ENABLE_APPS", "true")
        server_mod.sync_apps_state(server_obj)
