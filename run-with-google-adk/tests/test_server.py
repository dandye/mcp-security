"""Unit tests for mcp_security_agent.server."""

import json
import sys
import unicodedata
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

# Add src directory to path
src_dir = str(Path(__file__).resolve().parents[1] / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from mcp_security_agent.server.app import create_app


def test_healthz():
    client = TestClient(create_app())
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_app_name():
    client = TestClient(create_app())
    response = client.get("/app_name")
    assert response.status_code == 200
    assert response.json() == {"app_name": "Google Security Agent"}


def test_info():
    client = TestClient(create_app())
    response = client.get("/info")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "0.3.0"
    assert "model" in data
    assert "location" in data
    assert "confirm_destructive_tools" in data
    assert "tools" in data
    assert "user" in data
    assert bool(data["user"])


def test_root():
    client = TestClient(create_app())
    response = client.get("/")
    assert response.status_code == 200
    assert "gemini-3.1-pro-preview" in response.text


def test_get_session_default():
    client = TestClient(create_app())
    response = client.get("/get_session")
    assert response.status_code == 200
    data = response.json()
    assert "session_id" in data
    assert len(data["session_id"]) > 10
    assert "user_id" in data
    assert bool(data["user_id"])


def test_get_session_with_username():
    client = TestClient(create_app())
    response = client.get("/get_session", params={"username": "alice"})
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == "alice"


class MockRunner:
    async def run_async(self, *args, **kwargs):
        from google.adk.events import Event
        from google.genai import types

        yield Event(
            author="SecurityOperationsAgent",
            content=types.Content(
                role="model", parts=[types.Part(text="Mocked analysis response")]
            ),
        )


def test_chat_post():
    with patch("mcp_security_agent.server.routes.get_runner", return_value=MockRunner()):
        client = TestClient(create_app())
        response = client.post(
            "/chat", json={"prompt": "Investigate alert 123", "session_id": "test-sess"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "response" in data
        assert "Mocked analysis response" in data["response"]
        assert data["session_id"] == "test-sess"


def test_chat_sse_stream():
    with patch("mcp_security_agent.server.routes.get_runner", return_value=MockRunner()):
        client = TestClient(create_app())
        response = client.get(
            "/chat", params={"message": "check finding", "session_id": "test-sess"}
        )
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        assert "Mocked analysis response" in response.text
        assert "Stream finished." in response.text


def test_chat_destructive_confirmation_interrupt_and_resume():
    from google.adk.events import Event
    from google.genai import types
    import mcp_security_agent.server.routes as server_routes

    svc = server_routes.BoundedSessionService(max_sessions=10)
    captured_calls = []

    class ConfirmationAwareRunner:
        async def run_async(self, **kwargs):
            captured_calls.append(kwargs)
            sess = await svc.get_session(
                app_name="mcp_security_agent",
                user_id=kwargs["user_id"],
                session_id=kwargs["session_id"],
            )
            new_msg = kwargs["new_message"]
            await svc.append_event(
                sess,
                Event(author="user", invocation_id="inv-1", content=new_msg),
            )
            if len(captured_calls) == 1:
                confirm_fc = types.FunctionCall(
                    id="confirm-fc-1",
                    name="adk_request_confirmation",
                    args={
                        "originalFunctionCall": {
                            "id": "orig-fc-1",
                            "name": "delete_security_rule",
                            "args": {"rule_id": "ru_a1b2c3d4-e5f6-4321-abcd-ef1234567890"},
                        }
                    },
                )
                ev = Event(
                    author="SecurityOperationsAgent",
                    invocation_id="inv-1",
                    long_running_tool_ids={"confirm-fc-1"},
                    content=types.Content(
                        role="model",
                        parts=[types.Part(function_call=confirm_fc)],
                    ),
                )
                await svc.append_event(sess, ev)
                yield ev
            else:
                ev = Event(
                    author="SecurityOperationsAgent",
                    invocation_id=kwargs.get("invocation_id") or "inv-1",
                    content=types.Content(
                        role="model",
                        parts=[types.Part(text="Confirmed and deleted rule.")],
                    ),
                )
                await svc.append_event(sess, ev)
                yield ev

    with (
        patch(
            "mcp_security_agent.server.routes.get_runner",
            return_value=ConfirmationAwareRunner(),
        ),
        patch(
            "mcp_security_agent.server.routes.get_session_service",
            return_value=svc,
        ),
    ):
        client = TestClient(create_app())
        first = client.post(
            "/chat",
            json={
                "message": "Delete rule ru_a1b2c3d4-e5f6-4321-abcd-ef1234567890",
                "session_id": "confirm-sess",
                "user_id": "analyst",
            },
            headers={"accept": "text/event-stream"},
        )
        assert first.status_code == 200
        assert "confirmation_request" in first.text
        assert "delete_security_rule" in first.text

        second = client.post(
            "/chat",
            json={
                "message": "yes",
                "session_id": "confirm-sess",
                "user_id": "analyst",
            },
            headers={"accept": "text/event-stream"},
        )
        assert second.status_code == 200
        assert "Confirmed and deleted rule." in second.text

        assert len(captured_calls) == 2
        resumed_kwargs = captured_calls[1]
        assert resumed_kwargs.get("invocation_id") == "inv-1"
        fr = resumed_kwargs["new_message"].parts[0].function_response
        assert fr.id == "confirm-fc-1"
        assert fr.name == "adk_request_confirmation"
        assert fr.response == {"confirmed": True}


def test_login_and_alias_routes():
    client = TestClient(create_app())
    for path in ["/login", "/index.html", "/landing.html", "/chat.html"]:
        response = client.get(path)
        assert response.status_code == 200


def test_chat_post_sse_streaming():
    with patch("mcp_security_agent.server.routes.get_runner", return_value=MockRunner()):
        client = TestClient(create_app())
        response = client.post(
            "/chat",
            json={"message": "Investigate alert 123", "session_id": "test-sess"},
            headers={"accept": "text/event-stream"},
        )
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        assert "Mocked analysis response" in response.text
        assert "Stream finished." in response.text


def test_no_cache_headers():
    client = TestClient(create_app())
    for path in ["/", "/login", "/landing.html", "/index.html"]:
        response = client.get(path)
        assert response.status_code == 200
        assert "no-store" in response.headers.get("cache-control", "")
        assert "no-cache" in response.headers.get("pragma", "")


def test_favicon():
    client = TestClient(create_app())
    response = client.get("/favicon.ico")
    assert response.status_code == 204


def test_static_assets():
    client = TestClient(create_app())
    for path in ["/static/app.css", "/static/app.js"]:
        response = client.get(path)
        assert response.status_code == 200
        assert "no-store" in response.headers.get("cache-control", "")


def test_no_emojis_in_web_app_and_stream():
    client = TestClient(create_app())
    for path in ["/", "/index.html", "/static/app.js", "/static/app.css"]:
        resp = client.get(path)
        assert resp.status_code == 200
        for char in resp.text:
            code = ord(char)
            if (
                (code > 0x2000 and unicodedata.category(char) in ("So", "Sk", "Sm", "Cn"))
                or code > 0x1F000
                or (0x2600 <= code <= 0x27BF)
            ):
                assert char in (
                    "`",
                    "^",
                    "~",
                    "<",
                    ">",
                    "+",
                    "=",
                    "|",
                    "\u2022",
                ), f"Unexpected emoji/symbol in {path}: {char!r} (U+{code:04X})"

    with patch("mcp_security_agent.server.routes.get_runner", return_value=None):
        resp = client.get("/chat", params={"message": "hello"})
        assert resp.status_code == 200
        assert "[Warning]" in resp.text
        for char in resp.text:
            code = ord(char)
            if (
                (code > 0x2000 and unicodedata.category(char) in ("So", "Sk", "Sm", "Cn"))
                or code > 0x1F000
                or (0x2600 <= code <= 0x27BF)
            ):
                assert char in (
                    "`",
                    "^",
                    "~",
                    "<",
                    ">",
                    "+",
                    "=",
                    "|",
                    "\u2022",
                ), f"Unexpected emoji/symbol in stream: {char!r}"


def test_scroll_and_layout_constraints():
    client = TestClient(create_app())
    resp = client.get("/static/app.css")
    assert resp.status_code == 200
    css = resp.text

    assert "max-height: 100vh" in css or "height: 100vh" in css
    assert "min-height: 0" in css
    assert "overflow-y: auto" in css
    assert "scrollbar-width: thin" in css
    assert "::-webkit-scrollbar" in css


def test_bounded_session_service_eviction():
    from mcp_security_agent.server.routes import BoundedSessionService

    service = BoundedSessionService(max_sessions=10)

    import asyncio

    async def run_test():
        for i in range(12):
            await service.create_session(
                app_name="test_app",
                user_id="user",
                session_id=f"sess_{i}",
            )
        assert len(service._session_order) == 10
        user_sessions = service.sessions["test_app"]["user"]
        assert len(user_sessions) == 10
        assert "sess_0" not in user_sessions
        assert "sess_1" not in user_sessions
        assert "sess_10" in user_sessions
        assert "sess_11" in user_sessions

        multi_service = BoundedSessionService(max_sessions=5)
        for i in range(8):
            await multi_service.create_session(
                app_name="test_app",
                user_id=f"user_{i}",
                session_id=f"sess_{i}",
            )
        assert len(multi_service._session_order) == 5
        assert "user_0" not in multi_service.sessions["test_app"]
        assert "user_1" not in multi_service.sessions["test_app"]
        assert "user_2" not in multi_service.sessions["test_app"]
        for i in range(3, 8):
            assert f"user_{i}" in multi_service.sessions["test_app"]

        await multi_service.delete_session(
            app_name="test_app",
            user_id="user_7",
            session_id="sess_7",
        )
        assert "user_7" not in multi_service.sessions["test_app"]

    asyncio.run(run_test())


def test_get_runner_agent_creation():
    from unittest.mock import MagicMock
    import mcp_security_agent.agent as agent_mod
    import mcp_security_agent.server.routes as server_routes

    original_runner = server_routes._runner
    original_root = getattr(agent_mod, "_root_agent", None)
    try:
        server_routes._runner = None
        agent_mod._root_agent = None

        mock_agent = MagicMock()
        with (
            patch(
                "mcp_security_agent.agent.create_security_agent", return_value=mock_agent
            ) as mock_create,
            patch("mcp_security_agent.server.routes.Runner"),
        ):
            runner = server_routes.get_runner()
            assert runner is not None
            mock_create.assert_called_once()
            assert agent_mod._root_agent is mock_agent
    finally:
        server_routes._runner = original_runner
        agent_mod._root_agent = original_root


def test_dompurify_xss_protection():
    client = TestClient(create_app())
    html = client.get("/index.html").text
    js = client.get("/static/app.js").text

    assert "dompurify" in html
    assert "DOMPurify.sanitize" in js
    assert "renderMarkdown" in js
    assert "failing closed to escaped text" in js


def test_frontend_streaming_abort_on_reset():
    client = TestClient(create_app())
    js = client.get("/static/app.js").text

    assert "cancelStreaming" in js
    assert "newInvestigationBtn.addEventListener" in js
    assert "if (isStreaming) {\n      cancelStreaming();\n    }\n    messagesContainer.innerHTML = '';" in js
    assert "if (isStreaming) {\n      cancelStreaming();\n    }\n    currentUserId = newName;" in js


def test_bounded_session_service_thread_safe_lookups():
    from google.adk.events import Event
    from google.genai import types
    from mcp_security_agent.server.routes import BoundedSessionService

    service = BoundedSessionService(max_sessions=5)

    import asyncio

    async def run_test():
        sess = await service.create_session(
            app_name="test_app",
            user_id="alice",
            session_id="sess_1",
        )
        assert sess is not None

        retrieved = await service.get_session(
            app_name="test_app", user_id="alice", session_id="sess_1"
        )
        assert retrieved is not None
        assert retrieved.id == "sess_1"

        sessions_list = await service.list_sessions(app_name="test_app", user_id="alice")
        assert len(sessions_list.sessions) == 1

        test_event = Event(
            author="SecurityOperationsAgent",
            content=types.Content(role="model", parts=[types.Part(text="Test event")]),
        )
        appended = await service.append_event(sess, test_event)
        assert appended == test_event

        dummy_sess = type(
            "DummySession", (), {"app_name": "test_app", "user_id": "bob", "id": "sess_gone"}
        )()
        result_evicted = await service.append_event(dummy_sess, test_event)
        assert result_evicted == test_event

    asyncio.run(run_test())
