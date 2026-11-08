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
"""REST and SSE endpoints for FastAPI server and Cloud Run deployments."""

import asyncio
from collections import OrderedDict
import json
import logging
from pathlib import Path
import threading
from typing import Any, AsyncGenerator, Dict, Optional, Tuple
import uuid

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from pydantic import BaseModel

from mcp_security_agent import __version__
import mcp_security_agent.agent as agent_mod
from mcp_security_agent.config import AgentSettings, discover_user_identity

logger = logging.getLogger(__name__)

router = APIRouter()

CONFIRMATION_FUNCTION_CALL_NAME = "adk_request_confirmation"


class ChatRequest(BaseModel):
    prompt: Optional[str] = None
    message: Optional[str] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    confirmed: Optional[bool] = None


class ChatResponse(BaseModel):
    response: str
    session_id: str


@router.get("/")
@router.get("/index.html")
@router.get("/landing.html")
@router.get("/chat.html")
@router.get("/login")
def get_root():
    """Serves the unified investigation console of the web UI."""
    pkg_root = Path(__file__).resolve().parents[3]
    index_file = pkg_root / "static" / "index.html"
    if index_file.is_file():
        return FileResponse(str(index_file))
    return JSONResponse({"status": "ok", "message": "MCP Security Agent API is running."})


@router.get("/healthz")
def health_check() -> Dict[str, str]:
    """Health check endpoint for Cloud Run and Kubernetes probes."""
    return {"status": "ok"}


@router.get("/favicon.ico")
def get_favicon():
    """Returns 204 No Content for browser favicon requests."""
    return Response(status_code=204)


@router.get("/app_name")
def get_app_name() -> Dict[str, str]:
    """Returns the application display name for the Web UI navbar."""
    return {"app_name": "Google Security Agent"}


@router.get("/get_session")
def get_session(
    username: Optional[str] = Query(None, description="Username for session")
) -> Dict[str, str]:
    """Generates a session ID and returns user context for chat sessions."""
    detected_user = discover_user_identity()
    user = (
        username
        if (username and username.strip() and username != "secops_user")
        else detected_user
    )
    return {
        "session_id": str(uuid.uuid4()),
        "user_id": user,
    }


_settings: Optional[AgentSettings] = None
_settings_lock = threading.Lock()


def get_settings() -> AgentSettings:
    """Returns cached AgentSettings singleton to avoid redundant env parsing."""
    global _settings
    if _settings is None:
        with _settings_lock:
            if _settings is None:
                _settings = AgentSettings()
    return _settings


@router.get("/info")
def get_info() -> Dict[str, Any]:
    """Provides server runtime metadata, active user identity, and enabled MCP server status."""
    settings = get_settings()
    return {
        "version": __version__,
        "model": settings.google_model,
        "location": settings.google_cloud_location,
        "user": discover_user_identity(),
        "confirm_destructive_tools": settings.confirm_destructive_tools,
        "tools": {
            "secops": settings.load_secops_mcp,
            "scc": settings.load_scc_mcp,
            "gti": settings.load_gti_mcp,
            "soar": settings.load_secops_soar_mcp,
        },
    }


class BoundedSessionService(InMemorySessionService):
    """InMemorySessionService with FIFO session eviction to prevent unbounded memory growth."""

    def __init__(self, max_sessions: int = 1000):
        super().__init__()
        self.max_sessions = max_sessions
        self._session_order: OrderedDict = OrderedDict()
        self._lock = threading.RLock()

    def _create_session_impl(
        self,
        *,
        app_name: str,
        user_id: str,
        state: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
    ) -> Any:
        with self._lock:
            while len(self._session_order) >= self.max_sessions:
                (old_app, old_user, old_sess), _ = self._session_order.popitem(last=False)
                if old_app in self.sessions and old_user in self.sessions[old_app]:
                    self.sessions[old_app][old_user].pop(old_sess, None)
                    if not self.sessions[old_app][old_user]:
                        self.sessions[old_app].pop(old_user, None)
                if old_app in self.sessions and not self.sessions[old_app]:
                    self.sessions.pop(old_app, None)
            sess = super()._create_session_impl(
                app_name=app_name,
                user_id=user_id,
                state=state,
                session_id=session_id,
            )
            self._session_order[(app_name, user_id, sess.id)] = True
            return sess

    def _get_session_impl(
        self,
        *,
        app_name: str,
        user_id: str,
        session_id: str,
        config: Optional[Any] = None,
    ) -> Optional[Any]:
        with self._lock:
            return super()._get_session_impl(
                app_name=app_name,
                user_id=user_id,
                session_id=session_id,
                config=config,
            )

    def _list_sessions_impl(
        self,
        *,
        app_name: str,
        user_id: Optional[str] = None,
    ) -> Any:
        with self._lock:
            return super()._list_sessions_impl(
                app_name=app_name,
                user_id=user_id,
            )

    async def append_event(self, session: Any, event: Any) -> Any:
        with self._lock:
            app_name = getattr(session, "app_name", None)
            user_id = getattr(session, "user_id", None)
            session_id = getattr(session, "id", None)
            if (
                not app_name
                or not user_id
                or not session_id
                or app_name not in self.sessions
                or user_id not in self.sessions[app_name]
                or session_id not in self.sessions[app_name][user_id]
            ):
                return event
            return await super().append_event(session=session, event=event)

    def _delete_session_impl(
        self,
        *,
        app_name: str,
        user_id: str,
        session_id: str,
    ) -> None:
        with self._lock:
            self._session_order.pop((app_name, user_id, session_id), None)
            super()._delete_session_impl(
                app_name=app_name,
                user_id=user_id,
                session_id=session_id,
            )
            if app_name in self.sessions and user_id in self.sessions[app_name]:
                if not self.sessions[app_name][user_id]:
                    self.sessions[app_name].pop(user_id, None)
            if app_name in self.sessions and not self.sessions[app_name]:
                self.sessions.pop(app_name, None)


_runner: Optional[Runner] = None
_runner_lock = threading.Lock()
_session_service: Optional[BoundedSessionService] = None


def get_session_service() -> BoundedSessionService:
    """Returns the singleton BoundedSessionService for active chat sessions."""
    global _session_service
    if _session_service is None:
        with _runner_lock:
            if _session_service is None:
                _session_service = BoundedSessionService(max_sessions=1000)
    return _session_service


def get_runner() -> Optional[Runner]:
    """Returns or initializes the thread-safe ADK Runner instance for the security agent."""
    global _runner
    if _runner is None:
        with _runner_lock:
            if _runner is None:
                settings = get_settings()
                agent = getattr(agent_mod, "_root_agent", None)
                if agent is None:
                    agent = agent_mod.create_security_agent(settings)
                    agent_mod._root_agent = agent
                if agent is None:
                    return None
                session_svc = get_session_service()
                _runner = Runner(
                    agent=agent,
                    app_name="mcp_security_agent",
                    session_service=session_svc,
                )
    return _runner


def _parse_confirmation_decision(message: str, explicit_confirmed: Optional[bool]) -> Dict[str, Any]:
    """Resolves an operator confirmation decision from explicit flag, JSON payload, or text."""
    if explicit_confirmed is not None:
        return {"confirmed": bool(explicit_confirmed)}
    cleaned = (message or "").strip()
    if cleaned.startswith("{"):
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict) and "confirmed" in parsed:
                return {"confirmed": bool(parsed["confirmed"])}
        except (ValueError, TypeError):
            pass
    affirmative = cleaned.lower() in (
        "y",
        "yes",
        "true",
        "1",
        "confirm",
        "confirmed",
        "approve",
        "approved",
    )
    return {"confirmed": affirmative}


def _find_open_confirmation_interrupt(session: Any) -> Tuple[Optional[str], Optional[str]]:
    """Finds the latest unanswered adk_request_confirmation interrupt in session.events."""
    events = getattr(session, "events", None) or []
    if not events:
        return None, None

    try:
        from google.adk.events._interrupts import index_open_interrupts

        open_ids = set(index_open_interrupts(events).keys())
    except Exception:
        answered = {
            fr.id
            for ev in events
            if getattr(ev, "author", None) == "user"
            for fr in ev.get_function_responses()
            if getattr(fr, "id", None)
        }
        open_ids = {
            fc_id
            for ev in events
            for fc_id in (getattr(ev, "long_running_tool_ids", None) or ())
            if fc_id not in answered
        }

    if not open_ids:
        return None, None

    for ev in reversed(events):
        for fc in ev.get_function_calls():
            fc_id = getattr(fc, "id", None)
            if fc_id in open_ids and getattr(fc, "name", None) == CONFIRMATION_FUNCTION_CALL_NAME:
                return fc_id, getattr(ev, "invocation_id", None)
    return None, None


async def sse_event_generator(
    message: str,
    session_id: str,
    user_id: Optional[str] = None,
    confirmed: Optional[bool] = None,
) -> AsyncGenerator[str, None]:
    """Streams real ADK agent execution events over Server-Sent Events (SSE)."""
    uid = user_id or discover_user_identity()
    session_svc = get_session_service()
    runner = get_runner()

    if runner is None:
        err_msg = json.dumps(
            {
                "text": "[Warning] Agent runner is unavailable in this environment.",
                "last_msg": False,
                "session_id": session_id,
            }
        )
        yield f"data: {err_msg}\n\n"
        done_msg = json.dumps(
            {"text": "Stream finished.", "last_msg": True, "session_id": session_id}
        )
        yield f"data: {done_msg}\n\n"
        return

    session = await session_svc.get_session(
        app_name="mcp_security_agent",
        user_id=uid,
        session_id=session_id,
    )
    if not session:
        session = await session_svc.create_session(
            app_name="mcp_security_agent",
            user_id=uid,
            session_id=session_id,
        )

    interrupt_id, interrupt_invocation_id = _find_open_confirmation_interrupt(session)
    run_kwargs: Dict[str, Any] = {
        "user_id": session.user_id,
        "session_id": session.id,
    }
    if interrupt_id:
        decision = _parse_confirmation_decision(message, confirmed)
        content = types.Content(
            role="user",
            parts=[
                types.Part(
                    function_response=types.FunctionResponse(
                        id=interrupt_id,
                        name=CONFIRMATION_FUNCTION_CALL_NAME,
                        response=decision,
                    )
                )
            ],
        )
        if interrupt_invocation_id:
            run_kwargs["invocation_id"] = interrupt_invocation_id
    else:
        content = types.Content(role="user", parts=[types.Part(text=message)])
    run_kwargs["new_message"] = content

    try:
        async for event in runner.run_async(**run_kwargs):
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if part.text:
                        data = json.dumps(
                            {
                                "text": part.text,
                                "last_msg": False,
                                "session_id": session_id,
                                "author": event.author or "SecurityOperationsAgent",
                                "event_type": "content",
                            }
                        )
                        yield f"data: {data}\n\n"
                    elif part.function_call:
                        if part.function_call.name == CONFIRMATION_FUNCTION_CALL_NAME:
                            fc_args = part.function_call.args or {}
                            orig_fc = (
                                fc_args.get("originalFunctionCall")
                                if isinstance(fc_args, dict)
                                else None
                            )
                            target_name = (
                                orig_fc.get("name", "destructive_tool")
                                if isinstance(orig_fc, dict)
                                else "destructive_tool"
                            )
                            target_args = (
                                orig_fc.get("args", {}) if isinstance(orig_fc, dict) else {}
                            )
                            confirm_info = json.dumps(
                                {
                                    "text": (
                                        f"[Confirmation Required] **Destructive tool `{target_name}` "
                                        "requires operator approval.**\n"
                                        f"```json\n{json.dumps(target_args, indent=2)}\n```\n"
                                        "Reply `yes` to confirm execution or `no` to cancel."
                                    ),
                                    "last_msg": False,
                                    "session_id": session_id,
                                    "event_type": "confirmation_request",
                                    "tool_name": target_name,
                                    "interrupt_id": getattr(part.function_call, "id", None),
                                }
                            )
                            yield f"data: {confirm_info}\n\n"
                        else:
                            call_info = json.dumps(
                                {
                                    "text": (
                                        f"[Tool] **Calling tool `{part.function_call.name}`**\n"
                                        f"```json\n{json.dumps(part.function_call.args, indent=2)}\n```"
                                    ),
                                    "last_msg": False,
                                    "session_id": session_id,
                                    "event_type": "tool_call",
                                }
                            )
                            yield f"data: {call_info}\n\n"
                    elif part.function_response:
                        if part.function_response.name == CONFIRMATION_FUNCTION_CALL_NAME:
                            continue
                        resp_info = json.dumps(
                            {
                                "text": f"[Tool] **Received tool response from `{part.function_response.name}`**",
                                "last_msg": False,
                                "session_id": session_id,
                                "event_type": "tool_response",
                            }
                        )
                        yield f"data: {resp_info}\n\n"
    except asyncio.CancelledError:
        logger.info("SSE client disconnected for session %s", session_id)
        raise
    except Exception as e:
        logger.error("Error during agent execution: %s", e, exc_info=True)
        err_data = json.dumps(
            {
                "text": f"[Error] **Error during investigation:** {str(e)}",
                "last_msg": False,
                "session_id": session_id,
                "event_type": "error",
            }
        )
        yield f"data: {err_data}\n\n"

    done_data = json.dumps(
        {
            "text": "Stream finished.",
            "last_msg": True,
            "session_id": session_id,
        }
    )
    yield f"data: {done_data}\n\n"


@router.get("/chat")
async def chat_sse_stream(
    message: str = Query(..., description="User prompt or security alert query"),
    session_id: Optional[str] = Query(None, description="Session ID for conversation history"),
    user_id: Optional[str] = Query(None, description="Active user ID"),
    confirmed: Optional[bool] = Query(
        None, description="Explicit confirmation decision for pending destructive tool"
    ),
):
    """Server-Sent Events (SSE) streaming endpoint for web UI clients."""
    sess_id = session_id or str(uuid.uuid4())
    return StreamingResponse(
        sse_event_generator(message, sess_id, user_id, confirmed=confirmed),
        media_type="text/event-stream",
    )


@router.post("/chat", response_model=ChatResponse)
async def chat_post(request: ChatRequest, http_request: Request):
    """REST and SSE chat endpoint for API clients, automated workflows, and web UI."""
    sess_id = request.session_id or str(uuid.uuid4())
    query_text = request.message or request.prompt or ""
    uid = request.user_id or discover_user_identity()

    accept_header = http_request.headers.get("accept", "")
    if "text/event-stream" in accept_header:
        return StreamingResponse(
            sse_event_generator(
                query_text, sess_id, uid, confirmed=request.confirmed
            ),
            media_type="text/event-stream",
        )

    # For non-streaming REST queries, collect text parts from runner
    accumulated = []
    async for chunk_str in sse_event_generator(
        query_text, sess_id, uid, confirmed=request.confirmed
    ):
        if chunk_str.startswith("data: "):
            try:
                data = json.loads(chunk_str[6:].strip())
                if not data.get("last_msg") and data.get("text"):
                    accumulated.append(data["text"])
            except Exception:
                pass

    response_text = (
        "\n\n".join(accumulated)
        if accumulated
        else f"No response generated for: {query_text}"
    )
    return JSONResponse(
        content={
            "response": response_text,
            "session_id": sess_id,
        }
    )
