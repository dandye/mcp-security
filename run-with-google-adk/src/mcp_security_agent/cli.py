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
"""Command-line interface for the MCP Security Agent."""

import asyncio
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Tuple
import typer
from rich.console import Console
from mcp_security_agent import __version__
from mcp_security_agent.config import AgentSettings

CONFIRMATION_FUNCTION_CALL_NAME = "adk_request_confirmation"

app = typer.Typer(
    help="Autonomous Security Operations Center (SOC) Agent powered by Google ADK v2 & MCP",
    no_args_is_help=True,
)
console = Console()


def _format_server_status(enabled: Optional[bool], transport: str) -> str:
    if enabled:
        return f"[green]Enabled ({transport})[/green]"
    return "[dim]Disabled (disabled)[/dim]"


@app.command()
def info():
    """Display agent version and loaded configuration."""
    settings = AgentSettings()
    transports = settings.get_server_transports()
    resolved_project = settings.resolved_project_id or "Not set"
    console.print(f"[bold green]MCP Security Agent v{__version__}[/bold green]")
    console.print(f"Model: [cyan]{settings.google_model}[/cyan]")
    console.print(f"Location: [cyan]{settings.google_cloud_location}[/cyan]")
    console.print(f"Project (project_id): [cyan]{resolved_project}[/cyan]")
    console.print(
        f"ADC: [cyan]{settings.google_application_credentials or 'Default (~/.config/gcloud/...)'}[/cyan]"
    )
    console.print(
        "Tool Name Prefixing (tool_name_prefix_enabled): "
        f"{'[green]Enabled[/green]' if settings.mcp_tool_name_prefix_enabled else '[dim]Disabled[/dim]'} "
        f"({str(settings.mcp_tool_name_prefix_enabled).lower()})"
    )
    console.print(
        "MCP Resources (use_mcp_resources): "
        f"{'[green]Enabled[/green]' if settings.mcp_use_resources else '[dim]Disabled[/dim]'} "
        f"({str(settings.mcp_use_resources).lower()})"
    )
    console.print(
        f"Destructive Tool Confirmation: {'[yellow]Enabled[/yellow]' if settings.confirm_destructive_tools else '[dim]Disabled[/dim]'}"
    )
    console.print(
        f"Elicitation Policy (elicitation_policy): [cyan]{settings.elicitation_policy}[/cyan]"
    )
    console.print(
        f"SecOps SIEM MCP: {_format_server_status(settings.load_secops_mcp, transports['secops'])}"
    )
    console.print(
        f"SCC MCP: {_format_server_status(settings.load_scc_mcp, transports['scc'])}"
    )
    console.print(
        f"GTI MCP: {_format_server_status(settings.load_gti_mcp, transports['gti'])}"
    )
    console.print(
        f"SecOps SOAR MCP: {_format_server_status(settings.load_secops_soar_mcp, transports['soar'])}"
    )


def _apply_cli_overrides(
    secops: Optional[bool] = None,
    scc: Optional[bool] = None,
    gti: Optional[bool] = None,
    soar: Optional[bool] = None,
    vertex: Optional[bool] = None,
    model: Optional[str] = None,
    project: Optional[str] = None,
    location: Optional[str] = None,
    customer_id: Optional[str] = None,
    confirm_destructive: Optional[bool] = None,
    prefix_tools: Optional[bool] = None,
) -> None:
    """Applies CLI flag overrides to environment variables before settings initialization."""
    if secops is not None:
        os.environ["LOAD_SECOPS_MCP"] = "Y" if secops else "N"
    if scc is not None:
        os.environ["LOAD_SCC_MCP"] = "Y" if scc else "N"
    if gti is not None:
        os.environ["LOAD_GTI_MCP"] = "Y" if gti else "N"
    if soar is not None:
        os.environ["LOAD_SECOPS_SOAR_MCP"] = "Y" if soar else "N"
    if vertex is not None:
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "TRUE" if vertex else "FALSE"
    if model:
        os.environ["GOOGLE_MODEL"] = model
    if location:
        os.environ["GOOGLE_CLOUD_LOCATION"] = location
    if project:
        os.environ["GOOGLE_CLOUD_PROJECT"] = project
        if "CHRONICLE_PROJECT_ID" not in os.environ:
            os.environ["CHRONICLE_PROJECT_ID"] = project
    if customer_id:
        os.environ["CHRONICLE_CUSTOMER_ID"] = customer_id
    if confirm_destructive is not None:
        os.environ["ADK_CONFIRM_DESTRUCTIVE_TOOLS"] = "Y" if confirm_destructive else "N"
    if prefix_tools is not None:
        os.environ["MCP_TOOL_NAME_PREFIX_ENABLED"] = "Y" if prefix_tools else "N"


def _display_active_toolsets(settings: AgentSettings) -> None:
    enabled_tools = []
    if settings.load_secops_mcp:
        enabled_tools.append("SecOps SIEM")
    if settings.load_scc_mcp:
        enabled_tools.append("SCC")
    if settings.load_gti_mcp:
        enabled_tools.append("GTI")
    if settings.load_secops_soar_mcp:
        enabled_tools.append("SecOps SOAR")

    if not enabled_tools:
        console.print(
            "[bold yellow]Warning:[/bold yellow] No MCP tools are currently enabled.\n"
            "Enable tools using environment variables (e.g. [cyan]LOAD_SECOPS_MCP=Y[/cyan]), "
            "CLI flags ([cyan]--secops[/cyan], [cyan]--scc[/cyan]), or [cyan].env[/cyan].\n"
        )
    else:
        console.print(f"[bold green]Active MCP Toolsets:[/bold green] {', '.join(enabled_tools)}\n")


def _parse_cli_confirmation_decision(raw_text: str) -> Dict[str, Any]:
    cleaned = (raw_text or "").strip()
    if cleaned.startswith("{"):
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict) and "confirmed" in parsed:
                return {"confirmed": bool(parsed["confirmed"])}
        except (ValueError, TypeError):
            pass
    approved = cleaned.lower() in (
        "y",
        "yes",
        "true",
        "1",
        "confirm",
        "confirmed",
        "approve",
        "approved",
    )
    return {"confirmed": approved}


def _find_open_cli_confirmation_interrupt(
    session: Any,
) -> Tuple[Optional[str], Optional[str]]:
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


async def _prompt_cli_confirmation_if_interactive(tool_name: str) -> Optional[bool]:
    """Prompts on interactive TTY or unread Click buffer; returns None if non-interactive."""
    stdin = getattr(sys, "stdin", None)
    if stdin is None:
        return None

    is_tty = bool(getattr(stdin, "isatty", lambda: False)())
    has_buffered_input = False
    if not is_tty and hasattr(stdin, "seekable") and stdin.seekable():
        try:
            pos = stdin.tell()
            peek = stdin.read(1)
            stdin.seek(pos)
            has_buffered_input = bool(peek)
        except Exception:
            has_buffered_input = False

    if not is_tty and not has_buffered_input:
        return None

    prompt_msg = f"[Confirm] Approve execution of {tool_name}? [y/N]: "
    typer.echo(prompt_msg, nl=False)
    try:
        if is_tty:
            answer = await asyncio.to_thread(stdin.readline)
        else:
            answer = stdin.readline()
    except (EOFError, KeyboardInterrupt):
        return False

    if answer == "":
        return False
    return bool(_parse_cli_confirmation_decision(answer)["confirmed"])


def _create_cli_runner_bundle(agent: Any, src_dir: Path) -> Tuple[Any, Any, str, str]:
    """Creates the ADK Runner and local-storage session service for single-turn CLI execution."""
    from google.adk.auth.credential_service.in_memory_credential_service import (
        InMemoryCredentialService,
    )
    from google.adk.cli.utils.service_factory import (
        create_artifact_service_from_options,
        create_memory_service_from_options,
        create_session_service_from_options,
    )
    from google.adk.runners import Runner

    app_name = "mcp_security_agent"
    user_id = "test_user"
    session_service = create_session_service_from_options(
        base_dir=src_dir,
        use_local_storage=True,
    )
    artifact_service = create_artifact_service_from_options(
        base_dir=src_dir,
        use_local_storage=True,
    )
    memory_service = create_memory_service_from_options(base_dir=src_dir)
    credential_service = InMemoryCredentialService()
    runner = Runner(
        agent=agent,
        app_name=app_name,
        session_service=session_service,
        artifact_service=artifact_service,
        memory_service=memory_service,
        credential_service=credential_service,
    )
    return runner, session_service, app_name, user_id


async def run_single_turn_query(
    *,
    agent: Any,
    src_dir: Path,
    query: str,
    session_id: Optional[str] = None,
) -> int:
    """Executes a single-turn query with plain-ASCII confirmation prompting and --session-id resume."""
    from google.adk.utils.context_utils import Aclosing
    from google.genai import types

    runner, session_service, app_name, user_id = _create_cli_runner_bundle(agent, src_dir)
    try:
        if session_id:
            session = await session_service.get_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
            if session is None:
                session = await session_service.create_session(
                    app_name=app_name, user_id=user_id, session_id=session_id
                )
        else:
            session = await session_service.create_session(
                app_name=app_name, user_id=user_id
            )

        typer.echo(f"Session ID: {session.id}", err=True)

        open_id, open_invocation_id = _find_open_cli_confirmation_interrupt(session)
        if open_id:
            decision = _parse_cli_confirmation_decision(query)
            next_message = types.Content(
                role="user",
                parts=[
                    types.Part(
                        function_response=types.FunctionResponse(
                            id=open_id,
                            name=CONFIRMATION_FUNCTION_CALL_NAME,
                            response=decision,
                        )
                    )
                ],
            )
            next_invocation_id: Optional[str] = open_invocation_id
        else:
            next_message = types.Content(role="user", parts=[types.Part(text=query)])
            next_invocation_id = None

        while True:
            pending_confirm_call = None
            pending_invocation_id = None
            has_unhandled_interrupt = False

            run_kwargs: Dict[str, Any] = {
                "user_id": session.user_id,
                "session_id": session.id,
                "new_message": next_message,
            }
            if next_invocation_id:
                run_kwargs["invocation_id"] = next_invocation_id

            async with Aclosing(runner.run_async(**run_kwargs)) as agen:
                async for event in agen:
                    author = getattr(event, "author", None) or "SecurityOperationsAgent"
                    if getattr(event, "content", None) and getattr(
                        event.content, "parts", None
                    ):
                        text_parts = [
                            p.text
                            for p in event.content.parts
                            if getattr(p, "text", None)
                        ]
                        if text_parts:
                            typer.echo(f"[{author}]: {''.join(text_parts)}")
                        for part in event.content.parts:
                            fc = getattr(part, "function_call", None)
                            if (
                                fc
                                and getattr(fc, "name", None)
                                == CONFIRMATION_FUNCTION_CALL_NAME
                            ):
                                pending_confirm_call = fc
                                pending_invocation_id = getattr(
                                    event, "invocation_id", None
                                )
                    if (
                        getattr(event, "long_running_tool_ids", None)
                        and pending_confirm_call is None
                    ):
                        has_unhandled_interrupt = True

            if pending_confirm_call is not None:
                fc_args = getattr(pending_confirm_call, "args", None) or {}
                orig_fc = (
                    fc_args.get("originalFunctionCall")
                    if isinstance(fc_args, dict)
                    else None
                )
                tool_name = (
                    orig_fc.get("name", "destructive_tool")
                    if isinstance(orig_fc, dict)
                    else "destructive_tool"
                )
                call_id = getattr(pending_confirm_call, "id", None)
                approved = await _prompt_cli_confirmation_if_interactive(tool_name)
                if approved is None:
                    typer.echo(
                        f"[Paused] Destructive tool '{tool_name}' requires operator confirmation.\n"
                        f"To resume, run:\n"
                        f"  mcp-security-agent chat --session-id {session.id} yes\n"
                        f"or pass 'no' to reject execution.",
                        err=True,
                    )
                    return 2

                next_message = types.Content(
                    role="user",
                    parts=[
                        types.Part(
                            function_response=types.FunctionResponse(
                                id=call_id,
                                name=CONFIRMATION_FUNCTION_CALL_NAME,
                                response={"confirmed": approved},
                            )
                        )
                    ],
                )
                next_invocation_id = pending_invocation_id
                refreshed = await session_service.get_session(
                    app_name=app_name, user_id=session.user_id, session_id=session.id
                )
                if refreshed is not None:
                    session = refreshed
                continue

            if has_unhandled_interrupt:
                typer.echo(
                    f"[Paused] Workflow is waiting for operator input. "
                    f"Resume with: mcp-security-agent chat --session-id {session.id} <response>",
                    err=True,
                )
                return 2

            return 0
    finally:
        close_fn = getattr(runner, "close", None)
        if callable(close_fn):
            maybe_coro = close_fn()
            if asyncio.iscoroutine(maybe_coro):
                await maybe_coro


@app.command()
def chat(
    query: Optional[str] = typer.Argument(
        None, help="Optional single-turn investigation query to execute"
    ),
    session_id: Optional[str] = typer.Option(
        None,
        "--session-id",
        "--session_id",
        help=(
            "Session ID to create or resume (persisting session state and "
            "pending confirmation interrupts across single-turn chat "
            "invocations within the same process or persistent session store)"
        ),
    ),
    secops: Optional[bool] = typer.Option(
        None, "--secops/--no-secops", help="Enable or disable SecOps SIEM MCP"
    ),
    scc: Optional[bool] = typer.Option(
        None, "--scc/--no-scc", help="Enable or disable SCC MCP"
    ),
    gti: Optional[bool] = typer.Option(
        None, "--gti/--no-gti", help="Enable or disable GTI MCP"
    ),
    soar: Optional[bool] = typer.Option(
        None, "--soar/--no-soar", help="Enable or disable SecOps SOAR MCP"
    ),
    vertex: Optional[bool] = typer.Option(
        None, "--vertex/--no-vertex", help="Use Vertex AI for LLM requests"
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Gemini model to use (e.g. gemini-3.1-pro-preview or gemini-3-flash-preview)",
    ),
    project: Optional[str] = typer.Option(None, "--project", help="Google Cloud project ID"),
    location: Optional[str] = typer.Option(
        None, "--location", help="Vertex AI location (defaults to global)"
    ),
    customer_id: Optional[str] = typer.Option(
        None, "--customer-id", help="Google SecOps customer ID (UUID)"
    ),
    confirm_destructive: Optional[bool] = typer.Option(
        None,
        "--confirm-destructive/--no-confirm-destructive",
        help="Require operator confirmation before running destructive MCP tools",
    ),
    prefix_tools: Optional[bool] = typer.Option(
        None,
        "--prefix-tools/--no-prefix-tools",
        help="Prefix MCP tool names by server (secops_, gti_, soar_, scc_)",
    ),
):
    """Start an interactive terminal chat session with the SOC agent powered by ADK v2."""
    _apply_cli_overrides(
        secops=secops,
        scc=scc,
        gti=gti,
        soar=soar,
        vertex=vertex,
        model=model,
        project=project,
        location=location,
        customer_id=customer_id,
        confirm_destructive=confirm_destructive,
        prefix_tools=prefix_tools,
    )

    settings = AgentSettings()
    _display_active_toolsets(settings)

    import mcp_security_agent.agent as agent_mod

    agent = agent_mod.create_security_agent(settings)
    agent_mod._root_agent = agent
    agent_mod.root_agent = agent
    if "mcp_security_agent" in sys.modules:
        sys.modules["mcp_security_agent"]._root_agent = agent  # type: ignore[attr-defined]
        sys.modules["mcp_security_agent"].root_agent = agent  # type: ignore[attr-defined]

    pkg_root = Path(__file__).resolve().parents[2]
    src_dir = pkg_root / "src"

    if query:
        try:
            exit_code = asyncio.run(
                run_single_turn_query(
                    agent=agent,
                    src_dir=src_dir,
                    query=query,
                    session_id=session_id,
                )
            )
        except (ImportError, ModuleNotFoundError):
            console.print("[red]Google ADK CLI runner is unavailable in this environment.[/red]")
            raise typer.Exit(code=1)
        raise typer.Exit(code=exit_code or 0)
    else:
        try:
            from google.adk.cli.cli import run_cli
        except (ImportError, ModuleNotFoundError):
            console.print("[red]Google ADK CLI runner is unavailable in this environment.[/red]")
            raise typer.Exit(code=1)
        asyncio.run(
            run_cli(
                agent_parent_dir=str(src_dir),
                agent_folder_name="mcp_security_agent",
                save_session=False,
                session_id=session_id,
                use_local_storage=True,
            )
        )


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host address to bind"),
    port: Optional[int] = typer.Option(
        None, help="Port to listen on (defaults to $PORT or 8080)"
    ),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload for development"),
    secops: Optional[bool] = typer.Option(
        None, "--secops/--no-secops", help="Enable or disable SecOps SIEM MCP"
    ),
    scc: Optional[bool] = typer.Option(
        None, "--scc/--no-scc", help="Enable or disable SCC MCP"
    ),
    gti: Optional[bool] = typer.Option(
        None, "--gti/--no-gti", help="Enable or disable GTI MCP"
    ),
    soar: Optional[bool] = typer.Option(
        None, "--soar/--no-soar", help="Enable or disable SecOps SOAR MCP"
    ),
    vertex: Optional[bool] = typer.Option(
        None, "--vertex/--no-vertex", help="Use Vertex AI for LLM requests"
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Gemini model to use (e.g. gemini-3.1-pro-preview or gemini-3-flash-preview)",
    ),
    project: Optional[str] = typer.Option(None, "--project", help="Google Cloud project ID"),
    location: Optional[str] = typer.Option(
        None, "--location", help="Vertex AI location (defaults to global)"
    ),
    customer_id: Optional[str] = typer.Option(
        None, "--customer-id", help="Google SecOps customer ID (UUID)"
    ),
    confirm_destructive: Optional[bool] = typer.Option(
        None,
        "--confirm-destructive/--no-confirm-destructive",
        help="Require operator confirmation before running destructive MCP tools",
    ),
    prefix_tools: Optional[bool] = typer.Option(
        None,
        "--prefix-tools/--no-prefix-tools",
        help="Prefix MCP tool names by server (secops_, gti_, soar_, scc_)",
    ),
):
    """Run the FastAPI web server and Cloud Run REST API."""
    _apply_cli_overrides(
        secops=secops,
        scc=scc,
        gti=gti,
        soar=soar,
        vertex=vertex,
        model=model,
        project=project,
        location=location,
        customer_id=customer_id,
        confirm_destructive=confirm_destructive,
        prefix_tools=prefix_tools,
    )

    settings = AgentSettings()
    _display_active_toolsets(settings)

    import mcp_security_agent.agent as agent_mod

    agent = agent_mod.create_security_agent(settings)
    agent_mod._root_agent = agent
    agent_mod.root_agent = agent
    if "mcp_security_agent" in sys.modules:
        sys.modules["mcp_security_agent"]._root_agent = agent  # type: ignore[attr-defined]
        sys.modules["mcp_security_agent"].root_agent = agent  # type: ignore[attr-defined]

    bind_port = port if port is not None else int(os.environ.get("PORT", 8080))
    console.print(f"[bold green]Starting MCP Security Agent server on {host}:{bind_port}[/bold green]")

    import uvicorn

    if reload:
        uvicorn.run(
            "mcp_security_agent.server.app:create_app",
            factory=True,
            host=host,
            port=bind_port,
            reload=True,
        )
    else:
        from mcp_security_agent.server.app import create_app

        app_instance = create_app()
        uvicorn.run(app_instance, host=host, port=bind_port)


if __name__ == "__main__":
    app()
