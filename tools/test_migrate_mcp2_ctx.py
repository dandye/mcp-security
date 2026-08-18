#!/usr/bin/env python3
"""Tests for the MCP 2.x ctx migration.

Run with::

    python3 -m unittest discover -s tools -p 'test_*.py' -v
"""

from __future__ import annotations

import ast
import textwrap
import unittest
from pathlib import Path

from migrate_mcp2_ctx import (
    CTX_PARAMETER,
    DEFAULT_DECORATOR_BASES,
    context_binding,
    find_tool_functions,
    has_ctx_parameter,
    optional_is_bound,
    transform_source,
)

FAKE = Path("fake.py")

LICENSE = textwrap.dedent(
    """\
    # Copyright 2025 Google LLC
    #
    # Licensed under the Apache License, Version 2.0 (the "License");
    # you may not use this file except in compliance with the License.
    """
)


def migrate(source: str, **kwargs: object) -> str:
    """Transform ``source`` and assert it succeeded, returning the new text."""
    outcome = transform_source(source, FAKE, **kwargs)  # type: ignore[arg-type]
    if outcome.error:
        raise AssertionError(f"unexpected transform error: {outcome.error}")
    return outcome.new_source if outcome.new_source is not None else source


def ctx_annotation(source: str, func_name: str) -> str:
    """Return the rendered ``ctx`` parameter of ``func_name`` in ``source``."""
    tree = ast.parse(source)
    for node in find_tool_functions(tree, DEFAULT_DECORATOR_BASES):
        if node.name != func_name:
            continue
        for arg, default in zip(
            reversed(node.args.args), reversed(node.args.defaults)
        ):
            if arg.arg == "ctx":
                return f"{arg.arg}: {ast.unparse(arg.annotation)} = {ast.unparse(default)}"
        raise AssertionError(f"{func_name} has no ctx with a default")
    raise AssertionError(f"no tool function named {func_name}")


class MultiLineSignatureTest(unittest.TestCase):
    def test_appends_ctx_and_imports(self) -> None:
        source = LICENSE + textwrap.dedent(
            '''\
            """Module docstring."""

            from typing import Any, Dict, Optional

            from secops_mcp.server import get_chronicle_client, server


            @server.tool()
            async def search_udm(
                query: str,
                hours_back: int = 24,
                region: str = None,
            ) -> Dict[str, Any]:
                """Docstring."""
                return {}
            '''
        )
        result = migrate(source)

        self.assertIn("from mcp.types import Context\n", result)
        self.assertIn("    region: str = None,\n    ctx: Optional[Context] = None,\n", result)
        self.assertEqual(ctx_annotation(result, "search_udm"), CTX_PARAMETER)
        # The import anchors on the first non-typing "from" import.
        self.assertIn(
            "from mcp.types import Context\nfrom secops_mcp.server import", result
        )
        # Docstring and license survive untouched.
        self.assertTrue(result.startswith(LICENSE))
        self.assertIn('"""Module docstring."""', result)

    def test_signature_without_trailing_comma(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Optional
            from mcp.types import Context
            from x import server


            @server.tool()
            async def f(
                a: str,
                b: int = 1
            ) -> None:
                return None
            """
        )
        result = migrate(source)
        self.assertIn("    b: int = 1,\n    ctx: Optional[Context] = None\n", result)
        self.assertEqual(ctx_annotation(result, "f"), CTX_PARAMETER)


class SingleLineAnnotatedSignatureTest(unittest.TestCase):
    """The secops-soar marketplace shape: one enormous line, nested in a function."""

    SOURCE = textwrap.dedent(
        '''\
        from mcp.server.fastmcp import FastMCP
        from typing import Optional, List, Annotated
        from pydantic import Field


        def register_tools(mcp: FastMCP):
            # Registers all tools for the integration.

            @mcp.tool()
            async def vertex_ai_execute_prompt(case_id: Annotated[str, Field(..., description="The ID (see \\"docs\\", https://x.example/a?b=1) of the case, e.g. 1,2.")], scope: Annotated[str, Field(default="All entities", description="Defines the scope.")]) -> dict:
                """Execute a prompt."""
                return {}
        '''
    )

    def test_splices_inline_and_survives_nested_parens_and_quotes(self) -> None:
        result = migrate(self.SOURCE)
        self.assertIn(f'description="Defines the scope.")], {CTX_PARAMETER}) -> dict:', result)
        self.assertEqual(ctx_annotation(result, "vertex_ai_execute_prompt"), CTX_PARAMETER)

    def test_finds_function_nested_inside_register_tools(self) -> None:
        tree = ast.parse(self.SOURCE)
        names = [n.name for n in find_tool_functions(tree, DEFAULT_DECORATOR_BASES)]
        self.assertEqual(names, ["vertex_ai_execute_prompt"])

    def test_descriptions_are_byte_identical_apart_from_the_splice(self) -> None:
        result = migrate(self.SOURCE)
        self.assertEqual(
            result.replace(f", {CTX_PARAMETER}", "", 1),
            self.SOURCE.replace("from mcp.server.fastmcp import FastMCP\n", "from mcp.types import Context\nfrom mcp.server.fastmcp import FastMCP\n", 1),
        )


class IdempotencyTest(unittest.TestCase):
    def test_second_pass_is_a_no_op(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Optional
            from x import server


            @server.tool()
            async def f(a: str) -> None:
                return None
            """
        )
        once = migrate(source)
        outcome = transform_source(once, FAKE)
        self.assertIsNone(outcome.error)
        self.assertIsNone(outcome.new_source, "second pass must not modify the file")
        self.assertEqual(outcome.tools_already_ctx, 1)
        self.assertEqual(outcome.tools_modified, 0)

    def test_existing_ctx_without_default_is_left_alone(self) -> None:
        source = textwrap.dedent(
            """\
            from mcp.types import Context
            from x import server


            @server.tool()
            async def get_file_report(hash: str, ctx: Context) -> dict:
                return {}
            """
        )
        outcome = transform_source(source, FAKE)
        self.assertIsNone(outcome.error)
        self.assertIsNone(outcome.new_source)
        self.assertEqual(outcome.tools_already_ctx, 1)


class ImportHandlingTest(unittest.TestCase):
    def test_does_not_duplicate_an_existing_mcp_types_import(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Optional
            from mcp.types import Context
            from x import server


            @server.tool()
            async def f(a: str) -> None:
                return None
            """
        )
        result = migrate(source)
        self.assertEqual(result.count("from mcp.types import Context"), 1)

    def test_context_from_a_different_module_is_reported_as_a_conflict(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Optional
            from mcp.server.fastmcp import Context
            from x import server


            @server.tool()
            async def f(a: str) -> None:
                return None
            """
        )
        outcome = transform_source(source, FAKE, on_context_conflict="report")
        self.assertIsNotNone(outcome.error)
        self.assertIn("mcp.server.fastmcp", str(outcome.error))
        self.assertIsNone(outcome.new_source)

    def test_conflict_rewrite_reuses_the_existing_binding(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Optional
            from mcp.server.fastmcp import Context
            from x import server


            @server.tool()
            async def f(a: str) -> None:
                return None
            """
        )
        result = migrate(source, on_context_conflict="rewrite")
        self.assertNotIn("from mcp.types import Context", result)
        self.assertEqual(ctx_annotation(result, "f"), CTX_PARAMETER)

    def test_conflict_skip_file_leaves_the_file_untouched(self) -> None:
        source = textwrap.dedent(
            """\
            from mcp.server.fastmcp import Context
            from x import server


            @server.tool()
            async def f(a: str) -> None:
                return None
            """
        )
        outcome = transform_source(source, FAKE, on_context_conflict="skip-file")
        self.assertIsNone(outcome.new_source)
        self.assertIn("skipped", str(outcome.error))

    def test_adds_typing_import_when_absent(self) -> None:
        source = textwrap.dedent(
            """\
            import typing

            from mcp.server.fastmcp import Context
            from x import server


            @server.tool()
            async def f(a: str) -> None:
                return None
            """
        )
        result = migrate(source, on_context_conflict="rewrite")
        self.assertIn("from typing import Optional", result)
        self.assertTrue(optional_is_bound(ast.parse(result)))

    def test_extends_an_existing_typing_import_in_place(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Any, Dict
            from mcp.types import Context
            from x import server


            @server.tool()
            async def f(a: str) -> None:
                return None
            """
        )
        result = migrate(source)
        self.assertIn("from typing import Any, Dict, Optional", result)
        self.assertEqual(result.count("from typing import"), 1)

    def test_extends_a_parenthesised_typing_import(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import (
                Any,
                Dict,
            )
            from mcp.types import Context
            from x import server


            @server.tool()
            async def f(a: str) -> None:
                return None
            """
        )
        result = migrate(source)
        self.assertTrue(optional_is_bound(ast.parse(result)))
        self.assertEqual(result.count("from typing import"), 1)

    def test_star_import_from_typing_counts_as_bound(self) -> None:
        self.assertTrue(optional_is_bound(ast.parse("from typing import *\n")))

    def test_context_binding_reports_the_source_module(self) -> None:
        self.assertEqual(
            context_binding(ast.parse("from mcp.types import Context\n")),
            (True, "mcp.types"),
        )
        self.assertEqual(context_binding(ast.parse("import os\n")), (False, None))

    def test_import_is_inserted_after_the_license_header(self) -> None:
        source = LICENSE + textwrap.dedent(
            """\
            from typing import Optional

            from x import server


            @server.tool()
            async def f(a: str) -> None:
                return None
            """
        )
        result = migrate(source)
        header_end = len(LICENSE)
        self.assertEqual(result[:header_end], LICENSE)
        self.assertGreater(result.index("from mcp.types import Context"), header_end)


class EdgeCaseTest(unittest.TestCase):
    def test_zero_argument_function(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Optional
            from mcp.types import Context
            from x import server


            @server.tool()
            async def ping() -> str:
                return "pong"
            """
        )
        result = migrate(source)
        self.assertIn(f"async def ping({CTX_PARAMETER}) -> str:", result)
        self.assertEqual(ctx_annotation(result, "ping"), CTX_PARAMETER)

    def test_non_tool_decorator_is_ignored(self) -> None:
        source = textwrap.dedent(
            """\
            from x import app


            @app.route("/health")
            async def health() -> str:
                return "ok"
            """
        )
        outcome = transform_source(source, FAKE)
        self.assertEqual(outcome.tools_found, 0)
        self.assertIsNone(outcome.new_source)

    def test_tool_decorator_on_an_unknown_receiver_is_ignored(self) -> None:
        source = textwrap.dedent(
            """\
            from x import other


            @other.tool()
            async def f(a: str) -> None:
                return None
            """
        )
        outcome = transform_source(source, FAKE)
        self.assertEqual(outcome.tools_found, 0)

    def test_bare_tool_decorator_without_call_is_matched(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Optional
            from mcp.types import Context
            from x import mcp


            @mcp.tool
            async def f(a: str) -> None:
                return None
            """
        )
        outcome = transform_source(source, FAKE)
        self.assertEqual(outcome.tools_found, 1)
        self.assertEqual(outcome.tools_modified, 1)

    def test_multiple_tools_in_one_file_all_get_ctx(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Optional
            from x import server


            @server.tool()
            async def a(x: str) -> None:
                return None


            @server.tool()
            async def b(
                y: int = 3,
            ) -> None:
                return None


            @server.tool()
            async def c(z: str, w: int = 1) -> None:
                return None
            """
        )
        result = migrate(source)
        for name in ("a", "b", "c"):
            self.assertEqual(ctx_annotation(result, name), CTX_PARAMETER, name)

    def test_comment_before_closing_paren_is_refused_not_corrupted(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Optional
            from mcp.types import Context
            from x import server


            @server.tool()
            async def f(
                a: str,  # trailing note
            ) -> None:
                return None
            """
        )
        outcome = transform_source(source, FAKE)
        self.assertIsNone(outcome.new_source)
        self.assertIn("comment", str(outcome.error))

    def test_unparseable_source_is_reported_not_raised(self) -> None:
        outcome = transform_source("def (:\n", FAKE)
        self.assertIn("does not parse", str(outcome.error))
        self.assertIsNone(outcome.new_source)

    def test_decorator_with_arguments_is_matched(self) -> None:
        source = textwrap.dedent(
            """\
            from typing import Optional
            from mcp.types import Context
            from x import server


            @server.tool(name="explicit", description="thing")
            async def f(a: str) -> None:
                return None
            """
        )
        outcome = transform_source(source, FAKE)
        self.assertEqual(outcome.tools_modified, 1)

    def test_non_ascii_source_offsets_are_handled(self) -> None:
        source = textwrap.dedent(
            '''\
            from typing import Optional
            from mcp.types import Context
            from x import server


            @server.tool()
            async def f(a: str = "café — naïve ☃") -> None:
                """Ünicode docstring ✓."""
                return None
            '''
        )
        result = migrate(source)
        self.assertIn('"café — naïve ☃", ctx: Optional[Context] = None) -> None:', result)
        self.assertIn('"""Ünicode docstring ✓."""', result)

    def test_has_ctx_parameter_detects_keyword_only_ctx(self) -> None:
        tree = ast.parse("async def f(a, *, ctx=None): pass\n")
        node = tree.body[0]
        self.assertTrue(has_ctx_parameter(node))  # type: ignore[arg-type]


class NewlinePreservationTest(unittest.TestCase):
    def test_crlf_file_round_trips_as_crlf(self) -> None:
        import tempfile

        from migrate_mcp2_ctx import process_file, write_source

        body = (
            "from typing import Optional\n"
            "from mcp.types import Context\n"
            "from x import server\n"
            "\n"
            "\n"
            "@server.tool()\n"
            "async def f(a: str) -> None:\n"
            "    return None\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "crlf.py"
            path.write_bytes(body.replace("\n", "\r\n").encode("utf-8"))

            outcome, _before, newline = process_file(
                path, bases=DEFAULT_DECORATOR_BASES, on_context_conflict="report"
            )
            self.assertEqual(newline, "\r\n")
            self.assertIsNotNone(outcome.new_source)
            assert outcome.new_source is not None

            write_source(path, outcome.new_source, newline)
            written = path.read_bytes()
            self.assertNotIn(b"\n", written.replace(b"\r\n", b""))
            self.assertIn(b"ctx: Optional[Context] = None", written)

    def test_mixed_line_endings_are_refused(self) -> None:
        import tempfile

        from migrate_mcp2_ctx import process_file

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.py"
            path.write_bytes(b"import os\r\nimport sys\n")
            outcome, _before, _newline = process_file(
                path, bases=DEFAULT_DECORATOR_BASES, on_context_conflict="report"
            )
            self.assertIn("mixed", str(outcome.error))


if __name__ == "__main__":
    unittest.main()
