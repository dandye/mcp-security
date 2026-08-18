#!/usr/bin/env python3
"""Add MCP 2.x ``ctx`` parameters to every decorated tool function.

For each ``@server.tool()`` / ``@mcp.tool()`` function under the target tree this
script appends a ``ctx: Optional[Context] = None`` parameter and ensures the
module imports both ``Context`` (from ``mcp.types``) and ``Optional`` (from
``typing``).

Edits are performed as offset-exact splices on the original source text. The
module is never round-tripped through ``ast.unparse``, so comments, docstrings,
blank lines and formatting outside the spliced regions stay byte-identical.

Stdlib only -- ``libcst`` is not available in this environment.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

CONTEXT_MODULE = "mcp.types"
CONTEXT_IMPORT = f"from {CONTEXT_MODULE} import Context"
TYPING_IMPORT = "from typing import Optional"
CTX_PARAMETER = "ctx: Optional[Context] = None"

#: Decorator receiver names that identify an MCP tool registration.
DEFAULT_DECORATOR_BASES = frozenset({"server", "mcp"})

EXIT_OK = 0
EXIT_FAILURES = 1
EXIT_USAGE = 2


class TransformError(Exception):
    """A file could not be transformed safely and must be left untouched."""


@dataclass(frozen=True)
class Splice:
    """A single text insertion at an absolute character offset."""

    offset: int
    text: str


@dataclass
class FileOutcome:
    """What happened to one file."""

    path: Path
    tools_found: int = 0
    tools_already_ctx: int = 0
    tools_modified: int = 0
    added_context_import: bool = False
    added_typing_import: bool = False
    new_source: str | None = None
    error: str | None = None

    @property
    def changed(self) -> bool:
        return self.new_source is not None


@dataclass
class RunSummary:
    """Aggregate results across every scanned file."""

    outcomes: list[FileOutcome] = field(default_factory=list)

    @property
    def tool_files(self) -> list[FileOutcome]:
        return [o for o in self.outcomes if o.tools_found or o.error]

    @property
    def failures(self) -> list[FileOutcome]:
        return [o for o in self.outcomes if o.error]

    @property
    def changed(self) -> list[FileOutcome]:
        return [o for o in self.outcomes if o.changed]

    def total(self, attribute: str) -> int:
        return sum(getattr(o, attribute) for o in self.outcomes)


# --------------------------------------------------------------------------- #
# Offset helpers
#
# ``ast`` reports ``col_offset`` in UTF-8 *bytes*, while we splice into a ``str``
# indexed by characters. These helpers do the conversion once per file.
# --------------------------------------------------------------------------- #


def line_start_offsets(source: str) -> list[int]:
    """Return the character offset at which each 1-indexed line begins."""
    offsets = [0, 0]  # index 0 unused; line numbers are 1-based
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _char_column(line: str, byte_column: int) -> int:
    """Convert a UTF-8 byte column into a character column within ``line``."""
    if byte_column <= 0:
        return 0
    return len(line.encode("utf-8")[:byte_column].decode("utf-8", errors="strict"))


class OffsetMap:
    """Translates ``ast`` (line, byte-column) positions into character offsets."""

    def __init__(self, source: str) -> None:
        self._lines = source.splitlines(keepends=True)
        self._starts = line_start_offsets(source)

    def offset(self, lineno: int, col_offset: int) -> int:
        line = self._lines[lineno - 1] if lineno - 1 < len(self._lines) else ""
        return self._starts[lineno] + _char_column(line, col_offset)

    def node_start(self, node: ast.AST) -> int:
        return self.offset(node.lineno, node.col_offset)

    def node_end(self, node: ast.AST) -> int:
        if node.end_lineno is None or node.end_col_offset is None:
            raise TransformError(f"node {type(node).__name__} has no end position")
        return self.offset(node.end_lineno, node.end_col_offset)


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def is_tool_decorator(node: ast.expr, bases: frozenset[str]) -> bool:
    """True when ``node`` is ``@<base>.tool`` or ``@<base>.tool(...)``."""
    target = node.func if isinstance(node, ast.Call) else node
    return (
        isinstance(target, ast.Attribute)
        and target.attr == "tool"
        and isinstance(target.value, ast.Name)
        and target.value.id in bases
    )


def find_tool_functions(
    tree: ast.Module, bases: frozenset[str]
) -> list[ast.AsyncFunctionDef | ast.FunctionDef]:
    """Find every tool-decorated function, at any nesting depth, in source order."""
    found = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
        and any(is_tool_decorator(d, bases) for d in node.decorator_list)
    ]
    found.sort(key=lambda n: (n.lineno, n.col_offset))
    return found


def parameter_names(node: ast.AsyncFunctionDef | ast.FunctionDef) -> list[str]:
    args = node.args
    named = args.posonlyargs + args.args + args.kwonlyargs
    return [a.arg for a in named]


def has_ctx_parameter(node: ast.AsyncFunctionDef | ast.FunctionDef) -> bool:
    return "ctx" in parameter_names(node)


# --------------------------------------------------------------------------- #
# Signature splicing
# --------------------------------------------------------------------------- #


def _last_parameter_end(
    node: ast.AsyncFunctionDef | ast.FunctionDef, offsets: OffsetMap
) -> int | None:
    """Character offset just past the final parameter, defaults included.

    Returns ``None`` for a zero-parameter signature.
    """
    args = node.args
    pieces: list[ast.AST] = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    pieces += [d for d in args.defaults if d is not None]
    pieces += [d for d in args.kw_defaults if d is not None]
    if args.vararg is not None:
        pieces.append(args.vararg)
    if args.kwarg is not None:
        pieces.append(args.kwarg)
    if not pieces:
        return None
    return max(offsets.node_end(p) for p in pieces)


def _find_signature_open_paren(source: str, node: ast.AST, offsets: OffsetMap) -> int:
    """Offset of the ``(`` that opens the parameter list."""
    cursor = offsets.node_start(node)
    paren = source.find("(", cursor)
    if paren == -1:
        raise TransformError("could not locate '(' opening the parameter list")
    return paren


def _find_signature_close_paren(source: str, start: int) -> int:
    """Offset of the ``)`` closing the parameter list, scanning from ``start``.

    ``start`` must already be past the final parameter, so the only tokens that
    can appear before the closing paren are whitespace, a trailing comma, and
    comments.
    """
    index = start
    while index < len(source):
        char = source[index]
        if char == ")":
            return index
        if char == "#":
            newline = source.find("\n", index)
            index = len(source) if newline == -1 else newline + 1
            continue
        if char in " \t\r\n,\\":
            index += 1
            continue
        raise TransformError(
            f"unexpected token {char!r} between last parameter and ')'"
        )
    raise TransformError("unterminated parameter list")


def _line_indent(source: str, offset: int) -> str:
    """Leading whitespace of the line containing ``offset``."""
    line_start = source.rfind("\n", 0, offset) + 1
    line = source[line_start:offset]
    return line[: len(line) - len(line.lstrip())]


def build_signature_splice(
    source: str,
    node: ast.AsyncFunctionDef | ast.FunctionDef,
    offsets: OffsetMap,
) -> Splice:
    """Build the insertion that appends ``ctx`` to ``node``'s parameter list."""
    last_end = _last_parameter_end(node, offsets)

    if last_end is None:
        open_paren = _find_signature_open_paren(source, node, offsets)
        close_paren = _find_signature_close_paren(source, open_paren + 1)
        gap = source[open_paren + 1 : close_paren]
        if "#" in gap:
            raise TransformError("comment inside empty parameter list")
        if "\n" in gap:
            indent = _line_indent(source, offsets.node_start(node)) + "    "
            return Splice(open_paren + 1, f"\n{indent}{CTX_PARAMETER},\n")
        return Splice(open_paren + 1, CTX_PARAMETER)

    close_paren = _find_signature_close_paren(source, last_end)
    gap = source[last_end:close_paren]
    if "#" in gap:
        raise TransformError("comment between last parameter and ')'")

    if "\n" in gap:
        indent = _line_indent(source, last_end)
        return Splice(last_end, f",\n{indent}{CTX_PARAMETER}")

    return Splice(last_end, f", {CTX_PARAMETER}")


# --------------------------------------------------------------------------- #
# Import handling
# --------------------------------------------------------------------------- #


def _top_level_imports(tree: ast.Module) -> list[ast.Import | ast.ImportFrom]:
    return [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]


def context_binding(tree: ast.Module) -> tuple[bool, str | None]:
    """Report whether bare ``Context`` is bound, and from which module.

    Returns ``(is_bound, source_module)``. ``source_module`` is ``None`` when
    ``Context`` is not bound at all.
    """
    for node in _top_level_imports(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if (alias.asname or alias.name) == "Context":
                    return True, node.module or ""
        else:
            for alias in node.names:
                if alias.asname == "Context":
                    return True, alias.name
    return False, None


def typing_optional_import(tree: ast.Module) -> ast.ImportFrom | None:
    """Return the ``from typing import ...`` node, if the module has one."""
    for node in _top_level_imports(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "typing":
            return node
    return None


def optional_is_bound(tree: ast.Module) -> bool:
    node = typing_optional_import(tree)
    if node is None:
        return False
    return any((a.asname or a.name) in ("Optional", "*") for a in node.names)


def extend_typing_import_splice(
    source: str, node: ast.ImportFrom, offsets: OffsetMap
) -> Splice:
    """Add ``Optional`` to an existing ``from typing import ...`` statement.

    ``ast.alias`` carries no position information before Python 3.10, so the
    insertion point is found by scanning the statement's own text span back from
    its end. Both the flat form (``from typing import Any, Dict``) and the
    parenthesised form -- with or without a trailing comma -- are handled.
    """
    start = offsets.node_start(node)
    end = offsets.node_end(node)
    statement = source[start:end]

    if not statement.rstrip().endswith(")"):
        return Splice(end, ", Optional")

    cursor = start + statement.rindex(")")
    while cursor > start and source[cursor - 1] in " \t\r\n":
        cursor -= 1

    if source[cursor - 1] == ",":
        indent = _line_indent(source, cursor - 1)
        return Splice(cursor, f"\n{indent}Optional,")
    return Splice(cursor, ", Optional")


def import_anchor_offset(tree: ast.Module, offsets: OffsetMap) -> int:
    """Offset at which new import lines should be inserted.

    New imports go immediately after the module's final top-level import. That
    placement is deterministic and, unlike anchoring on the first third-party
    import, it never splits an existing import group in two -- which matters
    when the edit lands in several hundred files at once.

    Falls back to the top of the module body when there are no imports at all.
    """
    imports = _top_level_imports(tree)
    if imports:
        return offsets.node_end(imports[-1]) + 1  # +1 steps past the newline
    if tree.body:
        return offsets.offset(tree.body[0].lineno, 0)
    return 0


def build_import_splices(
    source: str,
    tree: ast.Module,
    offsets: OffsetMap,
    *,
    need_context: bool,
    need_optional: bool,
) -> tuple[list[Splice], bool, bool]:
    """Build import insertions. Returns ``(splices, added_context, added_typing)``."""
    splices: list[Splice] = []
    added_context = False
    added_typing = False

    typing_node = typing_optional_import(tree)
    if need_optional and typing_node is not None:
        splices.append(
            extend_typing_import_splice(source, typing_node, offsets)
        )
        added_typing = True
        need_optional = False

    if need_context or need_optional:
        anchor = import_anchor_offset(tree, offsets)
        lines: list[str] = []
        if need_optional:
            lines.append(TYPING_IMPORT)
            added_typing = True
        if need_context:
            lines.append(CONTEXT_IMPORT)
            added_context = True
        splices.append(Splice(anchor, "".join(f"{line}\n" for line in lines)))

    return splices, added_context, added_typing


# --------------------------------------------------------------------------- #
# Whole-file transform (pure: text in, text out)
# --------------------------------------------------------------------------- #


def apply_splices(source: str, splices: Sequence[Splice]) -> str:
    """Apply insertions in descending offset order so earlier offsets stay valid."""
    result = source
    for splice in sorted(splices, key=lambda s: s.offset, reverse=True):
        result = result[: splice.offset] + splice.text + result[splice.offset :]
    return result


def transform_source(
    source: str,
    path: Path,
    *,
    bases: frozenset[str] = DEFAULT_DECORATOR_BASES,
    on_context_conflict: str = "report",
) -> FileOutcome:
    """Transform one module's text. Raises nothing -- errors land in the outcome."""
    outcome = FileOutcome(path=path)

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        outcome.error = f"does not parse: {exc}"
        return outcome

    functions = find_tool_functions(tree, bases)
    outcome.tools_found = len(functions)
    if not functions:
        return outcome

    pending = []
    for node in functions:
        if has_ctx_parameter(node):
            outcome.tools_already_ctx += 1
        else:
            pending.append(node)

    if not pending:
        return outcome

    bound, module = context_binding(tree)
    if bound and module != CONTEXT_MODULE:
        message = f"'Context' already imported from {module!r}, not {CONTEXT_MODULE!r}"
        if on_context_conflict == "report":
            outcome.error = message
            return outcome
        if on_context_conflict == "skip-file":
            outcome.error = f"skipped: {message}"
            return outcome
        # "rewrite": fall through and treat the existing binding as usable.

    offsets = OffsetMap(source)
    try:
        splices = [build_signature_splice(source, node, offsets) for node in pending]
        import_splices, added_ctx, added_typing = build_import_splices(
            source,
            tree,
            offsets,
            need_context=not bound,
            need_optional=not optional_is_bound(tree),
        )
    except TransformError as exc:
        outcome.error = str(exc)
        return outcome

    new_source = apply_splices(source, [*splices, *import_splices])

    try:
        new_tree = ast.parse(new_source)
    except SyntaxError as exc:
        outcome.error = f"result does not parse -- file left untouched: {exc}"
        return outcome

    still_missing = [
        n.name
        for n in find_tool_functions(new_tree, bases)
        if not has_ctx_parameter(n)
    ]
    if still_missing:
        outcome.error = f"postcondition failed, still missing ctx: {still_missing}"
        return outcome

    outcome.tools_modified = len(pending)
    outcome.added_context_import = added_ctx
    outcome.added_typing_import = added_typing
    outcome.new_source = new_source
    return outcome


# --------------------------------------------------------------------------- #
# File I/O edge
# --------------------------------------------------------------------------- #


def read_source(path: Path) -> tuple[str, str]:
    """Read ``path`` and return ``(lf_normalised_text, newline)``.

    Raises ``TransformError`` on mixed line endings, which this splicer cannot
    round-trip losslessly.
    """
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    crlf = text.count("\r\n")
    lf_only = text.count("\n") - crlf
    if crlf and lf_only:
        raise TransformError("mixed CRLF/LF line endings")
    newline = "\r\n" if crlf else "\n"
    return (text.replace("\r\n", "\n"), newline)


def write_source(path: Path, text: str, newline: str) -> None:
    payload = text.replace("\n", newline) if newline != "\n" else text
    path.write_bytes(payload.encode("utf-8"))


def iter_python_files(root: Path) -> Iterator[Path]:
    yield from sorted(root.rglob("*.py"))


def process_file(
    path: Path, *, bases: frozenset[str], on_context_conflict: str
) -> tuple[FileOutcome, str, str]:
    """Read, transform, and return ``(outcome, original_text, newline)``."""
    try:
        source, newline = read_source(path)
    except (TransformError, UnicodeDecodeError, OSError) as exc:
        return FileOutcome(path=path, error=f"unreadable: {exc}"), "", "\n"

    outcome = transform_source(
        source, path, bases=bases, on_context_conflict=on_context_conflict
    )
    return outcome, source, newline


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def render_diff(path: Path, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def report(summary: RunSummary, *, applied: bool, show_diff: bool) -> None:
    mode = "APPLIED" if applied else "DRY RUN"
    print(f"\n=== migrate_mcp2_ctx: {mode} ===")
    print(f"files containing tools : {len(summary.tool_files)}")
    print(f"tool functions found   : {summary.total('tools_found')}")
    print(f"already had ctx        : {summary.total('tools_already_ctx')}")
    print(f"ctx parameters added   : {summary.total('tools_modified')}")
    print(f"files modified         : {len(summary.changed)}")
    print(f"Context imports added  : {sum(o.added_context_import for o in summary.outcomes)}")
    print(f"typing imports touched : {sum(o.added_typing_import for o in summary.outcomes)}")

    if summary.failures:
        print(f"\nfailures ({len(summary.failures)}):")
        for outcome in summary.failures:
            print(f"  {outcome.path}: {outcome.error}")

    if show_diff:
        print()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Append 'ctx: Optional[Context] = None' to every @server.tool()/"
            "@mcp.tool() function and add the imports it needs."
        )
    )
    parser.add_argument(
        "--path",
        default="server",
        help="directory tree to migrate (default: server)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write changes to disk (default is a dry run)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="print a unified diff for every modified file",
    )
    parser.add_argument(
        "--decorator-base",
        action="append",
        dest="decorator_bases",
        default=None,
        metavar="NAME",
        help=(
            "decorator receiver to treat as a tool registry, repeatable "
            f"(default: {', '.join(sorted(DEFAULT_DECORATOR_BASES))})"
        ),
    )
    parser.add_argument(
        "--on-context-conflict",
        choices=("report", "rewrite", "skip-file"),
        default="report",
        help=(
            "what to do when 'Context' is already imported from a module other "
            "than mcp.types: 'report' fails the file (default), 'rewrite' reuses "
            "the existing binding, 'skip-file' passes over it quietly"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        print(f"error: --path {root} is not a directory", file=sys.stderr)
        return EXIT_USAGE

    bases = frozenset(args.decorator_bases or DEFAULT_DECORATOR_BASES)
    summary = RunSummary()

    for path in iter_python_files(root):
        outcome, before, newline = process_file(
            path, bases=bases, on_context_conflict=args.on_context_conflict
        )
        summary.outcomes.append(outcome)

        if not outcome.changed:
            continue

        assert outcome.new_source is not None
        if args.diff:
            print(render_diff(path, before, outcome.new_source), end="")
        if args.apply:
            try:
                write_source(path, outcome.new_source, newline)
            except OSError as exc:
                outcome.new_source = None
                outcome.error = f"write failed: {exc}"

    report(summary, applied=args.apply, show_diff=args.diff)
    return EXIT_FAILURES if summary.failures else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
