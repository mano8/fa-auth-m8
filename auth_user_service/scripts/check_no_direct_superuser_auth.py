#!/usr/bin/env python
"""AST guard: ban direct ``is_superuser`` authorization checks.

The canonical role/flag invariant means ``is_superuser`` is *derived evidence*
of ``role == SUPERADMIN``, never an independent permission switch. An
authorization decision must go through the shared SDK predicate
(``has_superuser_privileges(role, is_superuser)`` and friends), which requires
both fields to agree — a lone ``is_superuser`` flag must never grant access.

This checker fails CI when it finds a boolean *decision* that reads
``<something>.is_superuser`` directly (``if user.is_superuser``,
``... and current_user.is_superuser``, ``not user.is_superuser`` in a guard,
etc.). It deliberately allows:

* passing the flag as an argument to a canonical SDK predicate
  (``has_superuser_privileges``/``privilege_claims_are_consistent``/
  ``validate_privilege_claims``/``find_inconsistent_privilege_claims_error``),
* plain serialization / ORM-column use (``select(User).where(User.is_superuser)``,
  ``token payload=...is_superuser``), which is not a Python boolean decision.

Run: ``python -m auth_user_service.scripts.check_no_direct_superuser_auth``
(optionally pass one or more paths to scan; defaults to ``auth_user_service``).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Iterable, List, NamedTuple

FLAG_ATTR = "is_superuser"

# Calls whose arguments may legitimately read the raw flag: the shared SDK
# predicates that combine it with the role into a dual-evidence decision.
_ALLOWED_PREDICATES = frozenset(
    {
        "has_superuser_privileges",
        "privilege_claims_are_consistent",
        "validate_privilege_claims",
        "find_inconsistent_privilege_claims_error",
    }
)


class Violation(NamedTuple):
    """A single banned direct-flag authorization decision."""

    file: str
    line: int
    col: int
    snippet: str


def _called_name(call: ast.Call) -> str:
    """Return the simple callee name of a Call node (``a.b.c`` -> ``c``)."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


class _DecisionVisitor(ast.NodeVisitor):
    """Flag ``.is_superuser`` reads that sit in a boolean decision position."""

    def __init__(self, filename: str, source: str) -> None:
        self.filename = filename
        self._lines = source.splitlines()
        self.violations: List[Violation] = []
        # Set of Attribute nodes that are arguments to an allowed predicate call.
        self._allowed_nodes: set[int] = set()
        # Node ids already reported, so overlapping visitors (e.g. an ``if not
        # x.is_superuser`` seen by both visit_If and visit_UnaryOp) count once.
        self._reported: set[int] = set()

    # -- helpers -----------------------------------------------------------
    def _is_flag_read(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == FLAG_ATTR
            and isinstance(node.ctx, ast.Load)
        )

    def _record_allowed_args(self, call: ast.Call) -> None:
        if _called_name(call) not in _ALLOWED_PREDICATES:
            return
        for arg in list(call.args) + [kw.value for kw in call.keywords]:
            if self._is_flag_read(arg):
                self._allowed_nodes.add(id(arg))

    def _report(self, node: ast.Attribute) -> None:
        if id(node) in self._allowed_nodes or id(node) in self._reported:
            return
        self._reported.add(id(node))
        line = node.lineno
        snippet = self._lines[line - 1].strip() if 0 < line <= len(self._lines) else ""
        self.violations.append(Violation(self.filename, line, node.col_offset, snippet))

    def _scan_boolean(self, expr: ast.AST) -> None:
        """Report any direct flag read reachable inside a boolean expression."""
        for sub in ast.walk(expr):
            if self._is_flag_read(sub):
                self._report(sub)  # type: ignore[arg-type]

    # -- record predicate-arg exemptions before deciding -------------------
    def visit_Call(self, node: ast.Call) -> None:
        self._record_allowed_args(node)
        self.generic_visit(node)

    # -- boolean decision positions ---------------------------------------
    def visit_If(self, node: ast.If) -> None:
        self._scan_boolean(node.test)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self._scan_boolean(node.test)
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self._scan_boolean(node.test)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self._scan_boolean(node.test)
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        for value in node.values:
            if self._is_flag_read(value):
                self._report(value)  # type: ignore[arg-type]
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, ast.Not) and self._is_flag_read(node.operand):
            self._report(node.operand)  # type: ignore[arg-type]
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        for cond in node.ifs:
            self._scan_boolean(cond)
        self.generic_visit(node)


def find_violations(source: str, filename: str) -> List[Violation]:
    """Return every banned direct-flag authorization decision in ``source``."""
    tree = ast.parse(source, filename=filename)
    # Pre-pass: collect predicate-arg exemptions across the whole module so the
    # decision visitors can honour them regardless of visit order.
    visitor = _DecisionVisitor(filename, source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            visitor._record_allowed_args(node)
    visitor.visit(tree)
    return visitor.violations


def iter_python_files(paths: Iterable[Path]) -> Iterable[Path]:
    """Yield ``.py`` files under the given paths (files or directories)."""
    for path in paths:
        if path.is_dir():
            for sub in sorted(path.rglob("*.py")):
                if "__pycache__" in sub.parts:
                    continue
                yield sub
        elif path.suffix == ".py":
            yield path


def scan_paths(paths: Iterable[Path]) -> List[Violation]:
    """Scan the given paths and return all violations."""
    violations: List[Violation] = []
    for file in iter_python_files(paths):
        source = file.read_text(encoding="utf-8")
        violations.extend(find_violations(source, str(file)))
    return violations


def main(argv: List[str] | None = None) -> int:
    """CLI entry point: exit non-zero when any violation is found."""
    args = argv if argv is not None else sys.argv[1:]
    targets = [Path(a) for a in args] or [Path("auth_user_service")]
    violations = scan_paths(targets)
    if violations:
        print("Direct is_superuser authorization checks are banned:")
        for v in violations:
            print(f"  {v.file}:{v.line}:{v.col}: {v.snippet}")
        print(
            "\nUse the SDK dual-evidence predicate "
            "has_superuser_privileges(role, is_superuser) instead — a lone "
            "is_superuser flag must never grant access."
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
