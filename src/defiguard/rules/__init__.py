"""Rule base class, a tiny Solidity source helper, and the rule registry.

The source helper is intentionally lightweight: v0.1 is line/regex based, not a
full AST. It removes comments and string literals before pattern matching so a
rule does not fire on a pattern that only appears inside a comment or a string.
A real AST backend (e.g. Slither) is a documented future step, not a v0.1 goal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..findings import Finding

_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING = re.compile(r"""(".*?(?<!\\)"|'.*?(?<!\\)')""", re.DOTALL)


def strip_noise(source: str) -> str:
    """Replace comments and string literals with same-length blanks.

    Keeping length/newlines identical means line and column numbers in the
    cleaned text still map 1:1 back to the original file.
    """

    def _blank(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))

    source = _BLOCK_COMMENT.sub(_blank, source)
    source = _LINE_COMMENT.sub(_blank, source)
    source = _STRING.sub(_blank, source)
    return source


@dataclass
class FunctionBlock:
    """A Solidity function: its header line, signature text, and body text."""

    name: str
    start_line: int  # 1-indexed line of the `function` keyword
    header: str      # text from `function` up to the opening `{`
    body: str        # text between the outer braces


_FUNC_HEADER = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)


def iter_functions(clean_source: str):
    """Yield FunctionBlock for each function with a body (naive brace matching).

    Works on comment/string-stripped source. Good enough for v0.1 heuristics;
    nested unusual constructs may be imperfect, which is why findings are review
    hints, not assertions.
    """
    for m in _FUNC_HEADER.finditer(clean_source):
        name = m.group(1)
        start_line = clean_source.count("\n", 0, m.start()) + 1
        # find the opening brace of the body (skip the parameter/returns list)
        depth = 0
        i = m.end() - 1  # at the '('
        header_end = None
        while i < len(clean_source):
            ch = clean_source[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "{" and depth == 0:
                header_end = i
                break
            elif ch == ";" and depth == 0:
                break  # interface/abstract declaration, no body
            i += 1
        if header_end is None:
            continue
        header = clean_source[m.start():header_end]
        # match the body braces
        depth = 0
        j = header_end
        body_start = header_end + 1
        while j < len(clean_source):
            ch = clean_source[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    yield FunctionBlock(name, start_line, header, clean_source[body_start:j])
                    break
            j += 1


def line_of(clean_source: str, index: int) -> int:
    return clean_source.count("\n", 0, index) + 1


class Rule:
    """Base class for all rules. Subclasses set the class attributes and
    implement :meth:`check`."""

    id: str = ""
    title: str = ""
    cwe: str | None = None

    def check(self, path_label: str, source: str) -> list[Finding]:
        raise NotImplementedError


# populated by defiguard.rules.load_rules()
def load_rules() -> list[Rule]:
    """Instantiate every bundled rule. Import here to avoid cycles."""
    from .access_control import ThirdPartyFundSourceRule
    from .delegatecall import DelegatecallStorageRule
    from .external_calls import ExternalCallRule
    from .unbounded_loop import UnboundedLoopRule

    return [
        ThirdPartyFundSourceRule(),
        DelegatecallStorageRule(),
        ExternalCallRule(),
        UnboundedLoopRule(),
    ]
