"""Rule: delegatecall sites require manual storage-layout review.

`delegatecall` runs the target's bytecode in the CALLER's storage context. If
the target contract's storage layout is not identical to the caller's (same
state variables, same order, same packing), a write the target thinks lands in
slot N silently corrupts whatever the caller keeps in slot N. The safe pattern
is for the target ("sidecar") to inherit the exact same storage base as the
caller and declare no extra storage of its own (immutables are fine -- they live
in bytecode, not storage).

delegatecall is not a bug by itself (proxies, diamonds and EIP-170 size
work-arounds all use it legitimately). This rule only points the auditor at each
site and tells them what to verify.
"""

from __future__ import annotations

import re

from ..findings import Finding, Severity
from . import Rule, line_of, strip_noise

_DELEGATECALL = re.compile(r"\.\s*delegatecall\s*(?:\{[^}]*\})?\s*\(")


class DelegatecallStorageRule(Rule):
    id = "DG-DC-001"
    title = "delegatecall site: verify storage-layout compatibility with the target"
    cwe = "CWE-668"

    def check(self, path_label: str, source: str) -> list[Finding]:
        clean = strip_noise(source)
        lines = source.splitlines()
        findings: list[Finding] = []

        for m in _DELEGATECALL.finditer(clean):
            line = line_of(clean, m.start())
            snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            findings.append(
                Finding(
                    rule_id=self.id,
                    severity=Severity.REVIEW,
                    title=self.title,
                    file=path_label,
                    line=line,
                    snippet=snippet,
                    rationale=(
                        "delegatecall executes the target's code against THIS contract's storage. "
                        "If the target's storage layout differs from this contract's by even one "
                        "slot, a target write silently corrupts this contract's state."
                    ),
                    recommendation=(
                        "Diff the storage layouts (e.g. `forge inspect <Caller> storageLayout` vs "
                        "`forge inspect <Target> storageLayout`) and confirm slot/offset/type match, "
                        "ignoring compiler AST ids. The target should inherit the same storage base "
                        "and declare only `immutable`/`constant` extras. Also confirm the target "
                        "rejects direct calls if it must only run under delegatecall."
                    ),
                    cwe=self.cwe,
                )
            )

        return findings
