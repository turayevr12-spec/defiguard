"""Rule: external calls -- reentrancy (checks-effects-interactions) and
low-level call hygiene.

Two heuristics:

1. A state write that happens AFTER an external call, in a function that is not
   marked `nonReentrant`, is a classic checks-effects-interactions violation and
   a reentrancy candidate (the external callee can re-enter before the state is
   updated).

2. Raw low-level calls (`.call`, `.send`, `.transfer`) deserve a look for
   unchecked return values and hard-coded gas stipends.

Both are heuristics -- a reentrancy guard elsewhere, a trusted callee, or a pull
-payment design can make them safe. The rule points; the auditor confirms.
"""

from __future__ import annotations

import re

from ..findings import Finding, Severity
from . import Rule, iter_functions, line_of, strip_noise

# low-level / value-transfer interaction tokens
_LOWLEVEL = re.compile(r"\.\s*(call|send|transfer)\s*(?:\{[^}]*\})?\s*\(")
# any external-interaction token we treat as "the interaction point"
_INTERACTION = re.compile(
    r"\.\s*(?:call|send|transfer)\s*(?:\{[^}]*\})?\s*\("
    r"|\b(?:safeTransfer|safeTransferFrom|transferFrom|transfer)\s*\("
)
_NONREENTRANT = re.compile(r"\bnonReentrant\b")

# locally-declared identifiers we should NOT treat as state writes
_LOCAL_DECL = re.compile(
    r"\b(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping|[A-Z]\w*)\b"
    r"(?:\s+(?:memory|storage|calldata))?\s+([A-Za-z_]\w*)\s*(?:=|;|,|\))"
)
_ASSIGN = re.compile(r"(?<![=!<>])\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?(?:\+\+|--|[-+*/]?=)(?![=])")


class ExternalCallRule(Rule):
    id = "DG-EXT-001"
    title = "external call: review reentrancy (checks-effects-interactions) and return handling"
    cwe = "CWE-841"

    def check(self, path_label: str, source: str) -> list[Finding]:
        clean = strip_noise(source)
        lines = source.splitlines()
        findings: list[Finding] = []

        for fn in iter_functions(clean):
            body = fn.body
            body_offset = clean.index(body)

            interactions = list(_INTERACTION.finditer(body))
            if not interactions:
                continue
            first_call = interactions[0].start()
            guarded = bool(_NONREENTRANT.search(fn.header))

            # --- heuristic 1: state write after an external call, no guard ---
            if not guarded:
                locals_declared = set(_LOCAL_DECL.findall(body))
                for am in _ASSIGN.finditer(body):
                    if am.start() <= first_call:
                        continue  # effect happened before the interaction: fine
                    name = am.group(1)
                    if name in locals_declared or name in {"return", "emit"}:
                        continue
                    line = line_of(clean, body_offset + am.start())
                    snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=Severity.MEDIUM,
                            title="State write after an external call without nonReentrant (reentrancy candidate)",
                            file=path_label,
                            line=line,
                            snippet=snippet,
                            rationale=(
                                f"In `{fn.name}`, `{name}` is written AFTER an external call and the "
                                f"function is not marked nonReentrant. The callee may re-enter before "
                                f"`{name}` is updated (checks-effects-interactions violation)."
                            ),
                            recommendation=(
                                "Move all state updates BEFORE the external call, or add a reentrancy "
                                "guard, or use a pull-payment pattern. Confirm the callee cannot "
                                "re-enter any function that relies on the stale state."
                            ),
                            cwe=self.cwe,
                            meta={"function": fn.name, "written": name},
                        )
                    )
                    break  # one flag per function is enough signal

            # --- heuristic 2: raw low-level call hygiene ---
            for lm in _LOWLEVEL.finditer(body):
                line = line_of(clean, body_offset + lm.start())
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=Severity.LOW,
                        title="Low-level call: check return value and gas assumptions",
                        file=path_label,
                        line=line,
                        snippet=snippet,
                        rationale=(
                            f"`.{lm.group(1)}(...)` is a low-level interaction. `.call`/`.send` return "
                            f"a success bool that must be checked; `.transfer`/`.send` forward a fixed "
                            f"2300 gas stipend that can break legitimate receivers."
                        ),
                        recommendation=(
                            "Check the returned success flag and handle failure explicitly. Prefer a "
                            "checked `.call{value: ...}(\"\")` with require over `.transfer`/`.send`. "
                            "Pair with reentrancy protection if state depends on the call."
                        ),
                        cwe="CWE-252",
                        meta={"function": fn.name, "kind": lm.group(1)},
                    )
                )

        return findings
