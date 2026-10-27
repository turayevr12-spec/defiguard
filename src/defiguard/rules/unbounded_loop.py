"""Rule: a loop bounded by the length of an array that can grow without limit.

If a function iterates `for (...; i < arr.length; ...)` and `arr` (a storage
array, possibly keyed by a mapping) has a `.push(...)` reachable by users, the
array grows unbounded. Eventually the loop's gas cost exceeds the block gas
limit and the function reverts forever -- a denial-of-service that can lock the
funds or state it guards (the idOS node-staking `withdrawUnstaked` /
`withdrawableReward` class).

Heuristic: an array that is both pushed to AND iterated by `.length` in a loop
condition. A loop over a fixed-size or externally-bounded array, or one that is
paginated (iterating to a caller-supplied bound instead of `.length`), is not
flagged.
"""

from __future__ import annotations

import re

from ..findings import Finding, Severity
from . import Rule, line_of, strip_noise

# captures the base name even when indexed by a mapping key: `name[...].push(`
_PUSH = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\.\s*push\s*\(")
# a for-loop whose header references `name[...]?.length`. The `[^{}]` (which
# allows the `;` separators of a for-header but stops at the body's `{`) keeps
# the match inside the loop header.
_FOR_LEN = re.compile(r"\bfor\s*\([^{}]*?\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\.\s*length\b")


class UnboundedLoopRule(Rule):
    id = "DG-DOS-001"
    title = "Loop bounded by a growable array's length (unbounded iteration / gas-DoS candidate)"
    cwe = "CWE-834"

    def check(self, path_label: str, source: str) -> list[Finding]:
        clean = strip_noise(source)
        growable = set(_PUSH.findall(clean))
        if not growable:
            return []

        lines = source.splitlines()
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()

        for m in _FOR_LEN.finditer(clean):
            name = m.group(1)
            if name not in growable:
                continue
            line = line_of(clean, m.start())
            if (name, line) in seen:
                continue
            seen.add((name, line))
            snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            findings.append(
                Finding(
                    rule_id=self.id,
                    severity=Severity.MEDIUM,
                    title=self.title,
                    file=path_label,
                    line=line,
                    snippet=snippet,
                    rationale=(
                        f"This loop runs until `{name}.length`, and `{name}` is appended to with "
                        f"`.push(...)` elsewhere, so it can grow without bound. Once iterating it "
                        f"costs more than the block gas limit, every call on this path reverts "
                        f"permanently -- a denial-of-service on whatever the function unlocks."
                    ),
                    recommendation=(
                        f"Bound the work per call: paginate (iterate to a caller-supplied count, not "
                        f"`{name}.length`) and persist progress, or cap how large `{name}` can get, or "
                        f"redesign so a single user's growth cannot brick their own (or others') funds. "
                        f"Confirm whether `{name}` is attacker- or self-growable and whether the stuck "
                        f"state is recoverable."
                    ),
                    cwe=self.cwe,
                    meta={"array": name},
                )
            )

        return findings
