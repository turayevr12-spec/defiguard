"""Rule: a third-party `address` parameter used as a token source without any
authorization check tying it to msg.sender.

This is the exact class behind real-world "forced staking / forced deposit"
bugs: a function takes `address user` and does `token.safeTransferFrom(user, ...)`
while only `msg.sender` is the caller. If nothing requires `msg.sender == user`
(or a signed permit / operator delegation), ANYONE can move the tokens of ANY
address that left a standing ERC20 allowance to the contract -- forcing them
into a position they never consented to.

The rule is a heuristic: a function MAY legitimately pull from a third party if
it verifies an EIP-712 permit or an operator mapping. When such an auth check is
present the rule stays silent; otherwise it asks the auditor to confirm consent.
"""

from __future__ import annotations

import re

from ..findings import Finding, Severity
from . import Rule, iter_functions, line_of, strip_noise

_ADDR_PARAM = re.compile(r"\baddress\b(?:\s+(?:calldata|memory))?\s+([A-Za-z_]\w*)")
_EXTERNAL = re.compile(r"\b(external|public)\b")


class ThirdPartyFundSourceRule(Rule):
    id = "DG-AC-001"
    title = "Third-party address parameter used as token source without an authorization check"
    cwe = "CWE-284"

    def check(self, path_label: str, source: str) -> list[Finding]:
        clean = strip_noise(source)
        findings: list[Finding] = []

        for fn in iter_functions(clean):
            if not _EXTERNAL.search(fn.header):
                continue

            # candidate address parameters declared in the function signature
            params = [p for p in _ADDR_PARAM.findall(fn.header)]
            if not params:
                continue

            for param in params:
                # Is `param` used as the FROM address of a token pull?
                pull = re.search(
                    rf"\b(?:safeTransferFrom|transferFrom)\s*\(\s*{re.escape(param)}\b",
                    fn.body,
                )
                if not pull:
                    continue

                if self._has_auth_for(param, fn.body):
                    continue  # consent is verified -> not flagged

                # line of the offending pull, mapped back to the original file
                abs_index = clean.index(fn.body) + pull.start()
                line = line_of(clean, abs_index)
                snippet = source.splitlines()[line - 1].strip() if 0 < line <= len(source.splitlines()) else ""

                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=Severity.HIGH,
                        title=self.title,
                        file=path_label,
                        line=line,
                        snippet=snippet,
                        rationale=(
                            f"Function `{fn.name}` takes `address {param}` and pulls tokens with "
                            f"transferFrom({param}, ...), but nothing requires msg.sender == {param} "
                            f"(no equality guard, signed permit, or operator mapping was detected). "
                            f"Any caller can then move {param}'s tokens whenever {param} holds a "
                            f"standing allowance to this contract -- an allowance authorizes a spend "
                            f"cap, not consent to this specific action."
                        ),
                        recommendation=(
                            f"Confirm whether a caller other than {param} is meant to trigger this. "
                            f"If not, bind the action to msg.sender. If delegated/meta-tx use is a "
                            f"requirement, gate it behind an explicit EIP-712 permit (naming the exact "
                            f"action) or an authorized-operator mapping, not the ambient ERC20 allowance. "
                            f"Note: `if ({param} == address(0)) {param} = msg.sender;` is a default, "
                            f"not an authorization check."
                        ),
                        cwe=self.cwe,
                        meta={"function": fn.name, "param": param},
                    )
                )

        return findings

    @staticmethod
    def _has_auth_for(param: str, body: str) -> bool:
        p = re.escape(param)
        patterns = [
            rf"msg\.sender\s*==\s*{p}\b",
            rf"\b{p}\s*==\s*msg\.sender\b",
            rf"msg\.sender\s*!=\s*{p}\b",
            rf"\b{p}\s*!=\s*msg\.sender\b",
            # common delegation / permit shapes referencing the param
            rf"(authorized|operator|approvedBy|isApproved|delegat)\w*\s*\[\s*{p}\b",
            rf"permit\s*\([^;]*{p}\b",
            rf"_requireAuth\w*\s*\([^;]*{p}\b",
        ]
        return any(re.search(pat, body) for pat in patterns)
