"""Each rule must fire on its vulnerable fixture and stay silent on the fixed
one. These positive/negative pairs are the project's false-positive guardrail."""

from __future__ import annotations

from pathlib import Path

import pytest

from defiguard.rules.access_control import ThirdPartyFundSourceRule
from defiguard.rules.delegatecall import DelegatecallStorageRule
from defiguard.rules.external_calls import ExternalCallRule
from defiguard.rules.unbounded_loop import UnboundedLoopRule

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _ids(findings):
    return {f.rule_id for f in findings}


def _read(kind: str, name: str) -> str:
    return (FIXTURES / kind / name).read_text()


# ---- DG-AC-001: third-party token source without authorization ----

def test_access_control_fires_on_forced_stake():
    src = _read("vulnerable", "ForcedStake.sol")
    findings = ThirdPartyFundSourceRule().check("ForcedStake.sol", src)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "DG-AC-001"
    assert f.meta["param"] == "user"
    assert "transferFrom" in f.snippet


def test_access_control_silent_on_safe_stake():
    src = _read("fixed", "SafeStake.sol")
    findings = ThirdPartyFundSourceRule().check("SafeStake.sol", src)
    assert findings == []  # msg.sender-bound + authorized[] guarded variant


def test_access_control_zero_address_default_is_not_auth():
    # the `if (user == address(0)) user = msg.sender;` line must NOT be treated
    # as an authorization check -- this is the exact real-world trap.
    src = _read("vulnerable", "ForcedStake.sol")
    findings = ThirdPartyFundSourceRule().check("ForcedStake.sol", src)
    assert len(findings) == 1


# ---- DG-DC-001: delegatecall storage layout ----

def test_delegatecall_fires_on_proxy():
    src = _read("vulnerable", "DelegateProxy.sol")
    findings = DelegatecallStorageRule().check("DelegateProxy.sol", src)
    assert len(findings) == 1
    assert findings[0].rule_id == "DG-DC-001"


def test_delegatecall_silent_on_regular_call():
    src = _read("fixed", "NoDelegate.sol")
    findings = DelegatecallStorageRule().check("NoDelegate.sol", src)
    assert findings == []


# ---- DG-EXT-001: reentrancy / low-level call ----

def test_external_call_flags_state_write_after_call():
    src = _read("vulnerable", "ReentrantVault.sol")
    findings = ExternalCallRule().check("ReentrantVault.sol", src)
    titles = [f.title for f in findings]
    assert any("State write after an external call" in t for t in titles)


def test_external_call_no_reentrancy_flag_when_cei_and_guarded():
    src = _read("fixed", "SafeVault.sol")
    findings = ExternalCallRule().check("SafeVault.sol", src)
    # the MEDIUM reentrancy flag must be absent (effect precedes interaction,
    # and the function is nonReentrant). Low-level hygiene LOW may still appear.
    assert not any("State write after an external call" in f.title for f in findings)


# ---- DG-DOS-001: unbounded loop over a growable array ----

def test_unbounded_loop_fires_on_growable_array():
    src = _read("vulnerable", "UnboundedLoop.sol")
    findings = UnboundedLoopRule().check("UnboundedLoop.sol", src)
    assert len(findings) == 1
    assert findings[0].rule_id == "DG-DOS-001"
    assert findings[0].meta["array"] == "deposits"


def test_unbounded_loop_silent_on_paginated():
    src = _read("fixed", "BoundedLoop.sol")
    findings = UnboundedLoopRule().check("BoundedLoop.sol", src)
    assert findings == []  # loop runs to `end`, not to deposits[user].length


def test_unbounded_loop_silent_without_push():
    # a loop over `.length` of an array that is never pushed to is not flagged
    src = (
        "pragma solidity ^0.8.20;\n"
        "contract C {\n"
        "    address[] fixedSet;\n"
        "    function f() external view returns (uint256 n) {\n"
        "        for (uint256 i; i < fixedSet.length; i++) { n++; }\n"
        "    }\n"
        "}\n"
    )
    assert UnboundedLoopRule().check("C.sol", src) == []


# ---- comment/string stripping: no flag inside comments ----

def test_pattern_inside_comment_is_ignored():
    src = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract C {\n"
        "    // token.delegatecall(data) -- only a comment, must not flag\n"
        "    function f() external {}\n"
        "}\n"
    )
    assert DelegatecallStorageRule().check("C.sol", src) == []
