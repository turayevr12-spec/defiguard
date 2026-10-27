# Threat model

## What DeFiGuard is for

DeFiGuard helps **independent security researchers and smart-contract
developers** triage Solidity faster by surfacing a small set of high-signal DeFi
patterns with the context needed to confirm them. It is a *review accelerator*,
not an oracle.

## Who uses it

- **Auditors / bug-bounty hunters** pointing their attention at the riskiest
  lines in an unfamiliar codebase before deep manual review.
- **Developers** running it in CI to catch a known footgun before merge.

## What it assumes

- The input is Solidity source the user is authorized to review.
- The user confirms every finding manually and, where possible, with a test.
- Output is advisory; it never modifies the target.

## What it deliberately does NOT do

- It does not claim a finding is exploitable. Severity means "how much review
  this deserves".
- It does not perform cross-function / cross-contract data-flow analysis in
  v0.1 (line/regex heuristics only).
- It does not execute or deploy the contracts under review.
- It is not a substitute for a professional audit, Slither, or fuzzing.

## Trust boundaries & safety

- **No network, no execution of target code.** The scanner only reads files.
- **No secrets.** DeFiGuard reads source and emits findings; it stores nothing.
- Reproduction of a finding (via the Foundry scenarios) runs in a local EVM
  against synthetic actors — never against production systems or real user data.

## Abuse considerations

DeFiGuard surfaces patterns that *could* be abused. Users must only run it on
code they are permitted to analyze, and must follow the disclosure rules of any
bug-bounty program before acting on a finding. Responsible-disclosure guidance
is in [`../SECURITY.md`](../SECURITY.md).
