# DeFiGuard

**An open-source Solidity / DeFi security testing toolkit.**

DeFiGuard flags *suspicious* code patterns in Solidity and points an auditor at
the exact lines to review — then backs each pattern class with runnable Foundry
scenarios (a vulnerable contract, a fixed one, and a test that tells them apart).

> ⚠️ **A flag is not a vulnerability.** Every finding is a heuristic that a human
> — and, where possible, a test — must confirm. DeFiGuard's value is in curated
> DeFi threat scenarios, testable invariants, and honest false-positive
> accounting, **not** in replacing [Slither](https://github.com/crytic/slither)
> or [Foundry](https://getfoundry.sh/).

---

## Why another tool?

Generic analyzers are great at breadth but noisy on DeFi-specific intent. A
`delegatecall` is not a bug; a function that takes `address user` is not a bug.
DeFiGuard focuses on a small set of **high-signal DeFi patterns**, each tied to a
real failure mode and a reproducible test, so a finding comes with the context an
auditor actually needs:

- **what** was matched and **where** (`file:line`, code snippet),
- **why** it is suspicious (the concrete failure mode),
- **what to check** to confirm or dismiss it.

## Rules in v0.1

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `DG-AC-001` | HIGH | A third-party `address` parameter used as a **token source** (`transferFrom(user, …)`) with **no authorization check** tying it to `msg.sender`. The "forced staking / forced deposit" class: anyone can move the tokens of any address that left a standing allowance. |
| `DG-DC-001` | REVIEW | A `delegatecall` site — needs a manual **storage-layout** diff between caller and target (one mismatched slot = silent state corruption). |
| `DG-EXT-001` | MEDIUM / LOW | A **state write after an external call** without `nonReentrant` (checks-effects-interactions / reentrancy candidate), plus low-level `.call`/`.send`/`.transfer` return-value and gas hygiene. |

Run `defiguard rules` to list them.

## Install

```bash
git clone https://github.com/OWNER/defiguard.git
cd defiguard
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"
```

No install needed to try it:

```bash
PYTHONPATH=src python3 -m defiguard.cli scan <path-to-contracts>
```

## Usage

```bash
# Markdown report to stdout
defiguard scan ./src

# Machine-readable JSON, written to a file
defiguard scan ./src --format json --output report.json

# CI gate: exit non-zero if anything HIGH or above is flagged
defiguard scan ./src --fail-on high
```

### Example

Scanning the bundled fixtures:

```
$ defiguard scan tests/fixtures
# DeFiGuard report (v0.1.0)
- Solidity files scanned: 6
- Findings: 5
- By severity: 🔴 HIGH: 1, 🟠 MEDIUM: 1, 🟡 LOW: 2, 🔵 REVIEW: 1

| 1 | 🔴 HIGH   | DG-AC-001  | vulnerable/ForcedStake.sol:21    | Third-party address parameter used as token source without an authorization check |
| 2 | 🟠 MEDIUM | DG-EXT-001 | vulnerable/ReentrantVault.sol:17 | State write after an external call without nonReentrant |
| 5 | 🔵 REVIEW | DG-DC-001  | vulnerable/DelegateProxy.sol:12  | delegatecall site: verify storage-layout compatibility |
```

The fixed counterparts (`tests/fixtures/fixed/`) are **not** flagged for their
respective issue — that positive/negative pairing is how DeFiGuard keeps false
positives honest.

## Foundry scenarios

`examples/foundry/` contains the same patterns as deployable contracts plus a
Foundry test that **exploits the vulnerable version and shows the fix holding**,
and an invariant template. See [`examples/foundry/README.md`](examples/foundry/README.md).

## How it works (and its limits)

v0.1 is deliberately **line/regex based** (comments and strings are stripped
first, so a pattern inside a comment never fires). This is simple and dependency
-free but cannot reason about data flow across functions or contracts. A real AST
/ data-flow backend (e.g. Slither integration) is a planned next step. See
[`docs/limitations.md`](docs/limitations.md) and [`docs/threat-model.md`](docs/threat-model.md).

## Contributing

New rules are welcome — **every rule must ship with a vulnerable fixture it flags
and a fixed fixture it stays silent on.** See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

[MIT](LICENSE).
