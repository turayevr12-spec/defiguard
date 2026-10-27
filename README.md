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

## ⚠️ Authorized & responsible use (read this first)

DeFiGuard is for **learning and for testing your own projects.** By using it you
accept full responsibility for how you use it and for anything you do with its
output.

- **Authorized targets only.** Run DeFiGuard only on code you **own** or are
  **explicitly authorized** to analyze (e.g. your own contracts, or a bug-bounty
  program whose scope and rules permit it). Analyzing or attacking systems
  without permission may be illegal — that is on you, not this tool.
- **Educational / testing purpose.** This project exists to study smart-contract
  security and to test the tool itself. A flag is a *hypothesis to verify*, never
  a licence to exploit anything.
- **Follow program rules.** If a finding relates to a bug-bounty program, obey
  that program's scope, "test only your own accounts" rule, and **disclosure**
  policy. Many programs forbid *any* public disclosure (including pushing a PoC to
  a public repo) before resolution. Report privately, through the program.
- **No warranty, no liability.** DeFiGuard is provided "as is" under the
  [MIT License](LICENSE), **without any warranty.** The authors and contributors
  are **not liable** for any use, misuse, damage, or legal consequence. **All
  responsibility rests entirely with the person running it.**

See [`SECURITY.md`](SECURITY.md) and [`docs/threat-model.md`](docs/threat-model.md).

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
| `DG-DOS-001` | MEDIUM | A **loop bounded by a growable array's length** (`for (…; i < arr.length; …)` where `arr` is also `.push`-ed). Unbounded growth eventually makes the call exceed the block gas limit and revert forever — a denial-of-service / permanent fund lock-up. |

Run `defiguard rules` to list them.

## Install

```bash
git clone https://github.com/turayevr12-spec/defiguard.git
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

## False-positive benchmark

Measured on the bundled fixtures (`defiguard scan tests/fixtures`), 8 files — 4
vulnerable, 4 fixed, one pair per rule:

| Metric | Result |
|--------|--------|
| Vulnerable classes correctly flagged (true positives) | **4 / 4** — DG-AC-001, DG-EXT-001, DG-DC-001, DG-DOS-001 |
| Fixed files flagged for their vulnerability class (false positives) | **0 / 4** |
| Other notes on fixed files | 1 × LOW on `SafeVault.sol` — a low-level-call **hygiene** note (return value / gas), not a reentrancy claim. Documented and intentional. |

So on this set the detectors have **0 class-level false positives**; the single
LOW note is advisory hygiene, not a "this is broken" flag. These fixtures are the
regression gate — every new rule must keep this record (a vulnerable fixture it
flags, a fixed fixture it does not). The set is small and synthetic; a benchmark
on real-world corpora is planned (see [`docs/limitations.md`](docs/limitations.md)).

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
