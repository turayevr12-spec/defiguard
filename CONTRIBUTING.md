# Contributing to DeFiGuard

Thanks for helping! DeFiGuard values **precision over breadth**: a few
high-signal rules with honest false-positive accounting beat a flood of noisy
checks.

## Dev setup

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

## The rule for rules

**Every new rule MUST include:**

1. A rule class in `src/defiguard/rules/<name>.py` subclassing `Rule`, registered
   in `src/defiguard/rules/__init__.py`'s `load_rules()`.
2. A **vulnerable fixture** (`tests/fixtures/vulnerable/`) the rule flags.
3. A **fixed fixture** (`tests/fixtures/fixed/`) the rule stays **silent** on.
4. Unit tests asserting both (positive + negative), like `tests/unit/test_rules.py`.
5. A section in [`docs/rules.md`](docs/rules.md) including **known false positives**.
6. Ideally, a Foundry scenario in `examples/foundry/` that exploits the
   vulnerable version and shows the fix holding.

A rule with no negative fixture will not be merged — the negative case is how we
keep false positives honest.

## Finding quality bar

- A finding says *what*, *where*, *why*, and *what to check* — never "this is a
  vulnerability".
- Prefer precision. If a rule can't distinguish a real issue from a common safe
  idiom, add the guard or lower its severity and document the gap.

## Style

- Python 3.10+, standard library only for core rules (keep install light).
- Small, focused commits with a clear message. Don't pad commit counts.
- Run `python -m pytest -q` and `defiguard scan tests/fixtures` before opening a PR.

## Reporting a bug / proposing a rule

Use the issue templates in `.github/ISSUE_TEMPLATE/`.
