# Limitations

Being explicit about what DeFiGuard **cannot** do is part of the project. A tool
that hides its blind spots is worse than no tool.

## v0.1 is line/regex based

- Comments and string literals are stripped before matching (so a pattern inside
  a comment never fires), but there is **no AST and no data-flow analysis**.
- It cannot follow a value across functions or contracts, resolve inheritance,
  or understand modifiers it does not textually recognize.
- Function/body extraction uses naive brace matching; unusual formatting or
  deeply nested constructs may be parsed imperfectly.

## False positives are expected

Each rule documents its known false positives (see [`rules.md`](rules.md)). For
example, DG-EXT-001 flags the low-level call in a *fixed* vault at LOW severity —
that is honest hygiene guidance, not a claim the vault is broken. Treat findings
as "look here", never "this is a bug".

## False negatives are expected too

Absence of findings is **not** proof of safety. DeFiGuard only knows the patterns
it has rules for, and only matches what its regexes catch. It will miss:

- logic bugs with no syntactic signature (bad accounting, wrong rounding, flawed
  incentive design),
- issues that require cross-contract reasoning,
- anything outside its three v0.1 rules.

## Not a replacement for

- A professional audit.
- [Slither](https://github.com/crytic/slither) / Mythril (AST & symbolic depth).
- Foundry fuzzing / invariant testing (which DeFiGuard *complements* via the
  `examples/foundry/` scenarios).

## Planned

- An optional AST / data-flow backend (e.g. consuming Slither's output).
- More rules, each with fixtures and false-positive accounting.
- A measured false-positive benchmark published in the README.
