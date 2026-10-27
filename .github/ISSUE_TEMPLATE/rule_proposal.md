---
name: Rule proposal
about: Propose a new detection rule
title: "[rule] "
labels: rule
---

## Pattern

What suspicious pattern should DeFiGuard flag? Show a minimal code example.

## Why it matters (failure mode)

What real DeFi failure does this pattern lead to?

## Positive fixture (should flag)

```solidity
// vulnerable example
```

## Negative fixture (should stay silent)

```solidity
// safe idiom that must NOT be flagged
```

## Known false positives

Where would this rule fire on safe code? How do we keep it precise?

## Suggested severity

HIGH / MEDIUM / LOW / REVIEW — and why.
