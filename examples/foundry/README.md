# DeFiGuard Foundry scenarios

Runnable contracts and tests for the patterns DeFiGuard flags. Each scenario
exploits a **vulnerable** contract and shows the **fixed** one holding, so a
flag from the scanner can be confirmed (or dismissed) with a reproducible test.

These examples are **self-contained**: the tests declare a minimal `Vm`
cheatcode interface inline and assert with `require`, so they run with no
external dependency.

```bash
cd examples/foundry
forge test -vv
```

## What's here

| File | Shows |
|------|-------|
| `src/Staking.sol` | A `MockERC20`, a **vulnerable** `ForcedStake`, and a **fixed** `SafeStake`. |
| `test/ForcedStake.t.sol` | DG-AC-001: attacker force-stakes a victim's approved tokens (vulnerable); the fixed contract reverts, and an explicitly authorized operator is allowed. |
| `test/ConservationInvariant.t.sol` | An invariant template — token **solvency** (held balance ≥ total accounted stake) — with notes on upgrading it to a handler-based fuzzing invariant. |

## Expected output

```
[PASS] test_Vulnerable_AttackerForcesVictimStake()
[PASS] test_Fixed_RejectsForcedStake()
[PASS] test_Fixed_AuthorizedOperatorAllowed()
[PASS] test_SolvencyHoldsAcrossStakes()
```

The "vulnerable" test passing means the **exploit succeeds** against the unsafe
contract — that is the point. The "fixed" tests passing means the mitigation
actually blocks it.
