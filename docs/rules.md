# Rules

Each rule is a **high-signal heuristic**: it flags a pattern that is frequently
(but not always) a real problem, and tells the auditor exactly what to confirm.
Every rule ships with a vulnerable fixture it flags and a fixed fixture it stays
silent on (`tests/fixtures/`), plus — where useful — a Foundry scenario
(`examples/foundry/`).

Severity here means *how much review a flag deserves*, not confirmed
exploitability.

---

## DG-AC-001 — Third-party token source without authorization (HIGH, CWE-284)

**Fires when** an `external`/`public` function takes an `address <param>` and
pulls tokens with `transferFrom(<param>, …)` / `safeTransferFrom(<param>, …)`
while nothing requires `msg.sender == <param>` (no equality guard, EIP-712
permit, or operator mapping).

**Why it matters.** An ERC20 `approve` grants a *spend cap*, not consent to a
specific action. If any caller can name an arbitrary `user`, anyone can move the
tokens of any address that left a standing allowance — forcing them into a
position (a stake, a deposit, a lock) they never agreed to. The infamous trap:
`if (user == address(0)) user = msg.sender;` is a **default**, not an
authorization check, and the rule treats it as such.

**Confirm / dismiss.** Is a caller other than `user` meant to trigger this? If
not, bind to `msg.sender`. If delegation is a product requirement, verify a
signed permit naming the exact action, or an authorized-operator mapping.

**Known false positives.** Functions that verify a permit/operator the rule's
regex does not recognize; functions where `<param>` is only a *beneficiary*, not
the token *source* (the rule already keys on `transferFrom(<param>, …)` to avoid
this).

---

## DG-DC-001 — delegatecall storage-layout review (REVIEW, CWE-668)

**Fires when** a `.delegatecall(` site exists.

**Why it matters.** `delegatecall` runs the target's code against *this*
contract's storage. One mismatched slot between caller and target = silent state
corruption. delegatecall is legitimate (proxies, diamonds, EIP-170 size
splitting), so this is a REVIEW flag, not a defect.

**Confirm / dismiss.** Diff the storage layouts
(`forge inspect <Caller> storageLayout` vs the target), ignoring compiler AST
ids. The target should inherit the same storage base and add only
`immutable`/`constant` state. Confirm the target rejects direct calls if it must
only run under delegatecall.

---

## DG-EXT-001 — external call: reentrancy & low-level hygiene (MEDIUM / LOW, CWE-841/252)

**Fires when** (MEDIUM) a state variable is written *after* an external call in a
function not marked `nonReentrant` — a checks-effects-interactions violation and
reentrancy candidate; and (LOW) when raw `.call` / `.send` / `.transfer` is used,
to check the return value and gas assumptions.

**Why it matters.** The callee of an external call can re-enter before the state
is updated. `.transfer`/`.send` forward a fixed 2300-gas stipend that breaks
legitimate receivers; `.call`/`.send` return a success bool that must be checked.

**Confirm / dismiss.** Move state updates before the interaction, add a guard, or
use pull payments. Confirm the callee cannot re-enter anything relying on stale
state. For low-level calls, check the success flag explicitly.

**Known false positives.** A reentrancy guard the rule's regex misses; trusted
callees; variables the heuristic mistakes for state (it excludes locals it can
see declared, but cross-scope cases can slip through).

---

## DG-DOS-001 — Loop over a growable array's length (MEDIUM, CWE-834)

**Fires when** a `for` loop is bounded by `arr.length` (or `m[k].length`) and
`arr` is also appended to with `.push(...)` somewhere in the file — i.e. the
array can grow without bound.

**Why it matters.** Once the array is large enough, iterating it costs more than
the block gas limit and every call on that path reverts **permanently**. If that
path is how a user exits a position or claims funds, the funds are stuck — a
denial-of-service (the idOS node-staking `withdrawUnstaked` / `withdrawableReward`
class). Gas-griefing is out of scope in many programs, but *permanent* fund
lock-up from unbounded growth often is not — confirm which this is.

**Confirm / dismiss.** Is the array attacker-growable or only self-growable? Is
the stuck state recoverable by anyone? Paginate (iterate to a caller-supplied
count, persisting progress), cap the array size, or redesign so one account's
growth cannot brick funds.

**Known false positives.** A loop over a `.length` the heuristic links to a
`.push` that is actually access-controlled or hard-bounded; a `.length` used only
to clamp a paginated loop (the rule keys on `.length` *in the loop header*, so a
loop running to a separate `end` variable is not flagged).

---

## Adding a rule

See [`../CONTRIBUTING.md`](../CONTRIBUTING.md). A rule PR must include its
positive (vulnerable) and negative (fixed) fixtures and its false-positive notes.
