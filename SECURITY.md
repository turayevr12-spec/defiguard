# Security policy

## Reporting a vulnerability in DeFiGuard itself

DeFiGuard reads source files and emits text; it does not execute target code or
touch the network. If you nonetheless find a security issue in the tool (e.g. a
crafted input that causes unsafe behavior on the host), please report it
privately:

- Open a GitHub **security advisory** on this repository (Security → Report a
  vulnerability), or
- Email the maintainers listed in the repository profile.

Please do **not** open a public issue for a security report. We aim to acknowledge
within a few days.

## Using DeFiGuard responsibly

DeFiGuard surfaces patterns that could be abused. When you act on a finding:

- Only analyze code you are **authorized** to review.
- If the code is in a **bug-bounty** program, follow that program's rules
  exactly — scope, the "test only your own accounts" rule, and especially
  **disclosure**. Many programs forbid any public disclosure (including pushing a
  PoC to a public repo) before resolution. A DeFiGuard finding is a lead to
  verify and report **privately through the program**, not to publish.
- Reproduce findings in a **local** environment (the `examples/foundry/`
  scenarios use synthetic actors in a local EVM), never against production
  systems or real user data.

A flag is a hypothesis. Confirm it with a test and human review before you report
anything.

## Responsibility

DeFiGuard is provided for **educational use and for testing your own projects**,
"as is" and **without warranty** (see [LICENSE](LICENSE)). It must only be used
where you are **authorized**. The authors and contributors accept **no liability**
for any use, misuse, damage, or legal consequence. **All responsibility for how
the tool is used, and for acting on its output, rests entirely with the person
running it.**
