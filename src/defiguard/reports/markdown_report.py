"""Human-readable Markdown report."""

from __future__ import annotations

from .. import __version__
from ..findings import Severity
from ..scanner import ScanResult

_SEVERITY_BADGE = {
    Severity.HIGH.value: "🔴 HIGH",
    Severity.MEDIUM.value: "🟠 MEDIUM",
    Severity.LOW.value: "🟡 LOW",
    Severity.REVIEW.value: "🔵 REVIEW",
}


def render_markdown(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"# DeFiGuard report (v{__version__})")
    lines.append("")
    lines.append(f"- Root: `{result.root}`")
    lines.append(f"- Solidity files scanned: **{result.files_scanned}**")
    lines.append(f"- Findings: **{len(result.findings)}**")

    counts = result.counts_by_severity()
    if counts:
        badge = ", ".join(
            f"{_SEVERITY_BADGE.get(sev, sev)}: {n}"
            for sev, n in sorted(counts.items())
        )
        lines.append(f"- By severity: {badge}")
    lines.append("")
    lines.append(
        "> ⚠️ Findings are **heuristic review hints, not confirmed vulnerabilities.** "
        "Each must be confirmed by a human and, where possible, a test."
    )
    lines.append("")

    if not result.findings:
        lines.append("No suspicious patterns flagged. (Absence of flags is not proof of safety.)")
        return "\n".join(lines) + "\n"

    lines.append("## Summary")
    lines.append("")
    lines.append("| # | Severity | Rule | Location | What to review |")
    lines.append("|---|----------|------|----------|----------------|")
    for i, f in enumerate(result.sorted_findings(), 1):
        badge = _SEVERITY_BADGE.get(f.severity.value, f.severity.value)
        lines.append(f"| {i} | {badge} | `{f.rule_id}` | `{f.location()}` | {f.title} |")
    lines.append("")

    lines.append("## Details")
    lines.append("")
    for i, f in enumerate(result.sorted_findings(), 1):
        badge = _SEVERITY_BADGE.get(f.severity.value, f.severity.value)
        lines.append(f"### {i}. {f.title}")
        lines.append("")
        lines.append(f"- **Severity:** {badge}")
        lines.append(f"- **Rule:** `{f.rule_id}`" + (f" ({f.cwe})" if f.cwe else ""))
        lines.append(f"- **Location:** `{f.location()}`")
        if f.snippet:
            lines.append(f"- **Code:** `{f.snippet}`")
        lines.append(f"- **Why flagged:** {f.rationale}")
        lines.append(f"- **What to check:** {f.recommendation}")
        lines.append("")

    return "\n".join(lines) + "\n"
