"""Scanner: discover Solidity files and run every rule over them."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding, relpath
from .rules import Rule, load_rules

# directories that are dependencies / build output, never the code under audit
_SKIP_DIRS = {"node_modules", "lib", "dependencies", "out", "cache", "artifacts", ".git", "forge-std"}


def find_solidity_files(root: Path) -> list[Path]:
    """Find `.sol` files under ``root``, skipping dependency/build directories.

    Raises FileNotFoundError / NotADirectoryError for a bad path so the CLI can
    report a controlled error.
    """
    if not root.exists():
        raise FileNotFoundError(f"Directory not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    results: list[Path] = []
    for path in sorted(root.rglob("*.sol")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        results.append(path)
    return results


@dataclass
class ScanResult:
    root: Path
    files_scanned: int
    findings: list[Finding] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key)

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts


def scan(root: Path, rules: list[Rule] | None = None) -> ScanResult:
    rules = rules if rules is not None else load_rules()
    files = find_solidity_files(root)
    findings: list[Finding] = []

    for path in files:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        label = relpath(path, root)
        for rule in rules:
            findings.extend(rule.check(label, source))

    return ScanResult(root=root, files_scanned=len(files), findings=findings)
