"""Machine-readable JSON report (stable schema for CI / tooling)."""

from __future__ import annotations

import json

from .. import __version__
from ..scanner import ScanResult


def render_json(result: ScanResult, indent: int = 2) -> str:
    payload = {
        "tool": "defiguard",
        "version": __version__,
        "root": str(result.root),
        "files_scanned": result.files_scanned,
        "summary": result.counts_by_severity(),
        "findings_total": len(result.findings),
        "findings": [f.to_dict() for f in result.sorted_findings()],
        "disclaimer": (
            "Findings are heuristic review hints, not confirmed vulnerabilities. "
            "Each must be verified by a human and, where possible, a test. "
            "Use only on code you own or are authorized to analyze, for learning / "
            "testing purposes; follow any bug-bounty program's scope and disclosure "
            "rules. No warranty -- all responsibility rests with the person running it."
        ),
    }
    return json.dumps(payload, indent=indent)
