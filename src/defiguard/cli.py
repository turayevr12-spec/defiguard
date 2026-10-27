"""DeFiGuard command-line interface.

Usage:
    defiguard scan <path> [--format json|markdown] [--output FILE] [--fail-on SEV]
    defiguard rules
    defiguard version
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .findings import Severity
from .reports import render_json, render_markdown
from .rules import load_rules
from .scanner import scan

_FAIL_ORDER = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.REVIEW]


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    try:
        result = scan(root)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        output = render_json(result)
    else:
        output = render_markdown(result)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Wrote {args.format} report to {args.output} "
              f"({len(result.findings)} findings over {result.files_scanned} files).")
    else:
        print(output)

    # exit code policy for CI: fail if any finding at/above --fail-on severity
    if args.fail_on:
        threshold = Severity(args.fail_on)
        cutoff = _FAIL_ORDER.index(threshold)
        triggered = [
            f for f in result.findings
            if _FAIL_ORDER.index(f.severity) <= cutoff
        ]
        if triggered:
            print(
                f"\n{len(triggered)} finding(s) at or above '{threshold}' -- failing per --fail-on.",
                file=sys.stderr,
            )
            return 1
    return 0


def _cmd_rules(_args: argparse.Namespace) -> int:
    for rule in load_rules():
        cwe = f" [{rule.cwe}]" if rule.cwe else ""
        print(f"{rule.id}{cwe}: {rule.title}")
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"defiguard {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defiguard",
        description="Heuristic Solidity/DeFi security review helper. "
                    "Flags suspicious patterns to review -- not a vulnerability oracle.",
    )
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Scan a directory of Solidity files.")
    p_scan.add_argument("path", help="Directory to scan recursively.")
    p_scan.add_argument("--format", choices=["json", "markdown"], default="markdown")
    p_scan.add_argument("--output", "-o", help="Write the report to this file instead of stdout.")
    p_scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="Exit non-zero if any finding is at/above this severity (for CI).",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_rules = sub.add_parser("rules", help="List the bundled rules.")
    p_rules.set_defaults(func=_cmd_rules)

    p_version = sub.add_parser("version", help="Print the version.")
    p_version.set_defaults(func=_cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
