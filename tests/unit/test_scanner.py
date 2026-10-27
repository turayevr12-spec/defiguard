"""Tests for file discovery and the scan orchestration."""

from __future__ import annotations

from pathlib import Path

import pytest

from defiguard.scanner import find_solidity_files, scan

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_finds_solidity_files_in_existing_dir():
    files = find_solidity_files(FIXTURES)
    names = {p.name for p in files}
    assert "ForcedStake.sol" in names
    assert "SafeStake.sol" in names
    assert all(p.suffix == ".sol" for p in files)


def test_empty_dir_returns_no_files(tmp_path: Path):
    assert find_solidity_files(tmp_path) == []


def test_missing_path_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        find_solidity_files(tmp_path / "does-not-exist")


def test_file_instead_of_dir_raises(tmp_path: Path):
    f = tmp_path / "a.sol"
    f.write_text("// sol")
    with pytest.raises(NotADirectoryError):
        find_solidity_files(f)


def test_skips_dependency_dirs(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text("// a")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "Dep.sol").write_text("// dep")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "Pkg.sol").write_text("// pkg")

    names = {p.name for p in find_solidity_files(tmp_path)}
    assert names == {"A.sol"}


def test_scan_reports_files_scanned():
    result = scan(FIXTURES)
    assert result.files_scanned >= 6
    assert result.findings  # the vulnerable fixtures must produce findings
