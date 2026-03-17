# MIT License — Copyright (c) 2026 cvemula1
# Tests for CLI entry point

import subprocess
import sys


def test_version():
    result = subprocess.run(
        [sys.executable, "-m", "nhinsight.cli", "version"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "nhinsight 0.1.0" in result.stdout


def test_demo():
    result = subprocess.run(
        [sys.executable, "-m", "nhinsight.cli", "demo"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "NHInsight" in result.stdout
    assert "deploy-bot" in result.stdout
    assert "CRITICAL" in result.stdout


def test_help():
    result = subprocess.run(
        [sys.executable, "-m", "nhinsight.cli", "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "nhinsight" in result.stdout


def test_scan_no_provider():
    result = subprocess.run(
        [sys.executable, "-m", "nhinsight.cli", "scan"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "No providers selected" in result.stdout
