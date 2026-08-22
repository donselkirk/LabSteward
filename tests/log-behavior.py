#!/usr/bin/env python3
"""Behavior checks for sanitized runtime logs and retention."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


with tempfile.TemporaryDirectory(prefix="labsteward-log.") as directory:
    os.environ["LABSTEWARD_LOG_DIR"] = directory
    spec = importlib.util.spec_from_file_location("labsteward_log", ROOT / "src/labsteward_log.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    module.append(
        "test.event",
        component="test",
        message="token lst_secret and password should disappear",
        fields={"api_token": "secret-value", "safe": "ok"},
    )
    current = Path(directory) / "current.jsonl"
    record = json.loads(current.read_text().splitlines()[0])
    serialized = json.dumps(record)
    require("secret-value" not in serialized and "lst_secret" not in serialized, "secrets leaked into log")
    require(record["fields"]["api_token"] == "[REDACTED]", "sensitive field was not redacted")
    require(module.read()["events"][0]["type"] == "test.event", "current log read failed")
    archive = Path(directory) / "archive"
    archive.mkdir(exist_ok=True)
    old = archive / "2020-01-01.jsonl"
    old.write_text("{}\n")
    module._rotate_and_prune("2026-08-22")
    require(not old.exists(), "old archive was not pruned")

print("Log behavior checks passed.")
