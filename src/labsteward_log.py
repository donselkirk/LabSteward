#!/usr/bin/env python3
"""Bounded, sanitized LABSteward runtime and audit log storage."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import tempfile
from pathlib import Path
from typing import Any

LOG_DIR = Path(os.environ.get("LABSTEWARD_LOG_DIR", "/var/log/labsteward"))
CURRENT = LOG_DIR / "current.jsonl"
MAX_EVENT_BYTES = 8192
MAX_EVENTS_READ = 200
SECRET_KEY = re.compile(r"(?:pass|token|secret|credential|authorization|cookie|csrf|private|api[-_]?key)", re.I)
SENSITIVE_TEXT = re.compile(r"(?:bearer\s+|lst_[A-Za-z0-9_-]+|lsa_[A-Za-z0-9_-]+|lsc_[A-Za-z0-9_-]+|-----BEGIN [^-]+-----)", re.I)


def _safe(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if SECRET_KEY.search(str(k)) else _safe(v, depth + 1) for k, v in list(value.items())[:32]}
    if isinstance(value, (list, tuple)):
        return [_safe(v, depth + 1) for v in list(value)[:32]]
    if isinstance(value, str):
        text = SENSITIVE_TEXT.sub("[REDACTED]", value)
        return text[:1024]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:256]


def runtime_id() -> str:
    path = LOG_DIR / "runtime.id"
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    if value:
        return value
    value = f"rt_{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{secrets.token_hex(4)}"
    LOG_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")
    os.chmod(path, 0o640)
    return value


def append(event_type: str, severity: str = "info", component: str = "system", fields: dict[str, Any] | None = None, message: str = "") -> None:
    record = {
        "timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "runtime_id": runtime_id(),
        "type": str(event_type)[:80],
        "severity": str(severity)[:16],
        "component": str(component)[:48],
        "message": str(_safe(message))[:1024],
        "fields": _safe(fields or {}),
    }
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > MAX_EVENT_BYTES:
        record["fields"] = {"notice": "event fields truncated"}
        encoded = (json.dumps(record, sort_keys=True) + "\n").encode()
    LOG_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    _rotate_and_prune(record["timestamp"][:10])
    with CURRENT.open("ab") as handle:
        handle.write(encoded[:MAX_EVENT_BYTES])
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(CURRENT, 0o640)


def _rotate_and_prune(today: str) -> None:
    archive_dir = LOG_DIR / "archive"
    archive_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    if CURRENT.exists():
        try:
            first = json.loads(CURRENT.read_text(encoding="utf-8").splitlines()[0])
            previous = str(first.get("timestamp", ""))[:10]
        except (OSError, IndexError, json.JSONDecodeError):
            previous = today
        if previous and previous != today:
            destination = archive_dir / f"{previous}.jsonl"
            temporary = archive_dir / f".{previous}.{os.getpid()}.tmp"
            CURRENT.replace(temporary)
            if destination.exists():
                with destination.open("ab") as target, temporary.open("rb") as source:
                    target.write(source.read())
                temporary.unlink(missing_ok=True)
            else:
                temporary.replace(destination)
            os.chmod(destination, 0o640)
    cutoff = dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=30)
    for path in archive_dir.glob("*.jsonl"):
        try:
            if dt.date.fromisoformat(path.stem) < cutoff:
                path.unlink(missing_ok=True)
        except ValueError:
            continue


def read(archive: str = "", limit: int = MAX_EVENTS_READ) -> dict[str, Any]:
    limit = max(1, min(int(limit), MAX_EVENTS_READ))
    path = CURRENT if not archive else LOG_DIR / "archive" / f"{archive}.jsonl"
    if archive and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", archive):
        raise ValueError("invalid archive date")
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    except OSError:
        lines = []
    for line in reversed(lines):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(_safe(value))
    archives = []
    try:
        archives = sorted(p.stem for p in (LOG_DIR / "archive").glob("*.jsonl") if re.fullmatch(r"\d{4}-\d{2}-\d{2}", p.stem))
    except OSError:
        pass
    return {"runtime_id": runtime_id(), "archive": archive, "events": events, "archives": archives[-31:]}
