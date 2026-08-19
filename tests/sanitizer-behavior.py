#!/usr/bin/env python3
"""Behavior checks for the mandatory LabSteward output sanitizer."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from labsteward_sanitize import REDACTED, TRUNCATED, sanitize_result  # noqa: E402


payload = {
    "status": "running",
    "host": "pve1.example.test",
    "password": "do-not-return",
    "nested": {
        "apiToken": "token-value",
        "headers": {
            "Authorization": "Bearer header-token",
            "Set-Cookie": "PVEAuthCookie=cookie-value",
        },
        "message": "request failed: ticket=inline-ticket",
        "quoted": 'upstream said password="two word secret"',
        "endpoint": "https://user:url-password@example.test/api",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
    },
    "private_key": "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----",
}

sanitized = sanitize_result(payload)
serialized = json.dumps(sanitized, sort_keys=True)

assert sanitized["status"] == "running"
assert sanitized["host"] == "pve1.example.test"
assert sanitized["password"] == REDACTED
assert sanitized["nested"]["apiToken"] == REDACTED
assert sanitized["nested"]["headers"]["Authorization"] == REDACTED
assert sanitized["nested"]["headers"]["Set-Cookie"] == REDACTED
assert sanitized["private_key"] == REDACTED
for forbidden in (
    "do-not-return",
    "token-value",
    "header-token",
    "cookie-value",
    "inline-ticket",
    "two word secret",
    "url-password",
    "private-material",
    "signature",
):
    assert forbidden not in serialized

cyclic: list[object] = []
cyclic.append(cyclic)
assert sanitize_result(cyclic) == [TRUNCATED]
assert sanitize_result("abcdefgh", max_string_length=4) == f"abcd{TRUNCATED}"
assert sanitize_result([1, 2, 3], max_items=2) == [1, 2, TRUNCATED]

print("Sanitizer behavior checks passed.")
