#!/usr/bin/env python3
"""Fail-safe output sanitization for LabSteward plugin results.

Plugins must first construct results from an explicit output schema. This module
is the mandatory defense-in-depth pass applied before results are logged or
returned to a caller.
"""

from __future__ import annotations

import math
import re
from typing import Any

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"
MAX_DEPTH = 12
MAX_ITEMS = 256
MAX_STRING_LENGTH = 8192

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "credential",
    "privatekey",
    "cookie",
    "sessionid",
    "csrf",
    "ticket",
)
_SENSITIVE_KEYS = {"auth", "authorization", "pwd", "sid"}
_BEARER_OR_BASIC = re.compile(
    r"(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]+"
)
_URL_USERINFO = re.compile(r"(?i)\b(https?://)[^\s/@]+@")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b([a-z0-9_-]*(?:password|passwd|passphrase|secret|token|apikey|api_key|"
    r"credential|privatekey|cookie|sessionid|csrf|ticket)[a-z0-9_-]*|authorization|"
    r'''pwd|sid)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s&,;]+)'''
)
_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")


def _normalized_key(key: object) -> str:
    if not isinstance(key, str):
        return ""
    return re.sub(r"[^a-z0-9]", "", key.lower())


def is_sensitive_key(key: object) -> bool:
    """Return whether a result field name implies authentication material."""

    normalized = _normalized_key(key)
    return normalized in _SENSITIVE_KEYS or any(
        part in normalized for part in _SENSITIVE_KEY_PARTS
    )


def sanitize_text(value: str, *, max_length: int = MAX_STRING_LENGTH) -> str:
    """Redact common inline secret forms and cap output size."""

    if "PRIVATE KEY-----" in value.upper():
        return REDACTED
    value = _URL_USERINFO.sub(r"\1[REDACTED]@", value)
    value = _BEARER_OR_BASIC.sub(lambda match: f"{match.group(1)} {REDACTED}", value)
    value = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", value)
    value = _JWT.sub(REDACTED, value)
    if len(value) > max_length:
        value = f"{value[:max_length]}{TRUNCATED}"
    return value


def sanitize_result(
    value: Any,
    *,
    max_depth: int = MAX_DEPTH,
    max_items: int = MAX_ITEMS,
    max_string_length: int = MAX_STRING_LENGTH,
) -> Any:
    """Return a JSON-safe, recursively redacted copy of a plugin result."""

    seen: set[int] = set()

    def walk(item: Any, depth: int) -> Any:
        if depth > max_depth:
            return TRUNCATED
        if item is None or isinstance(item, (bool, int)):
            return item
        if isinstance(item, float):
            return item if math.isfinite(item) else "[UNSUPPORTED NUMBER]"
        if isinstance(item, str):
            return sanitize_text(item, max_length=max_string_length)
        if isinstance(item, bytes):
            return "[BINARY OMITTED]"

        identity = id(item)
        if isinstance(item, dict):
            if identity in seen:
                return TRUNCATED
            seen.add(identity)
            result: dict[str, Any] = {}
            entries = list(item.items())
            for key, child in entries[:max_items]:
                if not isinstance(key, str):
                    result["[UNSUPPORTED KEY]"] = REDACTED
                    continue
                output_key = sanitize_text(key, max_length=256)
                result[output_key] = REDACTED if is_sensitive_key(key) else walk(child, depth + 1)
            if len(entries) > max_items:
                result["_labsteward_truncated"] = len(entries) - max_items
            seen.remove(identity)
            return result

        if isinstance(item, (list, tuple)):
            if identity in seen:
                return TRUNCATED
            seen.add(identity)
            entries = list(item)
            result = [walk(child, depth + 1) for child in entries[:max_items]]
            if len(entries) > max_items:
                result.append(TRUNCATED)
            seen.remove(identity)
            return result

        return f"[UNSUPPORTED TYPE: {type(item).__name__}]"

    if max_depth < 0 or max_items < 1 or max_string_length < 1:
        raise ValueError("Sanitizer limits must be positive")
    return walk(value, 0)
