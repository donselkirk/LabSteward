#!/usr/bin/env python3
"""Shared, allowlisted LabSteward action dispatcher.

The local manager and remote MCP transport both call this module. Plugins will
register additional fixed actions in later releases; arbitrary commands, URLs,
paths, and upstream requests are intentionally outside this interface.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from labsteward_sanitize import sanitize_result

BASE_DIR = Path(os.environ.get("LABSTEWARD_BASE_DIR", "/opt/labsteward"))
CONFIG_FILE = Path(os.environ.get("LABSTEWARD_CONFIG_FILE", "/etc/labsteward/config.json"))
CATALOG_FILE = Path(
    os.environ.get("LABSTEWARD_CATALOG_FILE", str(BASE_DIR / "catalog/plugins.json"))
)
VERSION_FILE = Path(os.environ.get("LABSTEWARD_VERSION_FILE", str(BASE_DIR / "VERSION")))
TRANSPORT_CONFIG_FILE = Path(
    os.environ.get("LABSTEWARD_TRANSPORT_CONFIG", "/etc/labsteward/transport.json")
)

MAX_JSON_FILE_SIZE = 1024 * 1024


class DispatchError(Exception):
    """A safe error that may be returned to a caller."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _read_object(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_JSON_FILE_SIZE:
            raise ValueError("file is oversized")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise DispatchError("core_unhealthy", "LabSteward core data is unavailable") from exc
    if not isinstance(value, dict):
        raise DispatchError("core_unhealthy", "LabSteward core data is unavailable")
    return value


def _registry_summary() -> dict[str, Any]:
    config = _read_object(CONFIG_FILE)
    catalog = _read_object(CATALOG_FILE)
    if config.get("schema") != 1 or catalog.get("schema") != 1:
        raise DispatchError("core_unhealthy", "LabSteward core data is unavailable")
    plugins = config.get("plugins")
    servers = config.get("servers")
    clients = config.get("clients", {})
    catalog_plugins = catalog.get("plugins")
    if not all(isinstance(item, dict) for item in (plugins, servers, clients)):
        raise DispatchError("core_unhealthy", "LabSteward core data is unavailable")
    if not isinstance(catalog_plugins, list):
        raise DispatchError("core_unhealthy", "LabSteward core data is unavailable")
    enabled_clients = sum(
        1
        for client in clients.values()
        if isinstance(client, dict) and client.get("enabled") is True
    )
    try:
        version = VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        version = "development"
    if not version or len(version) > 64:
        version = "unknown"
    return {
        "status": "healthy",
        "version": version,
        "catalogued_plugins": len(catalog_plugins),
        "installed_plugins": len(plugins),
        "registered_servers": len(servers),
        "enabled_remote_clients": enabled_clients,
        "remote_transport": (
            "configured" if TRANSPORT_CONFIG_FILE.is_file() else "not_configured"
        ),
    }


def tool_definitions() -> list[dict[str, Any]]:
    """Return the complete allowlisted MCP tool catalog for this core release."""

    return [
        {
            "name": "core_status",
            "title": "LabSteward core status",
            "description": (
                "Return a sanitized LabSteward appliance health summary. "
                "This read-only tool does not contact any managed server."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            "outputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "status",
                    "version",
                    "catalogued_plugins",
                    "installed_plugins",
                    "registered_servers",
                    "enabled_remote_clients",
                    "remote_transport",
                ],
                "properties": {
                    "status": {"const": "healthy"},
                    "version": {"type": "string"},
                    "catalogued_plugins": {"type": "integer", "minimum": 0},
                    "installed_plugins": {"type": "integer", "minimum": 0},
                    "registered_servers": {"type": "integer", "minimum": 0},
                    "enabled_remote_clients": {"type": "integer", "minimum": 0},
                    "remote_transport": {"enum": ["configured", "not_configured"]},
                },
            },
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }
    ]


def dispatch_action(action: str, arguments: Any) -> dict[str, Any]:
    """Run one fixed action and return only its declared, sanitized result."""

    if action not in {"core.status", "core_status"}:
        raise DispatchError("unknown_action", "Unknown LabSteward action")
    if not isinstance(arguments, dict) or arguments:
        raise DispatchError("invalid_arguments", "core.status accepts no arguments")
    # _registry_summary constructs the result from an explicit output allowlist.
    return sanitize_result(_registry_summary())
