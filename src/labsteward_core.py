#!/usr/bin/env python3
"""Shared, allowlisted LabSteward action dispatcher.

The local manager and remote MCP transport both call this module. Plugins will
register additional fixed actions in later releases; arbitrary commands, URLs,
paths, and upstream requests are intentionally outside this interface.
"""

from __future__ import annotations

import json
import importlib.util
import os
import re
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
PLUGINS_DIR = Path(os.environ.get("LABSTEWARD_PLUGINS_DIR", str(BASE_DIR / "plugins")))
SERVER_SECRETS_DIR = Path(
    os.environ.get("LABSTEWARD_SERVER_SECRETS_DIR", "/etc/labsteward/secrets/servers")
)

MAX_JSON_FILE_SIZE = 1024 * 1024
SERVER_ALIAS = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
SYNOLOGY_ACTIONS = {
    "synology.system.summary": "system.read",
    "synology_system_summary": "system.read",
    "synology.storage.summary": "storage.read",
    "synology_storage_summary": "storage.read",
}
UNIFI_ACTIONS = {
    "unifi.configuration.summary": ("config.read", "read"),
    "unifi_configuration_summary": ("config.read", "read"),
    "unifi.diagnostics.summary": ("diagnostics.read", "read"),
    "unifi_diagnostics_summary": ("diagnostics.read", "read"),
    "unifi.client.summary": ("clients.read", "read"),
    "unifi_client_summary": ("clients.read", "read"),
    "unifi.clients.list": ("clients.read", "read"),
    "unifi_clients_list": ("clients.read", "read"),
    "unifi.firewall.rules": ("firewall.rules", "read"),
    "unifi_firewall_rules": ("firewall.rules", "read"),
    "unifi.firewall.logging.set": ("firewall.rules", "write"),
    "unifi_firewall_logging_set": ("firewall.rules", "write"),
}
UNIFI_CANONICAL = {
    "unifi_configuration_summary": "unifi.configuration.summary",
    "unifi_diagnostics_summary": "unifi.diagnostics.summary",
    "unifi_client_summary": "unifi.client.summary",
    "unifi_clients_list": "unifi.clients.list",
    "unifi_firewall_rules": "unifi.firewall.rules",
    "unifi_firewall_logging_set": "unifi.firewall.logging.set",
}


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


def _load_plugin(plugin_id: str, expected_version: str) -> Any:
    path = PLUGINS_DIR / plugin_id / "plugin.py"
    try:
        spec = importlib.util.spec_from_file_location(f"labsteward_plugin_{plugin_id}", path)
        if spec is None or spec.loader is None:
            raise ImportError("plugin loader is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except (OSError, ImportError, SyntaxError, AttributeError) as exc:
        raise DispatchError("plugin_unavailable", "Requested plugin is unavailable") from exc
    if module.PLUGIN_ID != plugin_id or module.PLUGIN_VERSION != expected_version:
        raise DispatchError("plugin_unavailable", "Requested plugin version is incompatible")
    return module


def _load_synology_plugin() -> Any:
    return _load_plugin("synology", "0.1.0")


def _synology_enabled(config: dict[str, Any]) -> bool:
    record = config.get("plugins", {}).get("synology")
    return isinstance(record, dict) and record.get("enabled") is True


def _synology_tools(config: dict[str, Any]) -> list[dict[str, Any]]:
    if not _synology_enabled(config):
        return []
    return _load_synology_plugin().tool_definitions()


def _unifi_tools(config: dict[str, Any]) -> list[dict[str, Any]]:
    if not _plugin_enabled(config, "unifi"):
        return []
    return _load_plugin("unifi", "0.1.0").tool_definitions()


def _plugin_enabled(config: dict[str, Any], plugin_id: str) -> bool:
    record = config.get("plugins", {}).get(plugin_id)
    return isinstance(record, dict) and record.get("enabled") is True


def _grant_allows(granted: object, required_level: str) -> bool:
    return granted == "write" or (required_level == "read" and granted == "read")


def _authorized_target(
    config: dict[str, Any], alias: object, plugin_id: str, permission: str,
    required_level: str, client_id: str | None,
) -> tuple[str, dict[str, Any]]:
    if not isinstance(alias, str) or not SERVER_ALIAS.fullmatch(alias):
        raise DispatchError("invalid_arguments", "A valid registered server alias is required")
    if not _plugin_enabled(config, plugin_id):
        raise DispatchError("plugin_unavailable", f"{plugin_id.title()} plugin is not installed and enabled")
    server = config.get("servers", {}).get(alias)
    if not isinstance(server, dict) or server.get("plugin") != plugin_id:
        raise DispatchError("unknown_server", f"Unknown {plugin_id.title()} server")
    if client_id is not None:
        client = config.get("clients", {}).get(client_id)
        grants = client.get("grants", {}) if isinstance(client, dict) else {}
        levels = grants.get(alias, {}) if isinstance(grants, dict) else {}
        if isinstance(levels, list):
            levels = {name: "read" for name in levels if isinstance(name, str)}
        granted = levels.get(permission) if isinstance(levels, dict) else None
        if not _grant_allows(granted, required_level):
            raise DispatchError(
                "permission_denied",
                f"Client is not permitted to perform this {required_level}-level {plugin_id.title()} action",
            )
    return alias, server


def _authorized_synology_target(
    config: dict[str, Any], alias: object, permission: str, client_id: str | None
) -> tuple[str, dict[str, Any]]:
    return _authorized_target(config, alias, "synology", permission, "read", client_id)


def _synology_credentials(alias: str) -> tuple[dict[str, Any], Path | None]:
    credential_path = SERVER_SECRETS_DIR / f"{alias}.json"
    try:
        if credential_path.stat().st_mode & 0o137:
            raise OSError("credential permissions are unsafe")
        credentials = _read_object(credential_path)
    except (OSError, DispatchError) as exc:
        raise DispatchError("credentials_unavailable", "Synology credentials are not configured") from exc
    ca_path = SERVER_SECRETS_DIR / f"{alias}.ca.crt"
    return credentials, ca_path if ca_path.is_file() else None


def tool_definitions() -> list[dict[str, Any]]:
    """Return the complete allowlisted MCP tool catalog for this core release."""

    tools = [
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
    config = _read_object(CONFIG_FILE)
    tools.extend(_synology_tools(config))
    tools.extend(_unifi_tools(config))
    return tools


def dispatch_action(
    action: str, arguments: Any, *, client_id: str | None = None
) -> dict[str, Any]:
    """Run one fixed action and return only its declared, sanitized result."""

    if action in {"core.status", "core_status"}:
        if not isinstance(arguments, dict) or arguments:
            raise DispatchError("invalid_arguments", "core.status accepts no arguments")
        # _registry_summary constructs the result from an explicit output allowlist.
        return sanitize_result(_registry_summary())
    permission = SYNOLOGY_ACTIONS.get(action)
    if permission is not None:
        if not isinstance(arguments, dict) or set(arguments) != {"server"}:
            raise DispatchError("invalid_arguments", "Synology actions require only a server alias")
        config = _read_object(CONFIG_FILE)
        alias, server = _authorized_synology_target(config, arguments["server"], permission, client_id)
        credentials, ca_file = _synology_credentials(alias)
        plugin = _load_synology_plugin()
        canonical = action.replace("synology_system_summary", "synology.system.summary").replace(
            "synology_storage_summary", "synology.storage.summary"
        )
        try:
            result = plugin.execute(canonical, server.get("endpoint", ""), credentials, ca_file=ca_file)
        except plugin.PluginError as exc:
            raise DispatchError("upstream_error", str(exc)) from exc
        return sanitize_result(result)
    unifi_access = UNIFI_ACTIONS.get(action)
    if unifi_access is None:
        raise DispatchError("unknown_action", "Unknown LabSteward action")
    required = {
        "unifi.configuration.summary": {"server"},
        "unifi.diagnostics.summary": {"server"},
        "unifi.firewall.rules": {"server"},
        "unifi.clients.list": {"server"},
        "unifi.client.summary": {"server", "client_id"},
        "unifi.firewall.logging.set": {"server", "policy_id", "logging_enabled"},
    }
    canonical = UNIFI_CANONICAL.get(action, action)
    if not isinstance(arguments, dict) or set(arguments) != required[canonical]:
        raise DispatchError("invalid_arguments", "UniFi action arguments do not match its fixed schema")
    permission, required_level = unifi_access
    config = _read_object(CONFIG_FILE)
    alias, server = _authorized_target(
        config, arguments["server"], "unifi", permission, required_level, client_id
    )
    credentials, ca_file = _synology_credentials(alias)
    plugin = _load_plugin("unifi", "0.1.0")
    try:
        result = plugin.execute(
            canonical,
            server.get("endpoint", ""),
            credentials,
            {key: value for key, value in arguments.items() if key != "server"},
            ca_file=ca_file,
        )
    except plugin.PluginError as exc:
        raise DispatchError("upstream_error", str(exc)) from exc
    return sanitize_result(result)
