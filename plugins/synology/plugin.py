#!/usr/bin/env python3
"""Fixed, read-only Synology DSM adapter for LABSteward."""

from __future__ import annotations

import http.client
import json
import re
import ssl
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit

PLUGIN_ID = "synology"
PLUGIN_VERSION = "0.1.0"
MAX_RESPONSE_BYTES = 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 12
SAFE_API_PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.cgi$")
SYSTEM_APIS = ("SYNO.API.Auth", "SYNO.Core.System", "SYNO.Core.System.Utilization")
STORAGE_APIS = ("SYNO.API.Auth", "SYNO.Storage.CGI.Storage")


class PluginError(Exception):
    """A safe Synology error that may be returned to a caller."""


def _bounded_text(value: object, *, maximum: int = 120) -> str | None:
    if not isinstance(value, str):
        return None
    value = " ".join(value.split())
    return value[:maximum] if value else None


def _number(value: object, *, minimum: float = 0, maximum: float = 10**18) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if minimum <= result <= maximum else None


def _integer(value: object, *, maximum: int = 10**18) -> int | None:
    result = _number(value, maximum=maximum)
    return int(result) if result is not None else None


def _percent(value: object) -> float | None:
    result = _number(value, maximum=100)
    return round(result, 1) if result is not None else None


def _first(mapping: object, *names: str) -> object:
    if not isinstance(mapping, dict):
        return None
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def _size(mapping: object, *names: str) -> int | None:
    direct = _first(mapping, *names)
    value = _integer(direct)
    if value is not None:
        return value
    nested = mapping.get("size") if isinstance(mapping, dict) else None
    aliases = {
        "total": ("total", "total_size", "size_total"),
        "used": ("used", "used_size", "size_used"),
    }
    for label, candidates in aliases.items():
        if any(name in names for name in candidates):
            return _integer(_first(nested, label, *candidates))
    return None


def _usage_percent(total: int | None, used: int | None, explicit: object = None) -> float | None:
    value = _percent(explicit)
    if value is not None:
        return value
    if total and used is not None and used <= total:
        return round((used / total) * 100, 1)
    return None


def _health(value: object) -> str:
    normalized = str(value or "").lower()
    if normalized in {"normal", "healthy", "optimal", "good", "1"}:
        return "healthy"
    if normalized in {"warning", "attention", "degraded", "repairing", "2"}:
        return "warning"
    if normalized in {"critical", "crashed", "failed", "error", "3", "4"}:
        return "critical"
    return "unknown"


def _api_path(record: object) -> str:
    path = record.get("path") if isinstance(record, dict) else None
    if not isinstance(path, str) or not SAFE_API_PATH.fullmatch(path) or ".." in path:
        raise PluginError("DSM advertised an unsafe API path")
    return f"/webapi/{path}"


def _api_version(record: object, *, maximum: int) -> int:
    if not isinstance(record, dict):
        raise PluginError("Required DSM API is unavailable")
    minimum = record.get("minVersion")
    supported = record.get("maxVersion")
    if not isinstance(minimum, int) or not isinstance(supported, int):
        raise PluginError("DSM advertised invalid API version metadata")
    selected = min(maximum, supported)
    if selected < minimum:
        raise PluginError("Required DSM API version is unavailable")
    return selected


class DsmClient:
    """HTTPS-only client exposing only the fixed DSM calls used by this plugin."""

    def __init__(self, endpoint: str, *, ca_file: Path | None = None):
        parsed = urlsplit(endpoint)
        try:
            port = parsed.port
        except ValueError as exc:
            raise PluginError("Synology endpoint is invalid") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise PluginError("Synology endpoint must be an HTTPS origin")
        try:
            context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        except (OSError, ssl.SSLError) as exc:
            raise PluginError("Synology TLS trust is unavailable or invalid") from exc
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.connection = http.client.HTTPSConnection(
            parsed.hostname,
            port or 443,
            timeout=REQUEST_TIMEOUT_SECONDS,
            context=context,
        )

    def close(self) -> None:
        self.connection.close()

    def request(self, path: str, parameters: dict[str, object]) -> dict[str, Any]:
        if not path.startswith("/webapi/") or ".." in path:
            raise PluginError("DSM API path is not allowed")
        body = urlencode(parameters)
        try:
            self.connection.request(
                "POST",
                path,
                body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response = self.connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise PluginError("Unable to reach the Synology DSM API securely") from exc
        if response.status != 200 or len(raw) > MAX_RESPONSE_BYTES:
            raise PluginError("Synology DSM returned an invalid response")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PluginError("Synology DSM returned invalid JSON") from exc
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise PluginError("Synology DSM rejected the read-only request")
        data = payload.get("data", {})
        if not isinstance(data, dict):
            raise PluginError("Synology DSM returned invalid result data")
        return data

    def api_info(self, names: tuple[str, ...]) -> dict[str, Any]:
        return self.request(
            "/webapi/entry.cgi",
            {"api": "SYNO.API.Info", "version": 1, "method": "query", "query": ",".join(names)},
        )

    def login(self, api: object, username: str, password: str) -> tuple[str, str | None]:
        data = self.request(
            _api_path(api),
            {
                "api": "SYNO.API.Auth",
                "version": _api_version(api, maximum=6),
                "method": "login",
                "account": username,
                "passwd": password,
                "session": "LABSteward",
                "format": "sid",
                "enable_syno_token": "yes",
            },
        )
        sid = data.get("sid")
        synotoken = data.get("synotoken")
        if not isinstance(sid, str) or not sid or len(sid) > 512:
            raise PluginError("Synology DSM login did not return a valid session")
        return sid, synotoken if isinstance(synotoken, str) and len(synotoken) <= 512 else None

    def logout(self, api: object, sid: str, synotoken: str | None) -> None:
        parameters: dict[str, object] = {
            "api": "SYNO.API.Auth",
            "version": _api_version(api, maximum=6),
            "method": "logout",
            "session": "LABSteward",
            "_sid": sid,
        }
        if synotoken:
            parameters["SynoToken"] = synotoken
        try:
            self.request(_api_path(api), parameters)
        except PluginError:
            pass

    def call(
        self,
        api_name: str,
        api: object,
        method: str,
        sid: str,
        synotoken: str | None,
        *,
        maximum_version: int,
        parameters: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        values: dict[str, object] = {
            "api": api_name,
            "version": _api_version(api, maximum=maximum_version),
            "method": method,
            "_sid": sid,
        }
        if synotoken:
            values["SynoToken"] = synotoken
        if parameters:
            values.update(parameters)
        return self.request(_api_path(api), values)


def _credentials(value: object) -> tuple[str, str]:
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise PluginError("Synology credentials are not configured")
    username = value.get("username")
    password = value.get("password")
    if not isinstance(username, str) or not username or len(username) > 128:
        raise PluginError("Synology credentials are not configured")
    if not isinstance(password, str) or not password or len(password) > 1024:
        raise PluginError("Synology credentials are not configured")
    return username, password


def _cpu_percent(utilization: object) -> float | None:
    cpu = utilization.get("cpu") if isinstance(utilization, dict) else None
    explicit = _first(cpu, "total_load", "usage", "load")
    result = _percent(explicit)
    if result is not None:
        return result
    if isinstance(cpu, dict):
        parts = [_number(cpu.get(name), maximum=100) for name in ("user_load", "system_load", "other_load")]
        if all(item is not None for item in parts):
            return round(min(100.0, sum(item for item in parts if item is not None)), 1)
    return None


def _memory_percent(utilization: object) -> float | None:
    memory = utilization.get("memory") if isinstance(utilization, dict) else None
    explicit = _first(memory, "real_usage", "usage", "used_percent")
    result = _percent(explicit)
    if result is not None:
        return result
    total = _number(_first(memory, "total_real", "total"))
    available = _number(_first(memory, "avail_real", "available"))
    if total and available is not None and available <= total:
        return round(((total - available) / total) * 100, 1)
    return None


def system_output(system: object, utilization: object) -> dict[str, Any]:
    warning = _first(system, "sys_tempwarn", "temperature_warning") is True
    return {
        "status": "warning" if warning else _health(_first(system, "status", "health", "system_status")),
        "model": _bounded_text(_first(system, "model", "model_name")),
        "dsm_version": _bounded_text(_first(system, "firmware_ver", "version_string", "dsm_version")),
        "uptime_seconds": _integer(_first(system, "up_time", "uptime")),
        "temperature_c": _number(_first(system, "sys_temp", "temperature"), maximum=150),
        "cpu_percent": _cpu_percent(utilization),
        "memory_percent": _memory_percent(utilization),
    }


def _storage_item(item: object) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    total = _size(item, "total_size", "size_total", "total")
    used = _size(item, "used_size", "size_used", "used")
    return {
        "id": _bounded_text(_first(item, "id", "volume_id", "pool_id"), maximum=64),
        "status": _health(_first(item, "status", "health")),
        "raid_type": _bounded_text(_first(item, "raidType", "raid_type", "type"), maximum=64),
        "size_total_bytes": total,
        "size_used_bytes": used,
        "usage_percent": _usage_percent(total, used, _first(item, "used_percent", "usage")),
    }


def storage_output(data: object) -> dict[str, Any]:
    pools_raw = _first(data, "storagePools", "storage_pools", "pools")
    volumes_raw = _first(data, "volumes", "volume")
    disks_raw = _first(data, "disks", "disk")
    pools = [value for item in pools_raw if (value := _storage_item(item)) is not None] if isinstance(pools_raw, list) else []
    volumes = [value for item in volumes_raw if (value := _storage_item(item)) is not None] if isinstance(volumes_raw, list) else []
    disks = disks_raw if isinstance(disks_raw, list) else []
    states = [_health(_first(item, "status", "health")) for item in disks if isinstance(item, dict)]
    return {
        "pools": pools[:32],
        "volumes": volumes[:64],
        "disks": {
            "total": min(len(disks), 256),
            "healthy": sum(state == "healthy" for state in states[:256]),
            "warning": sum(state in {"warning", "critical"} for state in states[:256]),
        },
    }


def execute(
    action: str,
    endpoint: str,
    credentials: object,
    *,
    ca_file: Path | None = None,
    client_factory: Callable[..., DsmClient] = DsmClient,
) -> dict[str, Any]:
    """Execute one fixed read-only action and return only allowlisted fields."""

    if action not in {"synology.system.summary", "synology.storage.summary"}:
        raise PluginError("Unknown Synology action")
    username, password = _credentials(credentials)
    client = client_factory(endpoint, ca_file=ca_file)
    sid = ""
    synotoken: str | None = None
    auth_api: object = None
    try:
        names = SYSTEM_APIS if action == "synology.system.summary" else STORAGE_APIS
        info = client.api_info(names)
        auth_api = info.get("SYNO.API.Auth")
        sid, synotoken = client.login(auth_api, username, password)
        if action == "synology.system.summary":
            system = client.call(
                "SYNO.Core.System", info.get("SYNO.Core.System"), "info", sid, synotoken,
                maximum_version=3,
            )
            utilization = client.call(
                "SYNO.Core.System.Utilization",
                info.get("SYNO.Core.System.Utilization"),
                "get",
                sid,
                synotoken,
                maximum_version=1,
            )
            return system_output(system, utilization)
        storage = client.call(
            "SYNO.Storage.CGI.Storage",
            info.get("SYNO.Storage.CGI.Storage"),
            "load_info",
            sid,
            synotoken,
            maximum_version=1,
        )
        return storage_output(storage)
    finally:
        if sid and auth_api is not None:
            client.logout(auth_api, sid, synotoken)
        client.close()


def tool_definitions() -> list[dict[str, Any]]:
    annotations = {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    server_input = {
        "type": "object",
        "additionalProperties": False,
        "required": ["server"],
        "properties": {"server": {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$"}},
    }
    nullable_number = {"type": ["number", "null"]}
    nullable_integer = {"type": ["integer", "null"]}
    nullable_string = {"type": ["string", "null"]}
    health = {"enum": ["healthy", "warning", "critical", "unknown"]}
    system_output_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "status", "model", "dsm_version", "uptime_seconds", "temperature_c",
            "cpu_percent", "memory_percent",
        ],
        "properties": {
            "status": health,
            "model": nullable_string,
            "dsm_version": nullable_string,
            "uptime_seconds": nullable_integer,
            "temperature_c": nullable_number,
            "cpu_percent": nullable_number,
            "memory_percent": nullable_number,
        },
    }
    storage_item_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "id", "status", "raid_type", "size_total_bytes", "size_used_bytes",
            "usage_percent",
        ],
        "properties": {
            "id": nullable_string,
            "status": health,
            "raid_type": nullable_string,
            "size_total_bytes": nullable_integer,
            "size_used_bytes": nullable_integer,
            "usage_percent": nullable_number,
        },
    }
    storage_output_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["pools", "volumes", "disks"],
        "properties": {
            "pools": {"type": "array", "maxItems": 32, "items": storage_item_schema},
            "volumes": {"type": "array", "maxItems": 64, "items": storage_item_schema},
            "disks": {
                "type": "object",
                "additionalProperties": False,
                "required": ["total", "healthy", "warning"],
                "properties": {
                    "total": {"type": "integer", "minimum": 0, "maximum": 256},
                    "healthy": {"type": "integer", "minimum": 0, "maximum": 256},
                    "warning": {"type": "integer", "minimum": 0, "maximum": 256},
                },
            },
        },
    }
    return [
        {
            "name": "synology_system_summary",
            "title": "Synology system summary",
            "description": "Read sanitized DSM health and resource utilization for one assigned Synology server.",
            "inputSchema": server_input,
            "outputSchema": system_output_schema,
            "annotations": annotations,
        },
        {
            "name": "synology_storage_summary",
            "title": "Synology storage summary",
            "description": "Read sanitized storage pool, volume, capacity, and aggregate disk health for one assigned Synology server.",
            "inputSchema": server_input,
            "outputSchema": storage_output_schema,
            "annotations": annotations,
        },
    ]
