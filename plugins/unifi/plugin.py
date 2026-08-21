#!/usr/bin/env python3
"""Fixed UniFi Network adapter for LABSteward's official local API surface."""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import ssl
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit

PLUGIN_ID = "unifi"
PLUGIN_VERSION = "0.1.0"
MAX_RESPONSE_BYTES = 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 12
API_PREFIX = "/proxy/network/integration/v1"
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)


class PluginError(Exception):
    """A safe UniFi error that may be returned to a caller."""


def _text(value: object, maximum: int = 120) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = " ".join(value.split())
    return normalized[:maximum] if normalized else None


def _uuid(value: object, label: str) -> str:
    if not isinstance(value, str) or not UUID.fullmatch(value):
        raise PluginError(f"A valid UniFi {label} is required")
    return value.lower()


def _number(value: object, minimum: float = 0, maximum: float = 10**18) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return round(result, 1) if minimum <= result <= maximum else None


def _integer(value: object, maximum: int = 10**18) -> int | None:
    result = _number(value, maximum=maximum)
    return int(result) if result is not None else None


def _bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _page(value: object, maximum: int = 200) -> list[dict[str, Any]]:
    data = value.get("data") if isinstance(value, dict) else None
    if not isinstance(data, list):
        raise PluginError("UniFi Network returned an invalid paginated response")
    return [item for item in data[:maximum] if isinstance(item, dict)]


def _credentials(value: object) -> tuple[str, str]:
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise PluginError("UniFi credentials are not configured")
    api_key = value.get("api_key")
    site_id = value.get("site_id")
    if not isinstance(api_key, str) or not 16 <= len(api_key) <= 2048 or "\x00" in api_key:
        raise PluginError("UniFi credentials are not configured")
    return api_key, _uuid(site_id, "site ID")


class UnifiClient:
    """HTTPS-only client exposing only fixed Network integration API requests."""

    def __init__(self, endpoint: str, api_key: str, *, ca_file: Path | None = None):
        parsed = urlsplit(endpoint)
        try:
            port = parsed.port
        except ValueError as exc:
            raise PluginError("UniFi endpoint is invalid") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise PluginError("UniFi endpoint must be an HTTPS origin")
        try:
            context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        except (OSError, ssl.SSLError) as exc:
            raise PluginError("UniFi TLS trust is unavailable or invalid") from exc
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.connection = http.client.HTTPSConnection(
            parsed.hostname,
            port or 443,
            timeout=REQUEST_TIMEOUT_SECONDS,
            context=context,
        )
        self.api_key = api_key

    def close(self) -> None:
        self.connection.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, object] | None = None,
        body: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        if method not in {"GET", "PATCH"} or not path.startswith("/v1/") or ".." in path:
            raise PluginError("UniFi API request is not allowed")
        target = API_PREFIX + path
        if query:
            target += "?" + urlencode(query)
        encoded = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        headers = {"Accept": "application/json", "X-API-Key": self.api_key}
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        try:
            self.connection.request(method, target, body=encoded, headers=headers)
            response = self.connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise PluginError("Unable to reach the UniFi Network API securely") from exc
        if response.status not in {200, 201} or len(raw) > MAX_RESPONSE_BYTES:
            raise PluginError("UniFi Network rejected the fixed API request")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PluginError("UniFi Network returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise PluginError("UniFi Network returned invalid result data")
        return payload

    def get(self, path: str, *, query: dict[str, object] | None = None) -> dict[str, Any]:
        return self.request("GET", path, query=query)

    def patch(self, path: str, body: dict[str, object]) -> dict[str, Any]:
        return self.request("PATCH", path, body=body)


def _network(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _text(item.get("id"), 64),
        "name": _text(item.get("name"), 120),
        "enabled": _bool(item.get("enabled")),
        "default": _bool(item.get("default")),
        "management": _text(item.get("management"), 32),
        "vlan_id": _integer(item.get("vlanId"), 4009),
    }


def _wifi(item: dict[str, Any]) -> dict[str, Any]:
    network = _dict(item.get("network"))
    security = _dict(item.get("securityConfiguration"))
    return {
        "id": _text(item.get("id"), 64),
        "name": _text(item.get("name"), 120),
        "enabled": _bool(item.get("enabled")),
        "type": _text(item.get("type"), 32),
        "network_id": _text(network.get("id"), 64),
        "security_type": _text(security.get("type"), 64),
    }


def configuration_output(info: object, networks: object, wifi: object) -> dict[str, Any]:
    application = _dict(info)
    return {
        "application_version": _text(
            application.get("applicationVersion", application.get("version")), 64
        ),
        "networks": [_network(item) for item in _page(networks)],
        "wifi_broadcasts": [_wifi(item) for item in _page(wifi)],
    }


def _device(item: dict[str, Any], statistics: dict[str, Any]) -> dict[str, Any]:
    uplink = _dict(statistics.get("uplink"))
    return {
        "id": _text(item.get("id"), 64),
        "name": _text(item.get("name"), 120),
        "model": _text(item.get("model"), 64),
        "state": _text(item.get("state"), 40),
        "firmware_version": _text(item.get("firmwareVersion"), 64),
        "firmware_updatable": _bool(item.get("firmwareUpdatable")),
        "uptime_seconds": _integer(statistics.get("uptimeSec")),
        "cpu_percent": _number(statistics.get("cpuUtilizationPct"), maximum=100),
        "memory_percent": _number(statistics.get("memoryUtilizationPct"), maximum=100),
        "uplink_state": _text(uplink.get("state"), 32),
        "uplink_speed_mbps": _integer(uplink.get("speedMbps"), 10**7),
    }


def diagnostics_output(devices: list[tuple[dict[str, Any], dict[str, Any]]]) -> dict[str, Any]:
    summaries = [_device(device, statistics) for device, statistics in devices[:64]]
    findings: list[dict[str, Any]] = []
    for device in summaries:
        device_id = device["id"]
        if device["state"] != "ONLINE":
            findings.append({
                "severity": "critical" if device["state"] in {"OFFLINE", "ISOLATED"} else "warning",
                "code": "device_not_online",
                "device_id": device_id,
                "message": f"Device state is {device['state'] or 'unknown'}.",
            })
        if device["firmware_updatable"] is True:
            findings.append({
                "severity": "info", "code": "firmware_update_available",
                "device_id": device_id, "message": "A firmware update is available.",
            })
        for field, code, label in (
            ("cpu_percent", "high_cpu", "CPU"),
            ("memory_percent", "high_memory", "memory"),
        ):
            value = device[field]
            if isinstance(value, (int, float)) and value >= 85:
                findings.append({
                    "severity": "warning", "code": code, "device_id": device_id,
                    "message": f"{label} utilization is at least 85 percent.",
                })
    return {
        "status": "critical" if any(item["severity"] == "critical" for item in findings)
        else "warning" if any(item["severity"] == "warning" for item in findings)
        else "healthy",
        "devices": summaries,
        "findings": findings[:128],
    }


def client_output(item: object) -> dict[str, Any]:
    client = _dict(item)
    access = _dict(client.get("access"))
    address = client.get("ipAddress")
    if isinstance(address, str):
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            address = None
    else:
        address = None
    return {
        "id": _text(client.get("id"), 64),
        "name": _text(client.get("name"), 120),
        "type": _text(client.get("type"), 32),
        "connected_at": _text(client.get("connectedAt"), 40),
        "ip_address": address,
        "uplink_device_id": _text(client.get("uplinkDeviceId"), 64),
        "access_type": _text(access.get("type"), 32),
        "authorized": _bool(access.get("authorized")),
    }


def _rule(item: dict[str, Any]) -> dict[str, Any]:
    source = _dict(item.get("source"))
    destination = _dict(item.get("destination"))
    source_filter = _dict(source.get("trafficFilter"))
    destination_filter = _dict(destination.get("trafficFilter"))
    action = _dict(item.get("action"))
    scope = _dict(item.get("ipProtocolScope"))
    metadata = _dict(item.get("metadata"))
    states = item.get("connectionStateFilter")
    return {
        "id": _text(item.get("id"), 64),
        "name": _text(item.get("name"), 120),
        "description": _text(item.get("description"), 240),
        "enabled": _bool(item.get("enabled")),
        "index": _integer(item.get("index"), 10**7),
        "action": _text(action.get("type"), 32),
        "logging_enabled": _bool(item.get("loggingEnabled")),
        "origin": _text(metadata.get("origin"), 32),
        "ip_version": _text(scope.get("ipVersion"), 32),
        "connection_states": [
            value for value in states[:8] if isinstance(value, str) and len(value) <= 32
        ] if isinstance(states, list) else [],
        "source_zone_id": _text(source.get("zoneId"), 64),
        "source_filter_type": _text(source_filter.get("type"), 40),
        "destination_zone_id": _text(destination.get("zoneId"), 64),
        "destination_filter_type": _text(destination_filter.get("type"), 40),
    }


def firewall_output(value: object) -> dict[str, Any]:
    return {"rules": [_rule(item) for item in _page(value)]}


def execute(
    action: str,
    endpoint: str,
    credentials: object,
    arguments: dict[str, object],
    *,
    ca_file: Path | None = None,
    client_factory: Callable[..., UnifiClient] = UnifiClient,
) -> dict[str, Any]:
    """Execute one fixed official Network API action."""

    allowed = {
        "unifi.configuration.summary",
        "unifi.diagnostics.summary",
        "unifi.client.summary",
        "unifi.clients.list",
        "unifi.firewall.rules",
        "unifi.firewall.logging.set",
    }
    if action not in allowed:
        raise PluginError("Unknown UniFi action")
    api_key, site_id = _credentials(credentials)
    client = client_factory(endpoint, api_key, ca_file=ca_file)
    site_path = f"/v1/sites/{site_id}"
    try:
        if action == "unifi.configuration.summary":
            return configuration_output(
                client.get("/v1/info"),
                client.get(f"{site_path}/networks", query={"offset": 0, "limit": 200}),
                client.get(f"{site_path}/wifi/broadcasts", query={"offset": 0, "limit": 200}),
            )
        if action == "unifi.diagnostics.summary":
            overview = _page(
                client.get(f"{site_path}/devices", query={"offset": 0, "limit": 64}),
                maximum=64,
            )
            pairs = [
                (device, client.get(f"{site_path}/devices/{_uuid(device.get('id'), 'device ID')}/statistics/latest"))
                for device in overview
            ]
            return diagnostics_output(pairs)
        if action == "unifi.client.summary":
            client_id = _uuid(arguments.get("client_id"), "client ID")
            return client_output(client.get(f"{site_path}/clients/{client_id}"))
        if action == "unifi.clients.list":
            return {
                "clients": [
                    client_output(item)
                    for item in _page(
                        client.get(f"{site_path}/clients", query={"offset": 0, "limit": 200})
                    )
                ]
            }
        if action == "unifi.firewall.rules":
            return firewall_output(
                client.get(f"{site_path}/firewall/policies", query={"offset": 0, "limit": 200})
            )
        policy_id = _uuid(arguments.get("policy_id"), "firewall policy ID")
        logging_enabled = arguments.get("logging_enabled")
        if not isinstance(logging_enabled, bool):
            raise PluginError("A boolean logging state is required")
        policy_path = f"{site_path}/firewall/policies/{policy_id}"
        current = client.get(policy_path)
        current_summary = _rule(current)
        if current_summary["origin"] != "USER_DEFINED":
            raise PluginError("Only a user-defined UniFi firewall policy may be updated")
        if current_summary["logging_enabled"] is logging_enabled:
            return {"updated": False, "rule": current_summary}
        updated = client.patch(
            policy_path,
            {"loggingEnabled": logging_enabled},
        )
        return {"updated": True, "rule": _rule(updated)}
    finally:
        client.close()


def tool_definitions() -> list[dict[str, Any]]:
    server = {
        "type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$",
    }
    uuid = {
        "type": "string",
        "pattern": "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
    }
    read_annotations = {
        "readOnlyHint": True, "destructiveHint": False,
        "idempotentHint": True, "openWorldHint": False,
    }
    write_annotations = {
        "readOnlyHint": False, "destructiveHint": False,
        "idempotentHint": True, "openWorldHint": False,
    }
    common = {
        "type": "object", "additionalProperties": False,
        "required": ["server"], "properties": {"server": server},
    }
    nullable_string = {"type": ["string", "null"]}
    nullable_integer = {"type": ["integer", "null"]}
    nullable_number = {"type": ["number", "null"]}
    nullable_boolean = {"type": ["boolean", "null"]}
    network_schema = {
        "type": "object", "additionalProperties": False,
        "required": ["id", "name", "enabled", "default", "management", "vlan_id"],
        "properties": {
            "id": nullable_string, "name": nullable_string, "enabled": nullable_boolean,
            "default": nullable_boolean, "management": nullable_string,
            "vlan_id": nullable_integer,
        },
    }
    wifi_schema = {
        "type": "object", "additionalProperties": False,
        "required": ["id", "name", "enabled", "type", "network_id", "security_type"],
        "properties": {
            "id": nullable_string, "name": nullable_string, "enabled": nullable_boolean,
            "type": nullable_string, "network_id": nullable_string,
            "security_type": nullable_string,
        },
    }
    configuration_schema = {
        "type": "object", "additionalProperties": False,
        "required": ["application_version", "networks", "wifi_broadcasts"],
        "properties": {
            "application_version": nullable_string,
            "networks": {"type": "array", "maxItems": 200, "items": network_schema},
            "wifi_broadcasts": {"type": "array", "maxItems": 200, "items": wifi_schema},
        },
    }
    device_schema = {
        "type": "object", "additionalProperties": False,
        "required": [
            "id", "name", "model", "state", "firmware_version", "firmware_updatable",
            "uptime_seconds", "cpu_percent", "memory_percent", "uplink_state",
            "uplink_speed_mbps",
        ],
        "properties": {
            "id": nullable_string, "name": nullable_string, "model": nullable_string,
            "state": nullable_string, "firmware_version": nullable_string,
            "firmware_updatable": nullable_boolean, "uptime_seconds": nullable_integer,
            "cpu_percent": nullable_number, "memory_percent": nullable_number,
            "uplink_state": nullable_string, "uplink_speed_mbps": nullable_integer,
        },
    }
    finding_schema = {
        "type": "object", "additionalProperties": False,
        "required": ["severity", "code", "device_id", "message"],
        "properties": {
            "severity": {"enum": ["info", "warning", "critical"]},
            "code": {"type": "string"}, "device_id": nullable_string,
            "message": {"type": "string"},
        },
    }
    diagnostics_schema = {
        "type": "object", "additionalProperties": False,
        "required": ["status", "devices", "findings"],
        "properties": {
            "status": {"enum": ["healthy", "warning", "critical"]},
            "devices": {"type": "array", "maxItems": 64, "items": device_schema},
            "findings": {"type": "array", "maxItems": 128, "items": finding_schema},
        },
    }
    client_schema = {
        "type": "object", "additionalProperties": False,
        "required": [
            "id", "name", "type", "connected_at", "ip_address", "uplink_device_id",
            "access_type", "authorized",
        ],
        "properties": {
            "id": nullable_string, "name": nullable_string, "type": nullable_string,
            "connected_at": nullable_string, "ip_address": nullable_string,
            "uplink_device_id": nullable_string, "access_type": nullable_string,
            "authorized": nullable_boolean,
        },
    }
    clients_schema = {
        "type": "object", "additionalProperties": False,
        "required": ["clients"],
        "properties": {
            "clients": {"type": "array", "maxItems": 200, "items": client_schema},
        },
    }
    rule_schema = {
        "type": "object", "additionalProperties": False,
        "required": [
            "id", "name", "description", "enabled", "index", "action",
            "logging_enabled", "origin", "ip_version", "connection_states",
            "source_zone_id", "source_filter_type", "destination_zone_id",
            "destination_filter_type",
        ],
        "properties": {
            "id": nullable_string, "name": nullable_string, "description": nullable_string,
            "enabled": nullable_boolean, "index": nullable_integer, "action": nullable_string,
            "logging_enabled": nullable_boolean, "origin": nullable_string,
            "ip_version": nullable_string,
            "connection_states": {"type": "array", "maxItems": 8, "items": {"type": "string"}},
            "source_zone_id": nullable_string, "source_filter_type": nullable_string,
            "destination_zone_id": nullable_string,
            "destination_filter_type": nullable_string,
        },
    }
    firewall_schema = {
        "type": "object", "additionalProperties": False,
        "required": ["rules"],
        "properties": {"rules": {"type": "array", "maxItems": 200, "items": rule_schema}},
    }
    output_schemas = {
        "unifi_configuration_summary": configuration_schema,
        "unifi_diagnostics_summary": diagnostics_schema,
        "unifi_clients_list": clients_schema,
        "unifi_firewall_rules": firewall_schema,
    }
    tools = []
    for name, title, description in (
        ("unifi_configuration_summary", "UniFi configuration summary", "Read sanitized network and WiFi configuration summaries."),
        ("unifi_diagnostics_summary", "UniFi diagnostic summary", "Diagnose bounded device state, firmware, CPU, memory, and uplink findings."),
        ("unifi_clients_list", "UniFi connected clients", "List bounded current client connection and access summaries for client-ID discovery."),
        ("unifi_firewall_rules", "UniFi firewall rules", "Read sanitized firewall policy summaries without raw filter payloads."),
    ):
        tools.append({
            "name": name, "title": title, "description": description,
            "inputSchema": common, "outputSchema": output_schemas[name],
            "annotations": read_annotations,
        })
    tools.append({
        "name": "unifi_client_summary",
        "title": "UniFi connected client summary",
        "description": "Read current connection and access context for one connected client; historical traffic totals are not available.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "required": ["server", "client_id"],
            "properties": {"server": server, "client_id": uuid},
        },
        "outputSchema": client_schema,
        "annotations": read_annotations,
    })
    tools.append({
        "name": "unifi_firewall_logging_set",
        "title": "Set UniFi firewall policy logging",
        "description": "Enable or disable syslog logging on one explicit firewall policy using the official partial-update endpoint.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "required": ["server", "policy_id", "logging_enabled"],
            "properties": {
                "server": server, "policy_id": uuid, "logging_enabled": {"type": "boolean"},
            },
        },
        "outputSchema": {
            "type": "object", "additionalProperties": False,
            "required": ["updated", "rule"],
            "properties": {"updated": {"type": "boolean"}, "rule": rule_schema},
        },
        "annotations": write_annotations,
    })
    return tools
