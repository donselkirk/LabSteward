#!/usr/bin/env python3
"""Bounded, read-only Proxmox VE API adapter for LabSteward."""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

PLUGIN_ID = "proxmox"
PLUGIN_VERSION = "0.1.0"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_GUESTS = 256
MAX_STORAGES = 64
MAX_TASKS = 100
NODE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TOKEN_ID = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$")


class PluginError(Exception):
    """A safe upstream error suitable for returning through the core."""


def _number(value: object) -> float | int | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _integer(value: object) -> int | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _text(value: object, limit: int = 160) -> str | None:
    if not isinstance(value, str):
        return None
    value = " ".join(value.split())
    return value[:limit] or None


def _boolean(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    return None


def _percent(used: object, total: object) -> float | None:
    used_number, total_number = _number(used), _number(total)
    if used_number is None or total_number in (None, 0):
        return None
    return round(float(used_number) * 100.0 / float(total_number), 1)


class ProxmoxClient:
    """HTTPS client limited to fixed GET requests below one API origin."""

    def __init__(self, endpoint: str, token_id: str, token_secret: str, ca_file: Path | None):
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise PluginError("Proxmox endpoint must be an HTTPS origin")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise PluginError("Proxmox endpoint must not contain a path, query, or fragment")
        self.base = urllib.parse.urlunsplit(("https", parsed.netloc, "", "", "")).rstrip("/")
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        self.authorization = f"PVEAPIToken={token_id}={token_secret}"

    def get(self, path: str, query: dict[str, object] | None = None) -> object:
        if not path.startswith("/api2/json/") or ".." in path:
            raise PluginError("Proxmox plugin rejected an invalid fixed API path")
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(
            url, method="GET", headers={"Authorization": self.authorization, "Accept": "application/json"}
        )
        try:
            with self.opener.open(request, timeout=12) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            raise PluginError("Proxmox API request failed") from exc
        if len(body) > MAX_RESPONSE_BYTES:
            raise PluginError("Proxmox API response exceeded the safe size limit")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PluginError("Proxmox API returned an invalid response") from exc
        if not isinstance(payload, dict) or "data" not in payload:
            raise PluginError("Proxmox API returned an unexpected response")
        return payload["data"]


def _credentials(credentials: object) -> tuple[str, str, str]:
    if not isinstance(credentials, dict) or credentials.get("schema") != 1:
        raise PluginError("Proxmox credentials are unavailable")
    token_id = credentials.get("token_id")
    token_secret = credentials.get("token_secret")
    node = credentials.get("node")
    if not isinstance(token_id, str) or not TOKEN_ID.fullmatch(token_id):
        raise PluginError("Proxmox API token ID is invalid")
    if not isinstance(token_secret, str) or not 8 <= len(token_secret) <= 2048 or "\x00" in token_secret:
        raise PluginError("Proxmox API token secret is invalid")
    if not isinstance(node, str) or not NODE_NAME.fullmatch(node):
        raise PluginError("Proxmox node name is invalid")
    return token_id, token_secret, node


def _node_summary(version: object, status: object, node: str) -> dict[str, Any]:
    version_data = version if isinstance(version, dict) else {}
    current = status if isinstance(status, dict) else {}
    memory = current.get("memory") if isinstance(current.get("memory"), dict) else {}
    rootfs = current.get("rootfs") if isinstance(current.get("rootfs"), dict) else {}
    return {
        "node": node,
        "status": _text(current.get("status"), 32),
        "pve_version": _text(version_data.get("version"), 64),
        "release": _text(version_data.get("release"), 64),
        "kernel_version": _text(current.get("kversion"), 128),
        "uptime_seconds": _integer(current.get("uptime")),
        "cpu_percent": round(float(current["cpu"]) * 100, 1) if _number(current.get("cpu")) is not None else None,
        "cpu_count": _integer(current.get("cpuinfo", {}).get("cpus")) if isinstance(current.get("cpuinfo"), dict) else None,
        "load_average": [_text(item, 24) for item in current.get("loadavg", [])[:3]] if isinstance(current.get("loadavg"), list) else [],
        "memory_used_bytes": _integer(memory.get("used")),
        "memory_total_bytes": _integer(memory.get("total")),
        "memory_percent": _percent(memory.get("used"), memory.get("total")),
        "root_used_bytes": _integer(rootfs.get("used")),
        "root_total_bytes": _integer(rootfs.get("total")),
        "root_percent": _percent(rootfs.get("used"), rootfs.get("total")),
    }


def _guest_item(item: object, kind: str, node: str) -> dict[str, Any] | None:
    if not isinstance(item, dict) or _integer(item.get("vmid")) is None:
        return None
    return {
        "node": node,
        "guest_id": _integer(item.get("vmid")),
        "kind": kind,
        "name": _text(item.get("name"), 96),
        "status": _text(item.get("status"), 32),
        "locked": bool(item.get("lock")) if item.get("lock") is not None else False,
        "uptime_seconds": _integer(item.get("uptime")),
        "cpu_percent": round(float(item["cpu"]) * 100, 1) if _number(item.get("cpu")) is not None else None,
        "cpu_count": _integer(item.get("cpus")),
        "memory_used_bytes": _integer(item.get("mem")),
        "memory_total_bytes": _integer(item.get("maxmem")),
        "memory_percent": _percent(item.get("mem"), item.get("maxmem")),
        "disk_used_bytes": _integer(item.get("disk")),
        "disk_total_bytes": _integer(item.get("maxdisk")),
        "disk_percent": _percent(item.get("disk"), item.get("maxdisk")),
    }


def _guest_config(config: object) -> dict[str, Any]:
    value = config if isinstance(config, dict) else {}
    return {
        "on_boot": _boolean(value.get("onboot")),
        "cpu_count": _integer(value.get("cores")),
        "memory_mib": _integer(value.get("memory")),
        "swap_mib": _integer(value.get("swap")),
        "architecture": _text(value.get("arch"), 32),
        "operating_system_type": _text(value.get("ostype"), 48),
        "unprivileged": _boolean(value.get("unprivileged")),
        "protection": _boolean(value.get("protection")),
        "startup_order": _text(value.get("startup"), 80),
        "description_present": bool(value.get("description")),
        "mount_point_count": sum(1 for key in value if re.fullmatch(r"mp\d+", str(key))),
        "network_device_count": sum(1 for key in value if re.fullmatch(r"net\d+", str(key))),
    }


def _storage_item(item: object) -> dict[str, Any] | None:
    if not isinstance(item, dict) or not isinstance(item.get("storage"), str):
        return None
    content = item.get("content")
    content_types = sorted(part.strip() for part in content.split(",") if part.strip())[:16] if isinstance(content, str) else []
    return {
        "id": _text(item.get("storage"), 64),
        "type": _text(item.get("type"), 32),
        "active": _boolean(item.get("active")),
        "enabled": _boolean(item.get("enabled")),
        "shared": _boolean(item.get("shared")),
        "content_types": content_types,
        "used_bytes": _integer(item.get("used")),
        "available_bytes": _integer(item.get("avail")),
        "total_bytes": _integer(item.get("total")),
        "used_percent": _percent(item.get("used"), item.get("total")),
    }


def _task_item(item: object) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    return {
        "type": _text(item.get("type"), 64),
        "guest_id": _integer(item.get("id")),
        "start_time": _integer(item.get("starttime")),
        "end_time": _integer(item.get("endtime")),
        "status": _text(item.get("status"), 96),
    }


def _finding(severity: str, code: str, scope: str, message: str) -> dict[str, str]:
    return {"severity": severity, "code": code, "scope": scope, "message": message}


def _resource_findings(scope: str, item: dict[str, Any]) -> list[dict[str, str]]:
    findings = []
    for field, label in (("cpu_percent", "CPU"), ("memory_percent", "memory"), ("disk_percent", "disk"), ("root_percent", "root filesystem")):
        value = item.get(field)
        if isinstance(value, (int, float)) and value >= 90:
            findings.append(_finding("critical", f"{field}.critical", scope, f"{label} utilization is at least 90%."))
        elif isinstance(value, (int, float)) and value >= 80:
            findings.append(_finding("warning", f"{field}.high", scope, f"{label} utilization is at least 80%."))
    if item.get("locked") is True:
        findings.append(_finding("warning", "guest.locked", scope, "The guest has an active configuration lock."))
    return findings


def _status(findings: list[dict[str, str]]) -> str:
    severities = {item["severity"] for item in findings}
    return "critical" if "critical" in severities else "warning" if "warning" in severities else "healthy"


def _guest_kind(value: object) -> str:
    if value not in {"lxc", "qemu"}:
        raise PluginError("Guest kind must be lxc or qemu")
    return str(value)


def _guest_id(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 100 <= value <= 999999999:
        raise PluginError("Guest ID is invalid")
    return value


def _all_guests(client: ProxmoxClient, node: str) -> list[dict[str, Any]]:
    results = []
    for kind in ("lxc", "qemu"):
        raw = client.get(f"/api2/json/nodes/{urllib.parse.quote(node, safe='')}/{kind}")
        if not isinstance(raw, list):
            raise PluginError("Proxmox API returned an invalid guest list")
        for item in raw[:MAX_GUESTS]:
            summary = _guest_item(item, kind, node)
            if summary is not None:
                results.append(summary)
    return sorted(results, key=lambda item: (item["guest_id"], item["kind"]))[:MAX_GUESTS]


def execute(
    action: str, endpoint: str, credentials: object, arguments: object | None = None,
    *, ca_file: Path | None = None, client_factory: object = ProxmoxClient,
) -> dict[str, Any]:
    allowed = {
        "proxmox.node.summary", "proxmox.guests.list", "proxmox.guest.summary",
        "proxmox.node.diagnostics", "proxmox.guest.diagnostics",
        "proxmox.storage.summary", "proxmox.tasks.recent",
    }
    if action not in allowed:
        raise PluginError("Unknown Proxmox action")
    token_id, token_secret, node = _credentials(credentials)
    args = arguments if isinstance(arguments, dict) else {}
    client = client_factory(endpoint, token_id, token_secret, ca_file)
    node_path = f"/api2/json/nodes/{urllib.parse.quote(node, safe='')}"
    if action == "proxmox.node.summary":
        return _node_summary(client.get("/api2/json/version"), client.get(f"{node_path}/status"), node)
    if action == "proxmox.guests.list":
        return {"guests": _all_guests(client, node)}
    if action in {"proxmox.guest.summary", "proxmox.guest.diagnostics"}:
        kind, guest_id = _guest_kind(args.get("kind")), _guest_id(args.get("guest_id"))
        guest_path = f"{node_path}/{kind}/{guest_id}"
        current = client.get(f"{guest_path}/status/current")
        config = client.get(f"{guest_path}/config")
        guest = _guest_item(current, kind, node)
        if guest is None:
            raise PluginError("Proxmox API returned an invalid guest summary")
        guest["configuration"] = _guest_config(config)
        if action == "proxmox.guest.summary":
            return guest
        findings = _resource_findings(f"{kind}/{guest_id}", guest)
        if guest.get("status") not in {"running", "stopped"}:
            findings.append(_finding("warning", "guest.state.unexpected", f"{kind}/{guest_id}", "The guest is in an unexpected state."))
        return {"status": _status(findings), "guest": guest, "findings": findings[:64]}
    if action == "proxmox.storage.summary":
        raw = client.get(f"{node_path}/storage")
        if not isinstance(raw, list):
            raise PluginError("Proxmox API returned an invalid storage list")
        return {"storage": [value for item in raw[:MAX_STORAGES] if (value := _storage_item(item)) is not None]}
    if action == "proxmox.tasks.recent":
        raw = client.get(f"{node_path}/tasks", {"limit": MAX_TASKS})
        if not isinstance(raw, list):
            raise PluginError("Proxmox API returned an invalid task list")
        return {"tasks": [value for item in raw[:MAX_TASKS] if (value := _task_item(item)) is not None]}
    version = client.get("/api2/json/version")
    current = client.get(f"{node_path}/status")
    node_summary = _node_summary(version, current, node)
    guests = _all_guests(client, node)
    raw_storage = client.get(f"{node_path}/storage")
    raw_tasks = client.get(f"{node_path}/tasks", {"limit": MAX_TASKS})
    storage = [value for item in raw_storage[:MAX_STORAGES] if (value := _storage_item(item)) is not None] if isinstance(raw_storage, list) else []
    tasks = [value for item in raw_tasks[:MAX_TASKS] if (value := _task_item(item)) is not None] if isinstance(raw_tasks, list) else []
    findings = _resource_findings(node, node_summary)
    for item in storage:
        if item.get("active") is False or item.get("enabled") is False:
            findings.append(_finding("critical", "storage.unavailable", str(item.get("id")), "Storage is inactive or disabled."))
        findings.extend(_resource_findings(str(item.get("id")), {"disk_percent": item.get("used_percent")}))
    for item in tasks:
        status = item.get("status")
        if status and status != "OK":
            findings.append(_finding("warning", "task.failed", str(item.get("type") or "task"), "A recent task did not complete successfully."))
    for item in guests:
        findings.extend(_resource_findings(f"{item['kind']}/{item['guest_id']}", item))
    return {
        "status": _status(findings), "node": node_summary,
        "guest_count": len(guests), "storage_count": len(storage),
        "recent_task_count": len(tasks), "findings": findings[:128],
    }


def tool_definitions() -> list[dict[str, Any]]:
    server = {"type": "string", "pattern": "^[a-z][a-z0-9._-]{0,63}$", "maxLength": 64}
    guest_id = {"type": "integer", "minimum": 100, "maximum": 999999999}
    kind = {"enum": ["lxc", "qemu"]}
    common = {"type": "object", "additionalProperties": False, "required": ["server"], "properties": {"server": server}}
    guest_input = {"type": "object", "additionalProperties": False, "required": ["server", "kind", "guest_id"], "properties": {"server": server, "kind": kind, "guest_id": guest_id}}
    nullable_string = {"type": ["string", "null"]}
    nullable_integer = {"type": ["integer", "null"]}
    nullable_number = {"type": ["number", "null"]}
    nullable_boolean = {"type": ["boolean", "null"]}
    guest_properties = {
        "node": {"type": "string"}, "guest_id": {"type": "integer"}, "kind": kind,
        "name": nullable_string, "status": nullable_string, "locked": {"type": "boolean"},
        "uptime_seconds": nullable_integer, "cpu_percent": nullable_number,
        "cpu_count": nullable_integer, "memory_used_bytes": nullable_integer,
        "memory_total_bytes": nullable_integer, "memory_percent": nullable_number,
        "disk_used_bytes": nullable_integer, "disk_total_bytes": nullable_integer,
        "disk_percent": nullable_number,
    }
    guest_required = list(guest_properties)
    guest_schema = {"type": "object", "additionalProperties": False, "required": guest_required, "properties": guest_properties}
    configuration_schema = {
        "type": "object", "additionalProperties": False,
        "required": ["on_boot", "cpu_count", "memory_mib", "swap_mib", "architecture", "operating_system_type", "unprivileged", "protection", "startup_order", "description_present", "mount_point_count", "network_device_count"],
        "properties": {"on_boot": nullable_boolean, "cpu_count": nullable_integer, "memory_mib": nullable_integer, "swap_mib": nullable_integer, "architecture": nullable_string, "operating_system_type": nullable_string, "unprivileged": nullable_boolean, "protection": nullable_boolean, "startup_order": nullable_string, "description_present": {"type": "boolean"}, "mount_point_count": {"type": "integer"}, "network_device_count": {"type": "integer"}},
    }
    detailed_guest_properties = dict(guest_properties)
    detailed_guest_properties["configuration"] = configuration_schema
    detailed_guest = {"type": "object", "additionalProperties": False, "required": guest_required + ["configuration"], "properties": detailed_guest_properties}
    node_properties = {"node": {"type": "string"}, "status": nullable_string, "pve_version": nullable_string, "release": nullable_string, "kernel_version": nullable_string, "uptime_seconds": nullable_integer, "cpu_percent": nullable_number, "cpu_count": nullable_integer, "load_average": {"type": "array", "maxItems": 3, "items": nullable_string}, "memory_used_bytes": nullable_integer, "memory_total_bytes": nullable_integer, "memory_percent": nullable_number, "root_used_bytes": nullable_integer, "root_total_bytes": nullable_integer, "root_percent": nullable_number}
    node_schema = {"type": "object", "additionalProperties": False, "required": list(node_properties), "properties": node_properties}
    finding_schema = {"type": "object", "additionalProperties": False, "required": ["severity", "code", "scope", "message"], "properties": {"severity": {"enum": ["info", "warning", "critical"]}, "code": {"type": "string"}, "scope": {"type": "string"}, "message": {"type": "string"}}}
    storage_properties = {"id": nullable_string, "type": nullable_string, "active": nullable_boolean, "enabled": nullable_boolean, "shared": nullable_boolean, "content_types": {"type": "array", "maxItems": 16, "items": {"type": "string"}}, "used_bytes": nullable_integer, "available_bytes": nullable_integer, "total_bytes": nullable_integer, "used_percent": nullable_number}
    storage_schema = {"type": "object", "additionalProperties": False, "required": list(storage_properties), "properties": storage_properties}
    task_properties = {"type": nullable_string, "guest_id": nullable_integer, "start_time": nullable_integer, "end_time": nullable_integer, "status": nullable_string}
    task_schema = {"type": "object", "additionalProperties": False, "required": list(task_properties), "properties": task_properties}
    read_annotations = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
    tools = [
        ("proxmox_node_summary", "Proxmox node summary", "Read bounded node version, health, and utilization.", common, node_schema),
        ("proxmox_guests_list", "Proxmox guests", "List sanitized LXC and virtual-machine state and utilization.", common, {"type": "object", "additionalProperties": False, "required": ["guests"], "properties": {"guests": {"type": "array", "maxItems": MAX_GUESTS, "items": guest_schema}}}),
        ("proxmox_guest_summary", "Proxmox guest summary", "Read sanitized state and configuration counts for one LXC or virtual machine.", guest_input, detailed_guest),
        ("proxmox_storage_summary", "Proxmox storage summary", "Read storage state and capacity without paths or credentials.", common, {"type": "object", "additionalProperties": False, "required": ["storage"], "properties": {"storage": {"type": "array", "maxItems": MAX_STORAGES, "items": storage_schema}}}),
        ("proxmox_tasks_recent", "Recent Proxmox tasks", "Read bounded recent task outcomes without worker identities or logs.", common, {"type": "object", "additionalProperties": False, "required": ["tasks"], "properties": {"tasks": {"type": "array", "maxItems": MAX_TASKS, "items": task_schema}}}),
        ("proxmox_guest_diagnostics", "Proxmox guest diagnostics", "Diagnose utilization, lock, and unexpected state for one LXC or virtual machine.", guest_input, {"type": "object", "additionalProperties": False, "required": ["status", "guest", "findings"], "properties": {"status": {"enum": ["healthy", "warning", "critical"]}, "guest": detailed_guest, "findings": {"type": "array", "maxItems": 64, "items": finding_schema}}}),
        ("proxmox_node_diagnostics", "Proxmox node diagnostics", "Diagnose bounded node, guest, storage, and recent task health.", common, {"type": "object", "additionalProperties": False, "required": ["status", "node", "guest_count", "storage_count", "recent_task_count", "findings"], "properties": {"status": {"enum": ["healthy", "warning", "critical"]}, "node": node_schema, "guest_count": {"type": "integer"}, "storage_count": {"type": "integer"}, "recent_task_count": {"type": "integer"}, "findings": {"type": "array", "maxItems": 128, "items": finding_schema}}}),
    ]
    return [{"name": name, "title": title, "description": description, "inputSchema": input_schema, "outputSchema": output_schema, "annotations": read_annotations} for name, title, description, input_schema, output_schema in tools]
