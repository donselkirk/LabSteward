#!/usr/bin/env python3
"""Behavior and output-boundary checks for the Proxmox plugin."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("proxmox_plugin", ROOT / "plugins/proxmox/plugin.py")
assert SPEC and SPEC.loader
plugin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plugin)


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


RESPONSES = {
    "/api2/json/version": {"version": "9.2.10", "release": "9.2"},
    "/api2/json/nodes/pve-test/status": {
        "status": "online", "kversion": "Linux safe", "uptime": 1000, "cpu": 0.12,
        "cpuinfo": {"cpus": 8, "model": "SECRET CPU SERIAL"},
        "loadavg": ["0.1", "0.2", "0.3"],
        "memory": {"used": 80, "total": 100}, "rootfs": {"used": 91, "total": 100},
    },
    "/api2/json/nodes/pve-test/lxc": [{
        "vmid": 101, "name": "media", "status": "running", "uptime": 20,
        "cpu": 0.5, "cpus": 2, "mem": 90, "maxmem": 100, "disk": 10, "maxdisk": 100,
        "netin": 999, "secret": "leak-me",
    }],
    "/api2/json/nodes/pve-test/qemu": [{
        "vmid": 201, "name": "build", "status": "stopped", "cpus": 4,
        "mem": 0, "maxmem": 200, "disk": 50, "maxdisk": 100,
    }],
    "/api2/json/nodes/pve-test/lxc/101/status/current": {
        "vmid": 101, "name": "media", "status": "running", "lock": "backup",
        "uptime": 20, "cpu": 0.5, "cpus": 2, "mem": 90, "maxmem": 100,
        "disk": 10, "maxdisk": 100,
    },
    "/api2/json/nodes/pve-test/lxc/101/config": {
        "cores": 2, "memory": 1024, "swap": 512, "arch": "amd64", "ostype": "debian",
        "onboot": 1, "unprivileged": 1, "protection": 1, "startup": "order=2",
        "description": "contains private notes", "mp0": "/secret/path,mp=/data",
        "net0": "name=eth0,ip=10.0.0.5/24,hwaddr=AA:BB:CC:DD:EE:FF",
    },
    "/api2/json/nodes/pve-test/storage": [{
        "storage": "local-zfs", "type": "zfspool", "active": 1, "enabled": 1,
        "shared": 0, "content": "rootdir,images", "used": 85, "avail": 15,
        "total": 100, "path": "/private/storage/path", "username": "secret-user",
    }],
    "/api2/json/nodes/pve-test/tasks": [{
        "type": "vzdump", "id": "101", "starttime": 10, "endtime": 20,
        "status": "ERROR", "user": "private@pam", "upid": "secret-upid",
    }],
}


class Client:
    instances: list["Client"] = []

    def __init__(self, endpoint: str, token_id: str, token_secret: str, ca_file: Path | None):
        self.init = (endpoint, token_id, token_secret, ca_file)
        self.calls: list[tuple[str, dict[str, object] | None]] = []
        Client.instances.append(self)

    def get(self, path: str, query: dict[str, object] | None = None):
        self.calls.append((path, query))
        return RESPONSES[path]


CREDENTIALS = {
    "schema": 1, "token_id": "audit@pve!labsteward",
    "token_secret": "very-secret-token", "node": "pve-test",
}


def execute(action: str, arguments: dict | None = None):
    return plugin.execute(
        action, "https://pve.example.test:8006", CREDENTIALS, arguments or {},
        client_factory=Client,
    )


node = execute("proxmox.node.summary")
require(set(node) == {"node", "status", "pve_version", "release", "kernel_version", "uptime_seconds", "cpu_percent", "cpu_count", "load_average", "memory_used_bytes", "memory_total_bytes", "memory_percent", "root_used_bytes", "root_total_bytes", "root_percent"}, "node output allowlist changed")
require(Client.instances[-1].calls == [("/api2/json/version", None), ("/api2/json/nodes/pve-test/status", None)], "node action must use exact fixed GETs")

guests = execute("proxmox.guests.list")
require([item["guest_id"] for item in guests["guests"]] == [101, 201], "both guest types must be listed")
require(set(guests["guests"][0]) == {"node", "guest_id", "kind", "name", "status", "locked", "uptime_seconds", "cpu_percent", "cpu_count", "memory_used_bytes", "memory_total_bytes", "memory_percent", "disk_used_bytes", "disk_total_bytes", "disk_percent"}, "guest output allowlist changed")

guest = execute("proxmox.guest.summary", {"kind": "lxc", "guest_id": 101})
require(guest["configuration"]["mount_point_count"] == 1 and guest["configuration"]["network_device_count"] == 1, "configuration must expose counts only")
require("description" not in guest["configuration"] and "mounts" not in guest["configuration"], "raw configuration leaked")

storage = execute("proxmox.storage.summary")
tasks = execute("proxmox.tasks.recent")
require(storage["storage"][0]["used_percent"] == 85.0, "storage percentage incorrect")
require(tasks["tasks"][0]["guest_id"] == 101, "numeric task guest ID must be normalized")

diagnostics = execute("proxmox.node.diagnostics")
codes = {item["code"] for item in diagnostics["findings"]}
require({"root_percent.critical", "disk_percent.high", "task.failed", "memory_percent.high"} <= codes, "expected diagnostic findings missing")
guest_diagnostics = execute("proxmox.guest.diagnostics", {"kind": "lxc", "guest_id": 101})
require("guest.locked" in {item["code"] for item in guest_diagnostics["findings"]}, "guest lock finding missing")

serialized = json.dumps((node, guests, guest, storage, tasks, diagnostics, guest_diagnostics)).lower()
for forbidden in ("very-secret-token", "secret cpu serial", "private/storage", "private notes", "aa:bb:cc", "private@pam", "secret-upid", "leak-me"):
    require(forbidden not in serialized, f"sensitive value leaked: {forbidden}")

for invalid_action, invalid_args in (("proxmox.shell", {}), ("proxmox.guest.summary", {"kind": "host", "guest_id": 101}), ("proxmox.guest.summary", {"kind": "lxc", "guest_id": 1})):
    try:
        execute(invalid_action, invalid_args)
    except plugin.PluginError:
        pass
    else:
        raise AssertionError(f"unsafe input accepted: {invalid_action}")

tools = plugin.tool_definitions()
require(len(tools) == 7, "exactly seven Proxmox tools must be exposed")
require(all(tool["annotations"]["readOnlyHint"] for tool in tools), "initial Proxmox tools must all be read-only")
require(all(tool["annotations"]["openWorldHint"] is False for tool in tools), "tools must be closed-world")
require(len({tool["name"] for tool in tools}) == 7, "tool names must be unique")
print("Proxmox plugin behavior checks passed.")
