#!/usr/bin/env python3
"""Behavior and data-minimization checks for the Synology plugin."""

from __future__ import annotations

import importlib.util
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_PATH = PROJECT_ROOT / "plugins/synology/plugin.py"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


spec = importlib.util.spec_from_file_location("synology_plugin_test", PLUGIN_PATH)
require(spec is not None and spec.loader is not None, "plugin must be loadable")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)  # type: ignore[union-attr]


class FakeClient:
    instances: list["FakeClient"] = []

    def __init__(self, endpoint: str, *, ca_file: Path | None = None):
        self.endpoint = endpoint
        self.ca_file = ca_file
        self.calls: list[tuple[str, str]] = []
        self.logged_out = False
        self.closed = False
        self.__class__.instances.append(self)

    def api_info(self, names: tuple[str, ...]) -> dict[str, object]:
        self.names = names
        return {
            name: {"path": "entry.cgi", "minVersion": 1, "maxVersion": 6}
            for name in names
        }

    def login(self, _api: object, username: str, password: str) -> tuple[str, str]:
        require(username == "readonly-user", "username must reach only the login call")
        require(password == "do-not-return-this-secret", "password must reach only the login call")
        return "secret-session-id", "secret-syno-token"

    def call(
        self,
        api_name: str,
        _api: object,
        method: str,
        _sid: str,
        _token: str | None,
        *,
        maximum_version: int,
        parameters: dict[str, object] | None = None,
    ) -> dict[str, object]:
        require(parameters is None, "plugin must not accept caller-controlled API parameters")
        require(maximum_version in {1, 3}, "API version ceiling must be fixed")
        self.calls.append((api_name, method))
        if api_name == "SYNO.Core.System":
            return {
                "status": "normal",
                "model": "DS-test",
                "firmware_ver": "DSM 7.test",
                "up_time": 3600,
                "sys_temp": 41,
                "hostname": "private-nas-name",
                "serial": "private-serial",
            }
        if api_name == "SYNO.Core.System.Utilization":
            return {
                "cpu": {"user_load": 10, "system_load": 5, "other_load": 1},
                "memory": {"real_usage": 42},
                "processes": [{"command": "password=do-not-return-this-secret"}],
            }
        return {
            "storagePools": [{
                "id": "pool_1", "status": "normal", "raidType": "shr",
                "size": {"total": 1000, "used": 250},
                "serial": "private-pool-serial",
            }],
            "volumes": [{
                "id": "volume_1", "status": "warning", "raid_type": "btrfs",
                "total_size": 800, "used_size": 400,
                "shares": ["private-share-name"],
            }],
            "disks": [
                {"status": "normal", "serial": "private-disk-1"},
                {"status": "failed", "serial": "private-disk-2"},
            ],
            "files": ["private-file-name"],
        }

    def logout(self, _api: object, _sid: str, _token: str | None) -> None:
        self.logged_out = True

    def close(self) -> None:
        self.closed = True


def execute(action: str) -> tuple[dict[str, object], FakeClient]:
    result = plugin.execute(
        action,
        "https://nas.example.test:5001",
        {"schema": 1, "username": "readonly-user", "password": "do-not-return-this-secret"},
        ca_file=Path("/tmp/test-only-ca.crt"),
        client_factory=FakeClient,
    )
    return result, FakeClient.instances[-1]


system, system_client = execute("synology.system.summary")
require(system_client.calls == [
    ("SYNO.Core.System", "info"),
    ("SYNO.Core.System.Utilization", "get"),
], "system action must use only its two fixed read calls")
require(system_client.logged_out and system_client.closed, "DSM session must be closed")
require(set(system) == {
    "status", "model", "dsm_version", "uptime_seconds", "temperature_c",
    "cpu_percent", "memory_percent",
}, "system output must use the exact public allowlist")
require(system["cpu_percent"] == 16.0 and system["memory_percent"] == 42.0, "resource mapping failed")

storage, storage_client = execute("synology.storage.summary")
require(storage_client.calls == [("SYNO.Storage.CGI.Storage", "load_info")], "storage action must use one fixed read call")
require(storage_client.logged_out and storage_client.closed, "DSM session must be closed")
require(storage == {
    "pools": [{
        "id": "pool_1", "status": "healthy", "raid_type": "shr",
        "size_total_bytes": 1000, "size_used_bytes": 250, "usage_percent": 25.0,
    }],
    "volumes": [{
        "id": "volume_1", "status": "warning", "raid_type": "btrfs",
        "size_total_bytes": 800, "size_used_bytes": 400, "usage_percent": 50.0,
    }],
    "disks": {"total": 2, "healthy": 1, "warning": 1},
}, "storage output must use the exact public allowlist")

serialized = repr((system, storage)).lower()
for forbidden in ("secret", "serial", "hostname", "share", "file", "process", "password", "token"):
    require(forbidden not in serialized, f"output leaked forbidden field: {forbidden}")

tools = plugin.tool_definitions()
require([item["name"] for item in tools] == [
    "synology_system_summary", "synology_storage_summary",
], "plugin must expose only the two declared tools")
require(all(item["annotations"]["readOnlyHint"] is True for item in tools), "tools must be read-only")

try:
    plugin._api_path({"path": "../entry.cgi"})
except plugin.PluginError:
    pass
else:
    raise AssertionError("unsafe DSM API paths must be rejected")

try:
    execute("synology.arbitrary.request")
except plugin.PluginError:
    pass
else:
    raise AssertionError("unknown Synology actions must be rejected")

print("Synology plugin behavior checks passed.")
