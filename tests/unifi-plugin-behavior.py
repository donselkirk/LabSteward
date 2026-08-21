#!/usr/bin/env python3
"""Behavior, mutation-boundary, and data-minimization checks for UniFi."""

from __future__ import annotations

import importlib.util
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_PATH = PROJECT_ROOT / "plugins/unifi/plugin.py"
SITE_ID = "11111111-1111-4111-8111-111111111111"
DEVICE_ID = "22222222-2222-4222-8222-222222222222"
CLIENT_ID = "33333333-3333-4333-8333-333333333333"
POLICY_ID = "44444444-4444-4444-8444-444444444444"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


spec = importlib.util.spec_from_file_location("unifi_plugin_test", PLUGIN_PATH)
require(spec is not None and spec.loader is not None, "plugin must be loadable")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)  # type: ignore[union-attr]


class FakeClient:
    instances: list["FakeClient"] = []
    origin = "USER_DEFINED"

    def __init__(self, endpoint: str, api_key: str, *, ca_file: Path | None = None):
        require(endpoint == "https://unifi.example.test", "endpoint must come from registration")
        require(api_key == "test-only-api-key-value", "API key must reach only the HTTP adapter")
        self.calls: list[tuple[str, str, object]] = []
        self.closed = False
        self.__class__.instances.append(self)

    def get(self, path: str, *, query: dict[str, object] | None = None) -> dict[str, object]:
        self.calls.append(("GET", path, query))
        if path == "/v1/info":
            return {"applicationVersion": "10.3.58", "apiKey": "never-return-this"}
        if path.endswith("/networks"):
            return {"data": [{
                "id": "55555555-5555-4555-8555-555555555555", "name": "Trusted",
                "enabled": True, "default": False, "management": "GATEWAY",
                "vlanId": 20, "subnet": "private-subnet",
            }]}
        if path.endswith("/wifi/broadcasts"):
            return {"data": [{
                "id": "66666666-6666-4666-8666-666666666666", "name": "Test WiFi",
                "enabled": True, "type": "STANDARD",
                "network": {"id": "55555555-5555-4555-8555-555555555555"},
                "securityConfiguration": {"type": "WPA3_PERSONAL", "passphrase": "never-return-this"},
            }]}
        if path.endswith("/devices"):
            return {"data": [{
                "id": DEVICE_ID, "name": "Test AP", "model": "U7-TEST",
                "state": "OFFLINE", "firmwareVersion": "1.2.3",
                "firmwareUpdatable": True, "macAddress": "aa:bb:cc:dd:ee:ff",
                "ipAddress": "192.0.2.10",
            }]}
        if path.endswith("/statistics/latest"):
            return {
                "uptimeSec": 7200, "cpuUtilizationPct": 91,
                "memoryUtilizationPct": 40, "uplink": {"state": "DOWN", "speedMbps": 0},
                "privateKey": "never-return-this",
            }
        if path.endswith(f"/clients/{CLIENT_ID}"):
            return {
                "id": CLIENT_ID, "name": "Test Client", "type": "WIRELESS",
                "connectedAt": "2026-01-01T00:00:00Z", "ipAddress": "192.0.2.30",
                "macAddress": "11:22:33:44:55:66", "uplinkDeviceId": DEVICE_ID,
                "access": {"type": "DEFAULT", "authorized": True, "token": "never-return-this"},
                "traffic": {"domains": ["private.example"]},
            }
        if path.endswith("/clients"):
            return {"data": [{
                "id": CLIENT_ID, "name": "Test Client", "type": "WIRELESS",
                "connectedAt": "2026-01-01T00:00:00Z", "ipAddress": "192.0.2.30",
                "macAddress": "11:22:33:44:55:66", "uplinkDeviceId": DEVICE_ID,
                "access": {"type": "DEFAULT", "authorized": True},
            }]}
        if path.endswith("/firewall/policies"):
            return {"data": [self.rule()]}
        if path.endswith(f"/firewall/policies/{POLICY_ID}"):
            return self.rule()
        raise AssertionError(f"unexpected fixed GET path: {path}")

    def patch(self, path: str, body: dict[str, object]) -> dict[str, object]:
        self.calls.append(("PATCH", path, body))
        require(path.endswith(f"/firewall/policies/{POLICY_ID}"), "only one explicit policy may be patched")
        require(body == {"loggingEnabled": True}, "mutation must contain only the logging state")
        value = self.rule()
        value["loggingEnabled"] = True
        return value

    @classmethod
    def rule(cls) -> dict[str, object]:
        return {
            "id": POLICY_ID, "name": "Allow DNS", "description": "Test rule",
            "enabled": True, "index": 10, "action": {"type": "ALLOW"},
            "loggingEnabled": False, "metadata": {"origin": cls.origin},
            "ipProtocolScope": {"ipVersion": "IPV4_AND_IPV6", "protocol": "UDP"},
            "connectionStateFilter": ["NEW"],
            "source": {"zoneId": SITE_ID, "trafficFilter": {"type": "NETWORK", "networkIds": ["secret"]}},
            "destination": {"zoneId": DEVICE_ID, "trafficFilter": {"type": "PORT", "ports": [53]}},
        }

    def close(self) -> None:
        self.closed = True


def execute(action: str, arguments: dict[str, object]) -> tuple[dict[str, object], FakeClient]:
    result = plugin.execute(
        action,
        "https://unifi.example.test",
        {"schema": 1, "api_key": "test-only-api-key-value", "site_id": SITE_ID},
        arguments,
        ca_file=Path("/tmp/test-only-unifi-ca.crt"),
        client_factory=FakeClient,
    )
    return result, FakeClient.instances[-1]


configuration, config_client = execute("unifi.configuration.summary", {})
require([call[1] for call in config_client.calls] == [
    "/v1/info", f"/v1/sites/{SITE_ID}/networks", f"/v1/sites/{SITE_ID}/wifi/broadcasts",
], "configuration action must use only three fixed reads")
require(config_client.closed, "connection must always close")
require(configuration["networks"][0]["vlan_id"] == 20, "network summary mapping failed")  # type: ignore[index]
require(configuration["wifi_broadcasts"][0]["security_type"] == "WPA3_PERSONAL", "WiFi summary mapping failed")  # type: ignore[index]

diagnostics, diag_client = execute("unifi.diagnostics.summary", {})
require(len(diag_client.calls) == 2, "diagnostics must use one bounded device list and one statistics call")
require(diagnostics["status"] == "critical", "offline device must produce critical status")
require({item["code"] for item in diagnostics["findings"]} == {  # type: ignore[index]
    "device_not_online", "firmware_update_available", "high_cpu",
}, "diagnostic findings must be deterministic")

client, client_adapter = execute("unifi.client.summary", {"client_id": CLIENT_ID})
require(client_adapter.calls == [("GET", f"/v1/sites/{SITE_ID}/clients/{CLIENT_ID}", None)], "client action must be target-specific")
require(set(client) == {
    "id", "name", "type", "connected_at", "ip_address", "uplink_device_id",
    "access_type", "authorized",
}, "client output must use the exact allowlist")

clients, clients_adapter = execute("unifi.clients.list", {})
require(clients_adapter.calls == [("GET", f"/v1/sites/{SITE_ID}/clients", {"offset": 0, "limit": 200})], "client discovery must use one bounded list")
require(clients["clients"] == [client], "client list and detail must share one sanitized shape")

rules, rules_client = execute("unifi.firewall.rules", {})
require(rules_client.calls == [("GET", f"/v1/sites/{SITE_ID}/firewall/policies", {"offset": 0, "limit": 200})], "firewall read must be bounded")
require(rules["rules"][0]["source_filter_type"] == "NETWORK", "rule source summary failed")  # type: ignore[index]

updated, update_client = execute(
    "unifi.firewall.logging.set", {"policy_id": POLICY_ID, "logging_enabled": True}
)
require(update_client.calls == [
    ("GET", f"/v1/sites/{SITE_ID}/firewall/policies/{POLICY_ID}", None),
    ("PATCH", f"/v1/sites/{SITE_ID}/firewall/policies/{POLICY_ID}", {"loggingEnabled": True}),
], "write action must verify the policy then use only the official logging patch")
require(updated["updated"] is True and updated["rule"]["logging_enabled"] is True, "write confirmation failed")  # type: ignore[index]

unchanged, unchanged_client = execute(
    "unifi.firewall.logging.set", {"policy_id": POLICY_ID, "logging_enabled": False}
)
require(unchanged_client.calls == [
    ("GET", f"/v1/sites/{SITE_ID}/firewall/policies/{POLICY_ID}", None),
], "an already-matching logging state must not cause a mutation")
require(unchanged["updated"] is False, "idempotent no-op must be reported")

FakeClient.origin = "SYSTEM_DEFINED"
try:
    execute("unifi.firewall.logging.set", {"policy_id": POLICY_ID, "logging_enabled": True})
except plugin.PluginError as exc:
    require("user-defined" in str(exc), "system policy rejection must be explicit")
else:
    raise AssertionError("a system-defined firewall policy must not be mutable")
finally:
    FakeClient.origin = "USER_DEFINED"

serialized = repr((configuration, diagnostics, client, clients, rules, updated)).lower()
for forbidden in ("api-key", "apikey", "passphrase", "privatekey", "macaddress", "never-return-this", "domains"):
    require(forbidden not in serialized, f"output leaked forbidden upstream data: {forbidden}")

tools = plugin.tool_definitions()
require(len(tools) == 6, "plugin must expose exactly six tools")
require(tools[-1]["annotations"]["readOnlyHint"] is False, "logging mutation must be marked write")
require(all(tool["annotations"]["openWorldHint"] is False for tool in tools), "tools must be closed-world")

for action, arguments in (
    ("unifi.arbitrary.request", {}),
    ("unifi.client.summary", {"client_id": "not-a-uuid"}),
    ("unifi.firewall.logging.set", {"policy_id": POLICY_ID, "logging_enabled": "yes"}),
):
    try:
        execute(action, arguments)
    except plugin.PluginError:
        pass
    else:
        raise AssertionError(f"unsafe action or arguments were accepted: {action}")

print("UniFi plugin behavior checks passed.")
