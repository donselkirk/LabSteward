#!/usr/bin/env python3
"""End-to-end security and protocol checks for the built-in MCP transport."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def request(
    port: int,
    context: ssl.SSLContext,
    token: str,
    payload: object,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object] | None]:
    body = json.dumps(payload).encode("utf-8")
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=context)
    request_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Host": "127.0.0.1",
    }
    request_headers.update(headers or {})
    connection.request("POST", "/mcp", body=body, headers=request_headers)
    response = connection.getresponse()
    raw = response.read()
    connection.close()
    decoded = json.loads(raw) if raw else None
    return response.status, decoded


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="labsteward-mcp-test.") as directory:
        fixture = Path(directory)
        cert = fixture / "server.crt"
        key = fixture / "server.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=127.0.0.1",
                "-addext", "subjectAltName=IP:127.0.0.1",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
                "-addext", "extendedKeyUsage=serverAuth",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        port = choose_port()
        token = f"lst_{secrets.token_urlsafe(32)}"
        config_file = fixture / "config.json"
        catalog_file = fixture / "plugins.json"
        version_file = fixture / "VERSION"
        token_dir = fixture / "clients"
        server_secrets = fixture / "server-secrets"
        plugins_dir = fixture / "plugins"
        (plugins_dir / "synology").mkdir(parents=True)
        (plugins_dir / "unifi").mkdir(parents=True)
        server_secrets.mkdir()
        for name in ("manifest.json", "plugin.py"):
            destination = plugins_dir / "synology" / name
            destination.write_bytes((PROJECT_ROOT / "plugins/synology" / name).read_bytes())
            destination.chmod(0o644)
        for name in ("manifest.json", "plugin.py"):
            destination = plugins_dir / "unifi" / name
            destination.write_bytes((PROJECT_ROOT / "plugins/unifi" / name).read_bytes())
            destination.chmod(0o644)
        transport_file = fixture / "transport.json"
        write_json(
            config_file,
            {
                "schema": 1,
                "plugins": {},
                "servers": {},
                "clients": {
                    "desktop": {
                        "enabled": True,
                        "sources": ["127.0.0.1/32"],
                        "grants": {},
                    }
                },
            },
        )
        write_json(catalog_file, {"schema": 1, "plugins": []})
        version_file.write_text("v0.1.1\n", encoding="utf-8")
        write_json(
            token_dir / "desktop.json",
            {
                "schema": 1,
                "algorithm": "sha256",
                "digest": hashlib.sha256(token.encode()).hexdigest(),
            },
        )
        write_json(
            transport_file,
            {
                "schema": 1,
                "bind": "127.0.0.1",
                "port": port,
                "allowed_hosts": ["127.0.0.1"],
                "cert_file": str(cert),
                "key_file": str(key),
            },
        )
        environment = os.environ.copy()
        environment.update(
            {
                "PYTHONPATH": str(PROJECT_ROOT / "src"),
                "LABSTEWARD_CONFIG_FILE": str(config_file),
                "LABSTEWARD_CATALOG_FILE": str(catalog_file),
                "LABSTEWARD_VERSION_FILE": str(version_file),
                "LABSTEWARD_CLIENT_SECRETS_DIR": str(token_dir),
                "LABSTEWARD_TRANSPORT_CONFIG": str(transport_file),
                "LABSTEWARD_PLUGINS_DIR": str(plugins_dir),
                "LABSTEWARD_SERVER_SECRETS_DIR": str(server_secrets),
            }
        )
        process = subprocess.Popen(
            [sys.executable, str(PROJECT_ROOT / "src/labsteward_mcp.py"), "--config", str(transport_file)],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        context = ssl.create_default_context(cafile=str(cert))
        try:
            deadline = time.monotonic() + 8
            while True:
                try:
                    status, _ = request(
                        port,
                        context,
                        "lst_" + "A" * 43,
                        {"jsonrpc": "2.0", "id": 0, "method": "ping"},
                    )
                    if status == 401:
                        break
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise AssertionError("MCP service did not start")
                time.sleep(0.05)

            initialize = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            }
            status, response = request(port, context, token, initialize)
            require(status == 200, "initialize must succeed")
            result = response["result"]  # type: ignore[index]
            require(result["serverInfo"]["name"] == "labsteward", "server identity missing")  # type: ignore[index]
            require("tools" in result["capabilities"], "tools capability missing")  # type: ignore[operator]

            status, _ = request(
                port,
                context,
                token,
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            require(status == 202, "initialized notification must be accepted")

            status, response = request(
                port,
                context,
                token,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                headers={"X-Forwarded-For": "192.0.2.200"},
            )
            require(status == 200, "tools/list must succeed")
            tools = response["result"]["tools"]  # type: ignore[index]
            require([tool["name"] for tool in tools] == ["core_status"], "only core_status may be exposed")

            status, response = request(
                port,
                context,
                token,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "core_status", "arguments": {}},
                },
            )
            require(status == 200, "core_status must succeed")
            tool_result = response["result"]  # type: ignore[index]
            require(tool_result["isError"] is False, "core_status returned an error")
            summary = tool_result["structuredContent"]
            require(summary["status"] == "healthy", "core status must be healthy")
            require(set(summary) == {
                "status", "version", "catalogued_plugins", "installed_plugins",
                "registered_servers", "enabled_remote_clients", "remote_transport",
            }, "core status returned undeclared fields")

            status, response = request(
                port,
                context,
                token,
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "shell", "arguments": {"command": "id"}},
                },
            )
            require(status == 200 and response["result"]["isError"] is True, "unknown tool must fail safely")  # type: ignore[index]

            write_json(
                config_file,
                {
                    "schema": 1,
                    "plugins": {"synology": {"enabled": True, "version": "0.1.0"}},
                    "servers": {
                        "nas-test": {
                            "plugin": "synology",
                            "endpoint": "https://nas.example.test:5001",
                        }
                    },
                    "clients": {
                        "desktop": {
                            "enabled": True,
                            "sources": ["127.0.0.1/32"],
                            "grants": {},
                        }
                    },
                },
            )
            status, response = request(
                port,
                context,
                token,
                {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}},
            )
            require(
                status == 200 and [tool["name"] for tool in response["result"]["tools"]] == [  # type: ignore[index]
                    "core_status", "synology_system_summary", "synology_storage_summary",
                ],
                "an enabled Synology plugin must expose only its two fixed tools",
            )
            status, response = request(
                port,
                context,
                token,
                {
                    "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                    "params": {"name": "synology_system_summary", "arguments": {"server": "nas-test"}},
                },
            )
            require(
                status == 200 and response["result"]["isError"] is True,  # type: ignore[index]
                "Synology access without an explicit client grant must fail",
            )
            denied = json.dumps(response)
            require("permitt" in denied.lower() and "nas.example.test" not in denied, "denial must be safe and sanitized")
            configured = json.loads(config_file.read_text(encoding="utf-8"))
            configured["clients"]["desktop"]["grants"] = {
                "nas-test": {"system.read": "read"}
            }
            write_json(config_file, configured)
            status, response = request(
                port,
                context,
                token,
                {
                    "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                    "params": {"name": "synology_system_summary", "arguments": {"server": "nas-test"}},
                },
            )
            require(
                status == 200 and response["result"]["isError"] is True  # type: ignore[index]
                and "credentials" in json.dumps(response).lower(),
                "a grant must not bypass protected credential configuration",
            )

            configured["plugins"]["unifi"] = {"enabled": True, "version": "0.1.0"}
            configured["servers"]["network-test"] = {
                "plugin": "unifi", "endpoint": "https://unifi.example.test",
            }
            configured["clients"]["desktop"]["grants"]["network-test"] = {
                "firewall.rules": "read"
            }
            write_json(config_file, configured)
            status, response = request(
                port, context, token,
                {
                    "jsonrpc": "2.0", "id": 8, "method": "tools/call",
                    "params": {
                        "name": "unifi_firewall_logging_set",
                        "arguments": {
                            "server": "network-test",
                            "policy_id": "44444444-4444-4444-8444-444444444444",
                            "logging_enabled": True,
                        },
                    },
                },
            )
            require(
                status == 200 and response["result"]["isError"] is True  # type: ignore[index]
                and "write-level" in json.dumps(response).lower(),
                "a read-level grant must never authorize a UniFi mutation",
            )
            configured["clients"]["desktop"]["grants"]["network-test"] = {
                "firewall.rules": "write"
            }
            write_json(config_file, configured)
            status, response = request(
                port, context, token,
                {
                    "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                    "params": {
                        "name": "unifi_firewall_logging_set",
                        "arguments": {
                            "server": "network-test",
                            "policy_id": "44444444-4444-4444-8444-444444444444",
                            "logging_enabled": True,
                        },
                    },
                },
            )
            require(
                status == 200 and response["result"]["isError"] is True  # type: ignore[index]
                and "credentials" in json.dumps(response).lower(),
                "a write grant must still require protected UniFi credentials",
            )

            status, _ = request(port, context, "lst_" + "B" * 43, initialize)
            require(status == 401, "wrong token must be rejected")
            status, _ = request(port, context, token, initialize, headers={"Origin": "https://evil.test"})
            require(status == 403, "browser Origin requests must be rejected")

            sys.path.insert(0, str(PROJECT_ROOT / "src"))
            old_environment = os.environ.copy()
            os.environ.update(environment)
            try:
                import labsteward_mcp

                require(
                    labsteward_mcp.authenticate_client(token, "192.0.2.10") is None,
                    "wrong socket source must be rejected",
                )
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
                sys.path.pop(0)

            current = json.loads(config_file.read_text(encoding="utf-8"))
            current["clients"]["desktop"]["enabled"] = False
            write_json(config_file, current)
            status, _ = request(port, context, token, initialize)
            require(status == 401, "revoked client must be rejected")
        finally:
            process.terminate()
            try:
                _, logs = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                _, logs = process.communicate(timeout=5)
        require(token not in logs, "audit logs must never contain plaintext tokens")
    print("MCP transport behavior checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
