#!/usr/bin/env python3
"""Root-owned fixed-operation broker for the LabSteward admin service.

The network-facing admin process is deliberately unprivileged.  It may ask this
local Unix-socket service to perform only the registry operations declared
below.  There is no command, path, URL-fetch, or arbitrary argument primitive.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
import re
import socket
import socketserver
import struct
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CONFIG_FILE = Path(os.environ.get("LABSTEWARD_CONFIG_FILE", "/etc/labsteward/config.json"))
CATALOG_FILE = Path(
    os.environ.get("LABSTEWARD_CATALOG_FILE", "/opt/labsteward/catalog/plugins.json")
)
VERSION_FILE = Path(os.environ.get("LABSTEWARD_VERSION_FILE", "/opt/labsteward/VERSION"))
TOKEN_SNAPSHOT = Path(
    os.environ.get("LABSTEWARD_OAUTH_TOKEN_FILE", "/etc/labsteward/secrets/oauth-tokens.json")
)
CLIENT_SECRETS_DIR = Path(
    os.environ.get("LABSTEWARD_CLIENT_SECRETS_DIR", "/etc/labsteward/secrets/clients")
)
SOCKET_PATH = Path(
    os.environ.get("LABSTEWARD_BROKER_SOCKET", "/run/labsteward/admin-broker.sock")
)
ADMIN_USER = os.environ.get("LABSTEWARD_ADMIN_USER", "labsteward-admin")
ADMIN_GROUP = os.environ.get("LABSTEWARD_ADMIN_GROUP", "labsteward-admin")
MAX_MESSAGE_BYTES = 64 * 1024
MAX_JSON_BYTES = 1024 * 1024

IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
ALIAS = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
PERMISSION = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")


class BrokerError(Exception):
    """A safe error that may be returned to the admin service."""


def read_object(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise BrokerError("Stored data exceeds the size limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BrokerError("Required LabSteward state is unavailable") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise BrokerError("Stored LabSteward state is invalid") from exc
    if not isinstance(value, dict):
        raise BrokerError("Stored LabSteward state is invalid")
    return value


def atomic_write(path: Path, value: dict[str, Any], mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if path.exists():
            metadata = path.stat()
            os.chown(temporary, metadata.st_uid, metadata.st_gid)
        elif CONFIG_FILE.exists():
            metadata = CONFIG_FILE.stat()
            os.chown(temporary, metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_config() -> dict[str, Any]:
    config = read_object(CONFIG_FILE)
    if config.get("schema") != 1:
        raise BrokerError("Unsupported LabSteward configuration")
    for registry in ("plugins", "servers", "clients"):
        if not isinstance(config.get(registry), dict):
            raise BrokerError("LabSteward configuration is inconsistent")
    return config


def load_catalog() -> dict[str, Any]:
    catalog = read_object(CATALOG_FILE)
    if catalog.get("schema") != 1 or not isinstance(catalog.get("plugins"), list):
        raise BrokerError("Plugin catalogue is invalid")
    return catalog


def require_text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise BrokerError(f"Invalid {label}")
    return value


def require_id(value: object, label: str, pattern: re.Pattern[str]) -> str:
    normalized = require_text(value, label, 64).lower()
    if not pattern.fullmatch(normalized):
        raise BrokerError(f"Invalid {label}")
    return normalized


def permission_levels(value: object, label: str = "permissions") -> dict[str, str]:
    """Normalize legacy permission lists to read-only level mappings."""
    if isinstance(value, list):
        value = {str(item): "read" for item in value}
    if not isinstance(value, dict) or len(value) > 64:
        raise BrokerError(f"Invalid {label}")
    normalized = {}
    for permission, level in value.items():
        name = require_id(permission, "permission", PERMISSION)
        if level not in {"read", "write"}:
            raise BrokerError(f"Invalid permission level for {name}")
        normalized[name] = str(level)
    return dict(sorted(normalized.items()))


def declared_permissions(plugin: dict[str, Any]) -> set[str]:
    raw = plugin.get("permissions", {})
    values = raw if isinstance(raw, list) else raw.keys() if isinstance(raw, dict) else []
    return {require_id(item, "permission", PERMISSION) for item in values}


def require_source(value: object) -> str:
    import ipaddress

    text = require_text(value, "source restriction", 64)
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise BrokerError("Invalid source restriction") from exc
    if network.prefixlen == 0 or network.is_multicast or network.is_unspecified:
        raise BrokerError("Source restrictions cannot be catch-all or unspecified")
    return str(network)


def require_endpoint(value: object) -> str:
    endpoint = require_text(value, "server endpoint", 2048)
    parsed = urlsplit(endpoint)
    try:
        parsed.port
    except ValueError as exc:
        raise BrokerError("Server endpoint contains an invalid port") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise BrokerError("Server endpoints must be HTTPS origins without credentials")
    return endpoint.rstrip("/")


def public_state() -> dict[str, Any]:
    config = load_config()
    catalog = load_catalog()
    try:
        version = VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        version = "unknown"
    clients = {}
    for client_id, client in sorted(config["clients"].items()):
        if not isinstance(client, dict):
            continue
        clients[client_id] = {
            "enabled": client.get("enabled") is True,
            "sources": client.get("sources", []),
            "grants": client.get("grants", {}),
            "auth": client.get("auth", "legacy_token"),
            "display_name": client.get("display_name", client_id),
        }
    return {
        "version": version[:64],
        "plugins": config["plugins"],
        "servers": config["servers"],
        "clients": clients,
        "catalog": catalog["plugins"],
    }


def token_snapshot() -> dict[str, Any]:
    if not TOKEN_SNAPSHOT.exists():
        return {"schema": 1, "tokens": [], "generations": {}}
    value = read_object(TOKEN_SNAPSHOT)
    value.setdefault("generations", {})
    if (
        value.get("schema") != 1
        or not isinstance(value.get("tokens"), list)
        or not isinstance(value.get("generations"), dict)
        or any(
            not isinstance(client, str) or not isinstance(generation, int) or generation < 1
            for client, generation in value["generations"].items()
        )
    ):
        raise BrokerError("OAuth token state is invalid")
    return value


def save_token_snapshot(value: dict[str, Any]) -> None:
    atomic_write(TOKEN_SNAPSHOT, value, 0o640)


def revoke_client_tokens(client_id: str) -> None:
    snapshot = token_snapshot()
    snapshot["tokens"] = [
        item
        for item in snapshot["tokens"]
        if not isinstance(item, dict) or item.get("client") != client_id
    ]
    save_token_snapshot(snapshot)


def operation_client_approve(arguments: dict[str, Any]) -> dict[str, Any]:
    client_id = require_id(arguments.get("client"), "client ID", IDENTIFIER)
    display_name = require_text(arguments.get("display_name"), "display name", 80)
    source = require_source(arguments.get("source"))
    oauth_client_id = require_text(arguments.get("oauth_client_id"), "OAuth client ID", 2048)
    config = load_config()
    existing_match = next(
        (
            key
            for key, item in config["clients"].items()
            if isinstance(item, dict) and item.get("oauth_client_id") == oauth_client_id
        ),
        None,
    )
    if existing_match and existing_match != client_id:
        raise BrokerError("This OAuth client is already registered under another name")
    existing = config["clients"].get(client_id)
    if existing and existing.get("oauth_client_id") != oauth_client_id:
        raise BrokerError("Client ID is already in use")
    snapshot = token_snapshot()
    previous_generation = int(snapshot["generations"].get(client_id, 0))
    if existing:
        existing["enabled"] = True
        existing["sources"] = [source]
        existing["display_name"] = display_name
        generation = max(previous_generation, int(existing.get("auth_generation", 0))) + 1
        existing["auth_generation"] = generation
    else:
        generation = previous_generation + 1
        config["clients"][client_id] = {
            "enabled": True,
            "sources": [source],
            "grants": {},
            "auth": "oauth",
            "oauth_client_id": oauth_client_id,
            "display_name": display_name,
            "auth_generation": generation,
        }
    snapshot["tokens"] = [
        item
        for item in snapshot["tokens"]
        if not isinstance(item, dict) or item.get("client") != client_id
    ]
    snapshot["generations"][client_id] = generation
    save_token_snapshot(snapshot)
    atomic_write(CONFIG_FILE, config)
    return {"client": client_id, "auth_generation": generation}


def operation_client_revoke(arguments: dict[str, Any]) -> dict[str, Any]:
    client_id = require_id(arguments.get("client"), "client ID", IDENTIFIER)
    config = load_config()
    client = config["clients"].get(client_id)
    if not isinstance(client, dict):
        raise BrokerError("Unknown client")
    snapshot = token_snapshot()
    generation = client.get("auth_generation")
    if isinstance(generation, int) and generation > 0:
        snapshot["generations"][client_id] = max(
            generation, int(snapshot["generations"].get(client_id, 0))
        )
    snapshot["tokens"] = [
        item
        for item in snapshot["tokens"]
        if not isinstance(item, dict) or item.get("client") != client_id
    ]
    save_token_snapshot(snapshot)
    del config["clients"][client_id]
    atomic_write(CONFIG_FILE, config)
    (CLIENT_SECRETS_DIR / f"{client_id}.json").unlink(missing_ok=True)
    return {"client": client_id}


def operation_client_sources(arguments: dict[str, Any]) -> dict[str, Any]:
    client_id = require_id(arguments.get("client"), "client ID", IDENTIFIER)
    raw_sources = arguments.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources or len(raw_sources) > 16:
        raise BrokerError("One to sixteen source restrictions are required")
    sources = sorted({require_source(item) for item in raw_sources})
    config = load_config()
    client = config["clients"].get(client_id)
    if not isinstance(client, dict) or client.get("enabled") is not True:
        raise BrokerError("Unknown or revoked client")
    client["sources"] = sources
    atomic_write(CONFIG_FILE, config)
    revoke_client_tokens(client_id)
    return {"client": client_id, "sources": sources}


def operation_client_grants(arguments: dict[str, Any]) -> dict[str, Any]:
    client_id = require_id(arguments.get("client"), "client ID", IDENTIFIER)
    server_id = require_id(arguments.get("server"), "server alias", ALIAS)
    raw_permissions = arguments.get("permissions")
    permissions = permission_levels(raw_permissions, "client permissions")
    config = load_config()
    client = config["clients"].get(client_id)
    server = config["servers"].get(server_id)
    if not isinstance(client, dict) or client.get("enabled") is not True:
        raise BrokerError("Unknown or revoked client")
    if not isinstance(server, dict):
        raise BrokerError("Unknown server")
    if server_id not in client.setdefault("grants", {}):
        raise BrokerError("Add the server to this client before configuring permissions")
    plugin = next(
        (
            item
            for item in load_catalog()["plugins"]
            if isinstance(item, dict) and item.get("id") == server.get("plugin")
        ),
        {},
    )
    if set(permissions) - declared_permissions(plugin):
        raise BrokerError("Permission is not declared by the server plugin")
    client["grants"][server_id] = permissions
    atomic_write(CONFIG_FILE, config)
    return {"client": client_id, "server": server_id, "permissions": permissions}


def operation_client_server_add(arguments: dict[str, Any]) -> dict[str, Any]:
    client_id = require_id(arguments.get("client"), "client ID", IDENTIFIER)
    server_id = require_id(arguments.get("server"), "server alias", ALIAS)
    config = load_config()
    client = config["clients"].get(client_id)
    if not isinstance(client, dict) or client.get("enabled") is not True:
        raise BrokerError("Unknown or revoked client")
    if server_id not in config["servers"]:
        raise BrokerError("Unknown server")
    grants = client.setdefault("grants", {})
    if server_id in grants:
        raise BrokerError("Server is already assigned to this client")
    grants[server_id] = {}
    atomic_write(CONFIG_FILE, config)
    return {"client": client_id, "server": server_id}


def operation_client_server_remove(arguments: dict[str, Any]) -> dict[str, Any]:
    client_id = require_id(arguments.get("client"), "client ID", IDENTIFIER)
    server_id = require_id(arguments.get("server"), "server alias", ALIAS)
    config = load_config()
    client = config["clients"].get(client_id)
    if not isinstance(client, dict) or client.get("enabled") is not True:
        raise BrokerError("Unknown or revoked client")
    if server_id not in client.setdefault("grants", {}):
        raise BrokerError("Server is not assigned to this client")
    del client["grants"][server_id]
    atomic_write(CONFIG_FILE, config)
    return {"client": client_id, "server": server_id}


def operation_server_add(arguments: dict[str, Any]) -> dict[str, Any]:
    alias = require_id(arguments.get("server"), "server alias", ALIAS)
    plugin_id = require_id(arguments.get("plugin"), "plugin ID", IDENTIFIER)
    endpoint = require_endpoint(arguments.get("endpoint"))
    config = load_config()
    if alias in config["servers"]:
        raise BrokerError("Server alias already exists")
    installed = config["plugins"].get(plugin_id)
    if not isinstance(installed, dict) or installed.get("enabled") is not True:
        raise BrokerError("The selected plugin is not installed and enabled")
    config["servers"][alias] = {
        "plugin": plugin_id,
        "endpoint": endpoint,
    }
    atomic_write(CONFIG_FILE, config)
    return {"server": alias}


def operation_server_remove(arguments: dict[str, Any]) -> dict[str, Any]:
    alias = require_id(arguments.get("server"), "server alias", ALIAS)
    config = load_config()
    if alias not in config["servers"]:
        raise BrokerError("Unknown server")
    for client in config["clients"].values():
        if isinstance(client, dict) and isinstance(client.get("grants"), dict):
            client["grants"].pop(alias, None)
    del config["servers"][alias]
    atomic_write(CONFIG_FILE, config)
    return {"server": alias}


def operation_token_put(arguments: dict[str, Any]) -> dict[str, Any]:
    digest = require_text(arguments.get("digest"), "token digest", 64)
    client_id = require_id(arguments.get("client"), "client ID", IDENTIFIER)
    expires_at = arguments.get("expires_at")
    auth_generation = arguments.get("auth_generation")
    if not DIGEST.fullmatch(digest):
        raise BrokerError("Invalid token digest")
    now = int(time.time())
    if not isinstance(expires_at, int) or not now < expires_at <= now + 3600:
        raise BrokerError("Invalid access-token expiry")
    config = load_config()
    client = config["clients"].get(client_id)
    if (
        not isinstance(client, dict)
        or client.get("enabled") is not True
        or client.get("auth") != "oauth"
        or not isinstance(auth_generation, int)
        or client.get("auth_generation") != auth_generation
    ):
        raise BrokerError("OAuth client is unavailable")
    snapshot = token_snapshot()
    snapshot["tokens"] = [
        item
        for item in snapshot["tokens"]
        if isinstance(item, dict)
        and item.get("expires_at", 0) > now
        and item.get("digest") != digest
    ]
    snapshot["tokens"].append(
        {"digest": digest, "client": client_id, "expires_at": expires_at}
    )
    if len(snapshot["tokens"]) > 2048:
        raise BrokerError("OAuth token registry is full")
    save_token_snapshot(snapshot)
    return {"stored": True}


def operation_token_revoke(arguments: dict[str, Any]) -> dict[str, Any]:
    digest = require_text(arguments.get("digest"), "token digest", 64)
    if not DIGEST.fullmatch(digest):
        raise BrokerError("Invalid token digest")
    snapshot = token_snapshot()
    before = len(snapshot["tokens"])
    snapshot["tokens"] = [
        item for item in snapshot["tokens"] if not isinstance(item, dict) or item.get("digest") != digest
    ]
    save_token_snapshot(snapshot)
    return {"revoked": len(snapshot["tokens"]) != before}


OPERATIONS = {
    "state.get": lambda _arguments: public_state(),
    "client.approve": operation_client_approve,
    "client.revoke": operation_client_revoke,
    "client.sources": operation_client_sources,
    "client.grants": operation_client_grants,
    "client.server.add": operation_client_server_add,
    "client.server.remove": operation_client_server_remove,
    "server.add": operation_server_add,
    "server.remove": operation_server_remove,
    "token.put": operation_token_put,
    "token.revoke": operation_token_revoke,
}


def dispatch(request: object) -> dict[str, Any]:
    if not isinstance(request, dict) or set(request) - {"operation", "arguments"}:
        raise BrokerError("Invalid broker request")
    operation = request.get("operation")
    arguments = request.get("arguments", {})
    if operation not in OPERATIONS or not isinstance(arguments, dict):
        raise BrokerError("Unsupported broker operation")
    return OPERATIONS[operation](arguments)


class BrokerServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path: str, handler: type[socketserver.StreamRequestHandler], allowed_uid: int):
        self.allowed_uid = allowed_uid
        self.operation_lock = threading.Lock()
        super().__init__(path, handler)


class BrokerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        credentials = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, _gid = struct.unpack("3i", credentials)
        if uid != self.server.allowed_uid:  # type: ignore[attr-defined]
            return
        raw = self.rfile.readline(MAX_MESSAGE_BYTES + 1)
        if not raw or len(raw) > MAX_MESSAGE_BYTES or not raw.endswith(b"\n"):
            return
        try:
            request = json.loads(raw)
            with self.server.operation_lock:  # type: ignore[attr-defined]
                result = dispatch(request)
            response = {"ok": True, "result": result}
        except (BrokerError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            response = {"ok": False, "error": str(exc) if isinstance(exc, BrokerError) else "Invalid request"}
        self.wfile.write(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the LabSteward fixed-operation broker")
    parser.add_argument("--socket", type=Path, default=SOCKET_PATH)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        load_config()
        load_catalog()
        print("LabSteward admin broker configuration is valid")
        return 0
    if os.geteuid() != 0 and os.environ.get("LABSTEWARD_BROKER_ALLOW_CURRENT_UID") != "1":
        raise SystemExit("labsteward broker must run as root")
    if os.environ.get("LABSTEWARD_BROKER_ALLOW_CURRENT_UID") == "1":
        allowed_uid = os.getuid()
        group_id = os.getgid()
        owner_uid = os.getuid()
    else:
        import pwd

        allowed_uid = pwd.getpwnam(ADMIN_USER).pw_uid
        group_id = grp.getgrnam(ADMIN_GROUP).gr_gid
        owner_uid = 0
    args.socket.parent.mkdir(parents=True, exist_ok=True)
    args.socket.unlink(missing_ok=True)
    server = BrokerServer(str(args.socket), BrokerHandler, allowed_uid)
    os.chown(args.socket, owner_uid, group_id)
    os.chmod(args.socket, 0o660)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        args.socket.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
