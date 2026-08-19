#!/usr/bin/env python3
"""Root-only LabSteward appliance manager.

This manager deliberately handles only non-secret registry data. Plugin-specific
credential commands will own protected secret-file creation in later releases.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(os.environ.get("LABSTEWARD_BASE_DIR", "/opt/labsteward"))
CONFIG_FILE = Path(os.environ.get("LABSTEWARD_CONFIG_FILE", "/etc/labsteward/config.json"))
CATALOG_FILE = Path(os.environ.get("LABSTEWARD_CATALOG_FILE", str(BASE_DIR / "catalog/plugins.json")))
VERSION_FILE = Path(os.environ.get("LABSTEWARD_VERSION_FILE", str(BASE_DIR / "VERSION")))
SELF_UPDATE = Path(os.environ.get("LABSTEWARD_SELF_UPDATE", str(BASE_DIR / "lib/self-update.sh")))
SCHEMA_FILE = Path(
    os.environ.get("LABSTEWARD_SCHEMA_FILE", str(BASE_DIR / "schemas/config.schema.json"))
)
SANITIZER_FILE = Path(
    os.environ.get("LABSTEWARD_SANITIZER_FILE", str(BASE_DIR / "lib/labsteward_sanitize.py"))
)
CORE_FILE = Path(os.environ.get("LABSTEWARD_CORE_FILE", str(BASE_DIR / "lib/labsteward_core.py")))
MCP_FILE = Path(os.environ.get("LABSTEWARD_MCP_FILE", str(BASE_DIR / "lib/labsteward_mcp.py")))
CLIENT_SECRETS_DIR = Path(
    os.environ.get("LABSTEWARD_CLIENT_SECRETS_DIR", "/etc/labsteward/secrets/clients")
)
TRANSPORT_CONFIG_FILE = Path(
    os.environ.get("LABSTEWARD_TRANSPORT_CONFIG", "/etc/labsteward/transport.json")
)
TLS_DIR = Path(os.environ.get("LABSTEWARD_TLS_DIR", "/etc/labsteward/secrets/tls"))
SYSTEMD_UNIT_FILE = Path(
    os.environ.get("LABSTEWARD_SYSTEMD_UNIT", "/etc/systemd/system/labsteward.service")
)
SYSTEMCTL = os.environ.get("LABSTEWARD_SYSTEMCTL", "/usr/bin/systemctl")
OPENSSL = os.environ.get("LABSTEWARD_OPENSSL", "/usr/bin/openssl")
ALLOW_NON_ROOT = os.environ.get("LABSTEWARD_ALLOW_NON_ROOT") == "1"
ALLOW_LOOPBACK = os.environ.get("LABSTEWARD_ALLOW_LOOPBACK") == "1"

IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
ALIAS = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
PERMISSION = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


class UserError(Exception):
    pass


def require_root() -> None:
    if not ALLOW_NON_ROOT and os.geteuid() != 0:
        raise UserError("Run stewctl as root.")


def read_json(path: Path) -> dict:
    try:
        if path.stat().st_size > 1024 * 1024:
            raise UserError(f"Refusing oversized JSON file: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise UserError(f"Required file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise UserError(f"Invalid JSON in {path}: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise UserError(f"Expected a JSON object in {path}")
    return value


def load_config() -> dict:
    config = read_json(CONFIG_FILE)
    if config.get("schema") != 1:
        raise UserError("Unsupported LabSteward configuration schema")
    config.setdefault("clients", {})
    if (
        not isinstance(config.get("plugins"), dict)
        or not isinstance(config.get("servers"), dict)
        or not isinstance(config.get("clients"), dict)
    ):
        raise UserError("Configuration must contain plugin, server, and client registries")
    return config


def save_config(config: dict) -> None:
    CONFIG_FILE.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".config.", dir=CONFIG_FILE.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, CONFIG_FILE)
    finally:
        temporary.unlink(missing_ok=True)


def save_json(path: Path, value: dict, mode: int = 0o640) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if CONFIG_FILE.exists():
            metadata = CONFIG_FILE.stat()
            os.chown(temporary, metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def catalog_plugins() -> dict[str, dict]:
    catalog = read_json(CATALOG_FILE)
    if catalog.get("schema") != 1 or not isinstance(catalog.get("plugins"), list):
        raise UserError("Unsupported plugin catalog schema")
    result = {}
    for plugin in catalog["plugins"]:
        if not isinstance(plugin, dict) or not IDENTIFIER.fullmatch(str(plugin.get("id", ""))):
            raise UserError("Plugin catalog contains an invalid ID")
        result[plugin["id"]] = plugin
    return result


def require_identifier(value: str, label: str, pattern: re.Pattern[str]) -> str:
    normalized = value.lower()
    if not pattern.fullmatch(normalized):
        raise UserError(f"Invalid {label}: {value}")
    return normalized


def require_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise UserError("Server endpoints must be HTTPS origins without embedded credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise UserError("Server endpoints cannot contain paths, queries, or fragments")
    if len(value) > 2048:
        raise UserError("Server endpoint is too long")
    return value.rstrip("/")


def require_source(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise UserError(f"Invalid client source IP or CIDR: {value}") from exc
    if (
        network.prefixlen == 0
        or network.network_address.is_multicast
        or network.network_address.is_unspecified
    ):
        raise UserError("Client sources cannot be catch-all, multicast, or unspecified networks")
    return str(network)


def require_bind_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise UserError(f"Transport bind must be a literal IP address: {value}") from exc
    if address.is_unspecified or address.is_multicast:
        raise UserError("Transport bind cannot be unspecified or multicast")
    if address.is_loopback and not ALLOW_LOOPBACK:
        raise UserError("Transport bind cannot be loopback for remote access")
    return str(address)


def require_transport_host(value: str) -> str:
    normalized = value.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(normalized)
        if address.is_unspecified or address.is_multicast:
            raise UserError(f"Invalid transport host: {value}")
        return str(address)
    except ValueError:
        if not HOSTNAME.fullmatch(normalized):
            raise UserError(f"Invalid transport host: {value}")
        return normalized


def tls_paths() -> dict[str, Path]:
    return {
        "ca_key": TLS_DIR / "labsteward-ca.key",
        "ca_cert": TLS_DIR / "labsteward-ca.crt",
        "server_key": TLS_DIR / "server.key",
        "server_cert": TLS_DIR / "server.crt",
    }


def install_tls_file(source: Path, destination: Path, mode: int, service_group: bool) -> None:
    destination.parent.mkdir(mode=0o2750, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(source, temporary)
        os.chmod(temporary, mode)
        if CONFIG_FILE.exists():
            metadata = CONFIG_FILE.stat()
            group_id = metadata.st_gid if service_group else BASE_DIR.stat().st_gid
            os.chown(temporary, metadata.st_uid, group_id)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def read_transport_config() -> dict:
    return read_json(TRANSPORT_CONFIG_FILE)


def validate_transport_config() -> dict:
    config = read_transport_config()
    if config.get("schema") != 1:
        raise UserError("Unsupported transport configuration schema")
    bind = require_bind_address(str(config.get("bind", "")))
    port = config.get("port")
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise UserError("Transport port must be between 1024 and 65535")
    hosts = config.get("allowed_hosts")
    if not isinstance(hosts, list) or not hosts or len(hosts) > 16:
        raise UserError("Transport must define one to sixteen allowed hosts")
    normalized_hosts = [require_transport_host(str(host)) for host in hosts]
    cert_file = Path(str(config.get("cert_file", "")))
    key_file = Path(str(config.get("key_file", "")))
    expected = tls_paths()
    if cert_file != expected["server_cert"] or key_file != expected["server_key"]:
        raise UserError("Transport must use the protected LabSteward TLS paths")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_file, key_file)
    except (OSError, ssl.SSLError) as exc:
        raise UserError("Transport TLS certificate and key are unavailable or mismatched") from exc
    return {
        "schema": 1,
        "bind": bind,
        "port": port,
        "allowed_hosts": normalized_hosts,
        "cert_file": str(cert_file),
        "key_file": str(key_file),
    }


def systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [SYSTEMCTL, *arguments],
            check=check,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise UserError(f"Unable to manage labsteward.service: {' '.join(arguments)}") from exc


def transport_service_state() -> str:
    try:
        result = systemctl("is-active", "labsteward.service", check=False)
    except UserError:
        return "unknown"
    state = result.stdout.strip()
    return state if state else "inactive"


def validate_file_security(path: Path, mode: int, group_id: int) -> str | None:
    try:
        metadata = path.stat()
    except OSError:
        return f"protected file is missing: {path}"
    if metadata.st_mode & 0o777 != mode:
        return f"protected file has unsafe permissions: {path}"
    owner_id = CONFIG_FILE.stat().st_uid
    if metadata.st_uid != owner_id or metadata.st_gid != group_id:
        return f"protected file has unsafe ownership: {path}"
    return None


def client_token_path(client_id: str) -> Path:
    return CLIENT_SECRETS_DIR / f"{client_id}.json"


def write_client_token(client_id: str) -> str:
    token = f"lst_{secrets.token_urlsafe(32)}"
    record = {
        "schema": 1,
        "algorithm": "sha256",
        "digest": hashlib.sha256(token.encode("utf-8")).hexdigest(),
    }
    CLIENT_SECRETS_DIR.mkdir(mode=0o2750, parents=True, exist_ok=True)
    os.chmod(CLIENT_SECRETS_DIR, 0o2750)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{client_id}.", dir=CLIENT_SECRETS_DIR)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, client_token_path(client_id))
    finally:
        temporary.unlink(missing_ok=True)
    return token


def validate_client_token(client_id: str) -> str | None:
    path = client_token_path(client_id)
    try:
        record = read_json(path)
        metadata = path.stat()
        mode = metadata.st_mode & 0o777
    except UserError as exc:
        return str(exc)
    if record.get("schema") != 1 or record.get("algorithm") != "sha256":
        return f"client {client_id} has unsupported token metadata"
    if not re.fullmatch(r"[a-f0-9]{64}", str(record.get("digest", ""))):
        return f"client {client_id} has invalid token metadata"
    if mode != 0o640:
        return f"client {client_id} token metadata has unsafe permissions"
    if (
        metadata.st_uid != CONFIG_FILE.stat().st_uid
        or metadata.st_gid != CLIENT_SECRETS_DIR.stat().st_gid
    ):
        return f"client {client_id} token metadata has unsafe ownership"
    return None


def command_version(_: argparse.Namespace) -> None:
    version = VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "development"
    print(f"LabSteward {version}")


def command_plugin_list(_: argparse.Namespace) -> None:
    config = load_config()
    for plugin_id, plugin in catalog_plugins().items():
        installed = config["plugins"].get(plugin_id)
        state = f"installed {installed['version']}" if installed else plugin.get("status", "unavailable")
        print(f"{plugin_id}\t{state}\t{plugin.get('name', plugin_id)}")


def command_configure(_: argparse.Namespace) -> None:
    config = load_config()
    catalog = catalog_plugins()
    available = [item["id"] for item in catalog.values() if item.get("status") == "available"]
    installed = sorted(config["plugins"])
    servers = sorted(config["servers"])
    print("LabSteward configuration")
    print(f"  Available plugins: {', '.join(available) if available else 'none released yet'}")
    print(f"  Installed plugins: {', '.join(installed) if installed else 'none'}")
    print(f"  Registered servers: {', '.join(servers) if servers else 'none'}")
    print("\nConfiguration order:")
    print("  1. stewctl transport tls create --host IP_OR_DNS")
    print("  2. stewctl transport configure --bind IP [--host DNS_NAME]")
    print("  3. stewctl client add CLIENT --source IP_OR_CIDR")
    print("  4. stewctl transport enable")
    print("  5. Connect an MCP client and call core_status")
    print("  6. Install and configure plugins only after transport validation")


def command_client_list(_: argparse.Namespace) -> None:
    clients = load_config()["clients"]
    if not clients:
        print("No remote clients are registered.")
        return
    for client_id, client in sorted(clients.items()):
        state = "enabled" if client.get("enabled") else "revoked"
        sources = ",".join(client.get("sources", [])) or "none"
        grants = len(client.get("grants", {}))
        print(f"{client_id}\t{state}\t{sources}\t{grants} server grant(s)")


def command_client_add(args: argparse.Namespace) -> None:
    client_id = require_identifier(args.client, "client ID", IDENTIFIER)
    sources = sorted({require_source(source) for source in args.source})
    config = load_config()
    if client_id in config["clients"]:
        raise UserError(f"Client already exists: {client_id}")
    token = write_client_token(client_id)
    config["clients"][client_id] = {"enabled": True, "sources": sources, "grants": {}}
    try:
        save_config(config)
    except Exception:
        client_token_path(client_id).unlink(missing_ok=True)
        raise
    print(f"Registered client {client_id} with no server permissions.")
    print("Client token (shown once; transfer and store it securely):")
    print(token)


def command_client_revoke(args: argparse.Namespace) -> None:
    client_id = require_identifier(args.client, "client ID", IDENTIFIER)
    config = load_config()
    client = config["clients"].get(client_id)
    if not client:
        raise UserError(f"Unknown client: {client_id}")
    if not args.yes:
        raise UserError("Client revocation requires --yes")
    client["enabled"] = False
    client["grants"] = {}
    save_config(config)
    client_token_path(client_id).unlink(missing_ok=True)
    print(f"Revoked client {client_id} and removed its token metadata.")


def command_client_rotate_token(args: argparse.Namespace) -> None:
    client_id = require_identifier(args.client, "client ID", IDENTIFIER)
    client = load_config()["clients"].get(client_id)
    if not client:
        raise UserError(f"Unknown client: {client_id}")
    if not client.get("enabled"):
        raise UserError("Cannot rotate a revoked client; register a new client instead")
    token = write_client_token(client_id)
    print(f"Rotated the token for client {client_id}; the previous token is now invalid.")
    print("Client token (shown once; transfer and store it securely):")
    print(token)


def command_client_source_set(args: argparse.Namespace) -> None:
    client_id = require_identifier(args.client, "client ID", IDENTIFIER)
    sources = sorted({require_source(source) for source in args.sources})
    config = load_config()
    client = config["clients"].get(client_id)
    if not client:
        raise UserError(f"Unknown client: {client_id}")
    if not client.get("enabled"):
        raise UserError("Cannot modify a revoked client")
    client["sources"] = sources
    save_config(config)
    print(f"Set {len(sources)} source restriction(s) for client {client_id}.")


def command_client_permission_set(args: argparse.Namespace) -> None:
    client_id = require_identifier(args.client, "client ID", IDENTIFIER)
    alias = require_identifier(args.server, "server alias", ALIAS)
    permissions = sorted({require_identifier(item, "permission", PERMISSION) for item in args.permissions})
    config = load_config()
    client = config["clients"].get(client_id)
    if not client:
        raise UserError(f"Unknown client: {client_id}")
    if not client.get("enabled"):
        raise UserError("Cannot modify a revoked client")
    server = config["servers"].get(alias)
    if not server:
        raise UserError(f"Unknown server alias: {alias}")
    unauthorized = sorted(set(permissions) - set(server.get("permissions", [])))
    if unauthorized:
        raise UserError(
            f"Client permissions exceed the server grant for {alias}: {', '.join(unauthorized)}"
        )
    if permissions:
        client["grants"][alias] = permissions
    else:
        client["grants"].pop(alias, None)
    save_config(config)
    print(f"Set {len(permissions)} permission(s) for client {client_id} on {alias}.")


def command_plugin_install(args: argparse.Namespace) -> None:
    plugin_id = require_identifier(args.plugin, "plugin ID", IDENTIFIER)
    plugin = catalog_plugins().get(plugin_id)
    if not plugin:
        raise UserError("Plugin is not in the approved release catalog")
    if plugin.get("status") != "available":
        raise UserError(f"Plugin {plugin_id} is catalogued but not yet available")
    raise UserError("Plugin package installation will be enabled with the first reviewed plugin release")


def command_plugin_remove(args: argparse.Namespace) -> None:
    plugin_id = require_identifier(args.plugin, "plugin ID", IDENTIFIER)
    config = load_config()
    users = [alias for alias, server in config["servers"].items() if server.get("plugin") == plugin_id]
    if users:
        raise UserError(f"Plugin {plugin_id} is still used by: {', '.join(sorted(users))}")
    raise UserError("Plugin removal will be enabled with the first reviewed plugin release")


def command_server_list(_: argparse.Namespace) -> None:
    for alias, server in sorted(load_config()["servers"].items()):
        permissions = ",".join(server.get("permissions", [])) or "none"
        print(f"{alias}\t{server.get('plugin')}\t{server.get('endpoint')}\t{permissions}")


def command_server_add(args: argparse.Namespace) -> None:
    alias = require_identifier(args.alias, "server alias", ALIAS)
    plugin_id = require_identifier(args.plugin, "plugin ID", IDENTIFIER)
    endpoint = require_endpoint(args.endpoint)
    config = load_config()
    if alias in config["servers"]:
        raise UserError(f"Server alias already exists: {alias}")
    installed = config["plugins"].get(plugin_id)
    if not installed or not installed.get("enabled"):
        raise UserError(f"Plugin must be installed and enabled first: {plugin_id}")
    config["servers"][alias] = {"plugin": plugin_id, "endpoint": endpoint, "permissions": []}
    save_config(config)
    print(f"Added server {alias} with no permissions. Grant permissions explicitly before use.")


def command_server_remove(args: argparse.Namespace) -> None:
    alias = require_identifier(args.alias, "server alias", ALIAS)
    config = load_config()
    if alias not in config["servers"]:
        raise UserError(f"Unknown server alias: {alias}")
    if not args.yes:
        raise UserError("Server removal requires --yes; credentials are not removed by this command")
    client_users = [
        client_id
        for client_id, client in config["clients"].items()
        if alias in client.get("grants", {})
    ]
    if client_users:
        raise UserError(
            f"Remove client grants for {alias} first: {', '.join(sorted(client_users))}"
        )
    del config["servers"][alias]
    save_config(config)
    print(f"Removed server registration {alias}; inspect protected credentials separately.")


def command_permission_set(args: argparse.Namespace) -> None:
    alias = require_identifier(args.alias, "server alias", ALIAS)
    permissions = sorted({require_identifier(item, "permission", PERMISSION) for item in args.permissions})
    config = load_config()
    server = config["servers"].get(alias)
    if not server:
        raise UserError(f"Unknown server alias: {alias}")
    plugin = catalog_plugins().get(server["plugin"], {})
    allowed = set(plugin.get("permissions", []))
    unknown = sorted(set(permissions) - allowed)
    if unknown:
        raise UserError(f"Permission is not declared by plugin {server['plugin']}: {', '.join(unknown)}")
    client_users = [
        client_id
        for client_id, client in config["clients"].items()
        if set(client.get("grants", {}).get(alias, [])) - set(permissions)
    ]
    if client_users:
        raise UserError(
            f"Reduce client permissions for {alias} first: {', '.join(sorted(client_users))}"
        )
    server["permissions"] = permissions
    save_config(config)
    print(f"Set {len(permissions)} permission(s) for {alias}.")


def validation_errors(config: dict, catalog: dict[str, dict]) -> list[str]:
    errors = []
    if not SELF_UPDATE.is_file() or not os.access(SELF_UPDATE, os.X_OK):
        errors.append(f"self-update helper is missing or not executable: {SELF_UPDATE}")
    try:
        schema = read_json(SCHEMA_FILE)
        if schema.get("title") != "LabSteward appliance configuration":
            errors.append("configuration schema metadata is invalid")
    except UserError as exc:
        errors.append(str(exc))
    for label, path in (
        ("output sanitizer", SANITIZER_FILE),
        ("core dispatcher", CORE_FILE),
        ("MCP transport", MCP_FILE),
    ):
        try:
            source = path.read_text(encoding="utf-8")
            compile(source, str(path), "exec")
        except (OSError, SyntaxError) as exc:
            errors.append(f"{label} is missing or invalid: {exc}")
    if not SYSTEMD_UNIT_FILE.is_file():
        errors.append(f"MCP service unit is missing: {SYSTEMD_UNIT_FILE}")
    else:
        core_group = BASE_DIR.stat().st_gid
        unit_error = validate_file_security(SYSTEMD_UNIT_FILE, 0o644, core_group)
        if unit_error:
            errors.append(unit_error)
    for path, mode in (
        (SELF_UPDATE, 0o755),
        (SANITIZER_FILE, 0o644),
        (CORE_FILE, 0o644),
        (MCP_FILE, 0o644),
    ):
        core_group = BASE_DIR.stat().st_gid
        security_error = validate_file_security(path, mode, core_group)
        if security_error:
            errors.append(security_error)
    if TRANSPORT_CONFIG_FILE.exists():
        try:
            validate_transport_config()
        except UserError as exc:
            errors.append(str(exc))
        core_group = BASE_DIR.stat().st_gid
        service_group = CONFIG_FILE.stat().st_gid
        protected_files = (
            (TRANSPORT_CONFIG_FILE, 0o640, service_group),
            (tls_paths()["ca_key"], 0o600, core_group),
            (tls_paths()["ca_cert"], 0o644, core_group),
            (tls_paths()["server_key"], 0o640, service_group),
            (tls_paths()["server_cert"], 0o644, core_group),
        )
        for path, mode, group_id in protected_files:
            security_error = validate_file_security(path, mode, group_id)
            if security_error:
                errors.append(security_error)
    for plugin_id, installed in config["plugins"].items():
        if plugin_id not in catalog:
            errors.append(f"installed plugin is absent from catalog: {plugin_id}")
        if not isinstance(installed, dict) or not isinstance(installed.get("enabled"), bool):
            errors.append(f"invalid installed plugin record: {plugin_id}")
    for alias, server in config["servers"].items():
        if not isinstance(server, dict):
            errors.append(f"invalid server record: {alias}")
            continue
        try:
            require_identifier(alias, "server alias", ALIAS)
            require_endpoint(server.get("endpoint", ""))
        except UserError as exc:
            errors.append(str(exc))
            continue
        plugin_id = server.get("plugin")
        if plugin_id not in config["plugins"]:
            errors.append(f"server {alias} uses an uninstalled plugin: {plugin_id}")
            continue
        if not isinstance(server.get("permissions"), list):
            errors.append(f"server {alias} has an invalid permission list")
            continue
        allowed = set(catalog.get(plugin_id, {}).get("permissions", []))
        unknown = set(server.get("permissions", [])) - allowed
        if unknown:
            errors.append(f"server {alias} has undeclared permissions: {', '.join(sorted(unknown))}")
    for client_id, client in config["clients"].items():
        try:
            require_identifier(client_id, "client ID", IDENTIFIER)
        except UserError as exc:
            errors.append(str(exc))
            continue
        if not isinstance(client, dict):
            errors.append(f"invalid client record: {client_id}")
            continue
        enabled = client.get("enabled")
        sources = client.get("sources")
        grants = client.get("grants")
        if not isinstance(enabled, bool):
            errors.append(f"client {client_id} has an invalid enabled state")
        if not isinstance(sources, list) or not sources:
            errors.append(f"client {client_id} must have at least one source restriction")
        else:
            for source in sources:
                try:
                    require_source(source)
                except (UserError, TypeError) as exc:
                    errors.append(f"client {client_id}: {exc}")
        if not isinstance(grants, dict):
            errors.append(f"client {client_id} has an invalid grant registry")
        else:
            for alias, permissions in grants.items():
                server = config["servers"].get(alias)
                if not server:
                    errors.append(f"client {client_id} has a grant for unknown server {alias}")
                    continue
                if not isinstance(permissions, list):
                    errors.append(f"client {client_id} has invalid permissions for {alias}")
                    continue
                unauthorized = set(permissions) - set(server.get("permissions", []))
                if unauthorized:
                    errors.append(
                        f"client {client_id} exceeds the server grant for {alias}: "
                        f"{', '.join(sorted(unauthorized))}"
                    )
        if enabled:
            token_error = validate_client_token(client_id)
            if token_error:
                errors.append(token_error)
        elif client_token_path(client_id).exists():
            errors.append(f"revoked client {client_id} retains token metadata")
    return errors


def command_validate(_: argparse.Namespace) -> None:
    config = load_config()
    catalog = catalog_plugins()
    errors = validation_errors(config, catalog)
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        raise UserError(f"Validation failed with {len(errors)} error(s)")
    print("PASS: LabSteward registry is internally consistent")


def command_status(_: argparse.Namespace) -> None:
    config = load_config()
    catalog = catalog_plugins()
    errors = validation_errors(config, catalog)
    if errors:
        print("LabSteward core: unhealthy", file=sys.stderr)
        for error in errors:
            print(f"  FAIL: {error}", file=sys.stderr)
        raise UserError(f"Status check failed with {len(errors)} error(s)")
    version = VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "development"
    enabled_clients = sum(1 for client in config["clients"].values() if client.get("enabled"))
    print("LabSteward core: healthy")
    print(f"  Version: {version}")
    print(f"  Catalogued plugins: {len(catalog)}")
    print(f"  Installed plugins: {len(config['plugins'])}")
    print(f"  Registered servers: {len(config['servers'])}")
    print(f"  Enabled remote clients: {enabled_clients}")
    if TRANSPORT_CONFIG_FILE.exists():
        print(f"  Remote transport: configured ({transport_service_state()})")
    else:
        print("  Remote transport: not configured")


def command_action_run(args: argparse.Namespace) -> None:
    if not CORE_FILE.is_file():
        raise UserError(f"Core dispatcher is missing: {CORE_FILE}")
    sys.path.insert(0, str(CORE_FILE.parent))
    try:
        spec = importlib.util.spec_from_file_location("labsteward_core", CORE_FILE)
        if spec is None or spec.loader is None:
            raise UserError("Unable to load the LabSteward core dispatcher")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    try:
        result = module.dispatch_action(args.action, {})
    except module.DispatchError as exc:
        raise UserError(exc.message) from exc
    print(json.dumps(result, indent=2, sort_keys=True))


def run_openssl(*arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [OPENSSL, *arguments],
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise UserError("OpenSSL could not create or validate the transport certificate") from exc


def command_transport_tls_create(args: argparse.Namespace) -> None:
    hosts = list(dict.fromkeys(require_transport_host(host) for host in args.host))
    paths = tls_paths()
    existing = [path for path in paths.values() if path.exists()]
    if existing and not (args.force and args.yes):
        raise UserError("Transport TLS material already exists; replacement requires --force --yes")
    TLS_DIR.mkdir(mode=0o2750, parents=True, exist_ok=True)
    os.chmod(TLS_DIR, 0o2750)
    if CONFIG_FILE.exists():
        metadata = CONFIG_FILE.stat()
        os.chown(TLS_DIR, metadata.st_uid, metadata.st_gid)
    with tempfile.TemporaryDirectory(prefix="labsteward-tls.") as directory:
        work = Path(directory)
        ca_key = work / "ca.key"
        ca_cert = work / "ca.crt"
        server_key = work / "server.key"
        server_request = work / "server.csr"
        server_cert = work / "server.crt"
        extensions = work / "server-ext.cnf"
        san_entries = []
        for index, host in enumerate(hosts, start=1):
            try:
                ipaddress.ip_address(host)
                san_entries.append(f"IP.{index} = {host}")
            except ValueError:
                san_entries.append(f"DNS.{index} = {host}")
        extensions.write_text(
            "[server]\n"
            "basicConstraints = critical,CA:FALSE\n"
            "keyUsage = critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid,issuer\n"
            "subjectAltName = @alt_names\n"
            "[alt_names]\n"
            + "\n".join(san_entries)
            + "\n",
            encoding="utf-8",
        )
        run_openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(ca_key))
        run_openssl(
            "req", "-x509", "-new", "-sha256", "-key", str(ca_key), "-out", str(ca_cert),
            "-days", "3650", "-subj", "/CN=LabSteward Local CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        )
        run_openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(server_key))
        run_openssl(
            "req", "-new", "-sha256", "-key", str(server_key), "-out", str(server_request),
            "-subj", f"/CN={hosts[0]}",
        )
        run_openssl(
            "x509", "-req", "-sha256", "-in", str(server_request), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(server_cert),
            "-days", "825", "-extfile", str(extensions), "-extensions", "server",
        )
        install_tls_file(ca_key, paths["ca_key"], 0o600, False)
        install_tls_file(ca_cert, paths["ca_cert"], 0o644, False)
        install_tls_file(server_key, paths["server_key"], 0o640, True)
        install_tls_file(server_cert, paths["server_cert"], 0o644, False)
    pem = paths["ca_cert"].read_text(encoding="ascii")
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
    formatted = ":".join(fingerprint[index:index + 2] for index in range(0, len(fingerprint), 2))
    print("Created a private LabSteward CA and server certificate.")
    print(f"Client trust certificate: {paths['ca_cert']}")
    print(f"CA SHA-256 fingerprint: {formatted}")


def certificate_covers(host: str, cert_file: Path) -> None:
    try:
        ipaddress.ip_address(host)
        check_argument = "-checkip"
    except ValueError:
        check_argument = "-checkhost"
    result = run_openssl("x509", "-in", str(cert_file), check_argument, host, "-noout")
    if "does match" not in result.stdout:
        raise UserError(f"Transport certificate does not cover allowed host: {host}")


def command_transport_configure(args: argparse.Namespace) -> None:
    bind = require_bind_address(args.bind)
    hosts = list(dict.fromkeys([bind, *(require_transport_host(host) for host in args.host)]))
    if len(hosts) > 16:
        raise UserError("Transport accepts at most sixteen allowed hosts")
    paths = tls_paths()
    for host in hosts:
        certificate_covers(host, paths["server_cert"])
    record = {
        "schema": 1,
        "bind": bind,
        "port": args.port,
        "allowed_hosts": hosts,
        "cert_file": str(paths["server_cert"]),
        "key_file": str(paths["server_key"]),
    }
    save_json(TRANSPORT_CONFIG_FILE, record)
    validate_transport_config()
    print(f"Configured TLS-only MCP transport at https://{bind}:{args.port}/mcp.")
    if transport_service_state() == "active":
        print("Configuration saved; apply it with: stewctl transport restart")
    else:
        print("The service remains disabled until: stewctl transport enable")


def command_transport_enable(_: argparse.Namespace) -> None:
    validate_transport_config()
    systemctl("daemon-reload")
    systemctl("enable", "--now", "labsteward.service")
    if transport_service_state() != "active":
        raise UserError("labsteward.service did not become active")
    print("Enabled and started the LabSteward MCP transport.")


def command_transport_disable(_: argparse.Namespace) -> None:
    systemctl("disable", "--now", "labsteward.service")
    print("Disabled and stopped the LabSteward MCP transport.")


def command_transport_restart(_: argparse.Namespace) -> None:
    validate_transport_config()
    systemctl("restart", "labsteward.service")
    if transport_service_state() != "active":
        raise UserError("labsteward.service did not become active")
    print("Restarted the LabSteward MCP transport.")


def command_transport_status(_: argparse.Namespace) -> None:
    if not TRANSPORT_CONFIG_FILE.exists():
        print("LabSteward remote transport: not configured")
        return
    config = validate_transport_config()
    print("LabSteward remote transport: configured")
    print(f"  Endpoint: https://{config['bind']}:{config['port']}/mcp")
    print(f"  Service: {transport_service_state()}")
    print(f"  Allowed Host values: {', '.join(config['allowed_hosts'])}")


def command_transport_test(_: argparse.Namespace) -> None:
    config = validate_transport_config()
    if transport_service_state() != "active":
        raise UserError("LabSteward transport is not active")
    paths = tls_paths()
    context = ssl.create_default_context(cafile=str(paths["ca_cert"]))
    connection = http.client.HTTPSConnection(
        config["bind"], config["port"], timeout=5, context=context
    )
    try:
        connection.request(
            "POST",
            "/mcp",
            body=b"{}",
            headers={"Content-Type": "application/json", "Host": config["bind"]},
        )
        response = connection.getresponse()
        response.read()
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise UserError("TLS connection to the LabSteward transport failed") from exc
    finally:
        connection.close()
    if response.status != 401:
        raise UserError("Transport did not reject the unauthenticated test request")
    print("PASS: TLS transport is reachable and rejects unauthenticated requests")
    print("A registered remote MCP client is still required for an authenticated end-to-end test.")


def command_self_update(_: argparse.Namespace) -> None:
    if not SELF_UPDATE.is_file():
        raise UserError(f"Self-update helper is missing: {SELF_UPDATE}")
    os.execv(str(SELF_UPDATE), [str(SELF_UPDATE)])


def command_update_check(_: argparse.Namespace) -> None:
    if not SELF_UPDATE.is_file():
        raise UserError(f"Self-update helper is missing: {SELF_UPDATE}")
    os.execv(str(SELF_UPDATE), [str(SELF_UPDATE), "--check"])


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="stewctl", description="Manage the LabSteward appliance")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("version").set_defaults(handler=command_version)
    commands.add_parser("status", aliases=["health"]).set_defaults(handler=command_status)
    commands.add_parser("configure").set_defaults(handler=command_configure)
    commands.add_parser("validate").set_defaults(handler=command_validate)
    commands.add_parser("self-update").set_defaults(handler=command_self_update)

    action = commands.add_parser("action")
    action_commands = action.add_subparsers(dest="action_command", required=True)
    run_action = action_commands.add_parser("run")
    run_action.add_argument("action", choices=["core.status"])
    run_action.set_defaults(handler=command_action_run)

    transport = commands.add_parser("transport")
    transport_commands = transport.add_subparsers(dest="transport_command", required=True)
    transport_commands.add_parser("status").set_defaults(handler=command_transport_status)
    transport_commands.add_parser("enable").set_defaults(handler=command_transport_enable)
    transport_commands.add_parser("disable").set_defaults(handler=command_transport_disable)
    transport_commands.add_parser("restart").set_defaults(handler=command_transport_restart)
    transport_commands.add_parser("test").set_defaults(handler=command_transport_test)
    configure_transport = transport_commands.add_parser("configure")
    configure_transport.add_argument("--bind", required=True)
    configure_transport.add_argument("--port", type=int, default=9443, choices=range(1024, 65536))
    configure_transport.add_argument("--host", action="append", default=[])
    configure_transport.set_defaults(handler=command_transport_configure)
    transport_tls = transport_commands.add_parser("tls")
    transport_tls_commands = transport_tls.add_subparsers(
        dest="transport_tls_command", required=True
    )
    create_transport_tls = transport_tls_commands.add_parser("create")
    create_transport_tls.add_argument("--host", action="append", required=True)
    create_transport_tls.add_argument("--force", action="store_true")
    create_transport_tls.add_argument("--yes", action="store_true")
    create_transport_tls.set_defaults(handler=command_transport_tls_create)

    update = commands.add_parser("update")
    update_commands = update.add_subparsers(dest="update_command", required=True)
    update_commands.add_parser("check").set_defaults(handler=command_update_check)
    update_commands.add_parser("apply").set_defaults(handler=command_self_update)

    plugin = commands.add_parser("plugin", aliases=["plugins"])
    plugin_commands = plugin.add_subparsers(dest="plugin_command", required=True)
    plugin_commands.add_parser("list").set_defaults(handler=command_plugin_list)
    install = plugin_commands.add_parser("install")
    install.add_argument("plugin")
    install.set_defaults(handler=command_plugin_install)
    remove = plugin_commands.add_parser("remove")
    remove.add_argument("plugin")
    remove.set_defaults(handler=command_plugin_remove)

    server = commands.add_parser("server", aliases=["servers"])
    server_commands = server.add_subparsers(dest="server_command", required=True)
    server_commands.add_parser("list").set_defaults(handler=command_server_list)
    add = server_commands.add_parser("add")
    add.add_argument("alias")
    add.add_argument("--plugin", required=True)
    add.add_argument("--endpoint", required=True)
    add.set_defaults(handler=command_server_add)
    remove_server = server_commands.add_parser("remove")
    remove_server.add_argument("alias")
    remove_server.add_argument("--yes", action="store_true")
    remove_server.set_defaults(handler=command_server_remove)

    client = commands.add_parser("client", aliases=["clients"])
    client_commands = client.add_subparsers(dest="client_command", required=True)
    client_commands.add_parser("list").set_defaults(handler=command_client_list)
    add_client = client_commands.add_parser("add")
    add_client.add_argument("client")
    add_client.add_argument("--source", action="append", required=True)
    add_client.set_defaults(handler=command_client_add)
    revoke_client = client_commands.add_parser("revoke")
    revoke_client.add_argument("client")
    revoke_client.add_argument("--yes", action="store_true")
    revoke_client.set_defaults(handler=command_client_revoke)
    rotate_client = client_commands.add_parser("rotate-token")
    rotate_client.add_argument("client")
    rotate_client.set_defaults(handler=command_client_rotate_token)
    client_source = client_commands.add_parser("source")
    client_source_commands = client_source.add_subparsers(dest="client_source_command", required=True)
    set_client_sources = client_source_commands.add_parser("set")
    set_client_sources.add_argument("client")
    set_client_sources.add_argument("sources", nargs="+")
    set_client_sources.set_defaults(handler=command_client_source_set)
    client_permission = client_commands.add_parser("permission")
    client_permission_commands = client_permission.add_subparsers(
        dest="client_permission_command", required=True
    )
    set_client_permissions = client_permission_commands.add_parser("set")
    set_client_permissions.add_argument("client")
    set_client_permissions.add_argument("server")
    set_client_permissions.add_argument("permissions", nargs="*")
    set_client_permissions.set_defaults(handler=command_client_permission_set)

    permission = commands.add_parser("permission", aliases=["permissions"])
    permission_commands = permission.add_subparsers(dest="permission_command", required=True)
    set_permissions = permission_commands.add_parser("set")
    set_permissions.add_argument("alias")
    set_permissions.add_argument("permissions", nargs="*")
    set_permissions.set_defaults(handler=command_permission_set)
    return root


def main() -> int:
    try:
        require_root()
        args = parser().parse_args()
        args.handler(args)
        return 0
    except UserError as exc:
        print(f"stewctl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
