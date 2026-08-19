#!/usr/bin/env bash
set -Eeuo pipefail

source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

msg_info "Installing LabSteward core dependencies"
$STD apt-get install -y ca-certificates curl jq openssl python3
msg_ok "Installed LabSteward core dependencies"

msg_info "Creating the LabSteward security boundary"
getent group labsteward >/dev/null || groupadd --system labsteward
id labsteward >/dev/null 2>&1 || useradd --system --gid labsteward --home-dir /var/lib/labsteward \
  --create-home --shell /usr/sbin/nologin labsteward
install -d -o root -g root -m 0755 /opt/labsteward /opt/labsteward/lib /opt/labsteward/catalog /opt/labsteward/schemas /opt/labsteward/plugins
install -d -o root -g labsteward -m 2750 /etc/labsteward
install -d -o root -g labsteward -m 2750 /etc/labsteward/secrets /etc/labsteward/secrets/clients
install -d -o labsteward -g labsteward -m 0700 /var/lib/labsteward

cat >/etc/labsteward/config.json <<'EOF_CONFIG'
{
  "schema": 1,
  "plugins": {},
  "servers": {},
  "clients": {}
}
EOF_CONFIG
chown root:labsteward /etc/labsteward/config.json
chmod 0640 /etc/labsteward/config.json

cat >/usr/local/bin/stewctl <<'EOF_LABSTEWARD_MANAGER'
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
EOF_LABSTEWARD_MANAGER
chmod 0755 /usr/local/bin/stewctl
ln -sfn /usr/local/bin/stewctl /usr/local/bin/labsteward
cat >/opt/labsteward/lib/self-update.sh <<'EOF_LABSTEWARD_UPDATE'
#!/usr/bin/env bash
set -Eeuo pipefail

readonly BASE_DIR="${LABSTEWARD_BASE_DIR:-/opt/labsteward}"
readonly MANAGER_PATH="${LABSTEWARD_MANAGER_PATH:-/usr/local/bin/stewctl}"
readonly MANAGER_ALIAS_PATH="${LABSTEWARD_MANAGER_ALIAS_PATH:-/usr/local/bin/labsteward}"
readonly SANITIZER_PATH="${LABSTEWARD_SANITIZER_PATH:-${BASE_DIR}/lib/labsteward_sanitize.py}"
readonly CORE_PATH="${LABSTEWARD_CORE_FILE:-${BASE_DIR}/lib/labsteward_core.py}"
readonly MCP_PATH="${LABSTEWARD_MCP_FILE:-${BASE_DIR}/lib/labsteward_mcp.py}"
readonly SYSTEMD_UNIT_PATH="${LABSTEWARD_SYSTEMD_UNIT:-/etc/systemd/system/labsteward.service}"
readonly SYSTEMCTL="${LABSTEWARD_SYSTEMCTL:-/usr/bin/systemctl}"
readonly VERSION_FILE="${LABSTEWARD_VERSION_FILE:-${BASE_DIR}/VERSION}"
readonly UPDATE_URL_FILE="${BASE_DIR}/update.url"
readonly DEFAULT_UPDATE_URL="https://github.com/donselkirk/LabSteward/releases/latest/download"

check_only=0
case "${1:-}" in
  "") ;;
  --check) check_only=1 ;;
  *)
    echo "Usage: stewctl update check | stewctl update apply" >&2
    exit 2
    ;;
esac

[[ $EUID -eq 0 || "${LABSTEWARD_ALLOW_NON_ROOT:-0}" == "1" ]] || {
  echo "Run LabSteward update commands as root." >&2
  exit 1
}

update_url="${LABSTEWARD_UPDATE_BASE_URL:-}"
if [[ -z "$update_url" && -r "$UPDATE_URL_FILE" ]]; then
  update_url="$(<"$UPDATE_URL_FILE")"
fi
update_url="${update_url:-$DEFAULT_UPDATE_URL}"
update_url="${update_url%/}"

stage="$(mktemp -d)"
backup=""
runtime_bundle=0
service_was_active=0
cleanup() {
  rm -rf "$stage"
  [[ -z "$backup" ]] || rm -rf "$backup"
}
trap cleanup EXIT

download_asset() {
  local url="$1"
  local destination="$2"
  local label="$3"
  if curl -fsSL --retry 3 --retry-all-errors "$url" -o "$destination"; then
    return 0
  fi
  echo "Unable to download ${label} from the configured update source." >&2
  if [[ "$url" == https://github.com/donselkirk/LabSteward/* ]]; then
    echo "Private GitHub releases are unavailable to the unauthenticated updater; use a reviewed manual upgrade until the repository is public." >&2
  fi
  return 1
}

download_asset "${update_url}/VERSION" "${stage}/VERSION" "release metadata"
grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' "${stage}/VERSION" || {
  echo "Release version metadata is invalid." >&2
  exit 1
}
release_version="$(<"${stage}/VERSION")"
current_version="v0.0.0"
if [[ -r "$VERSION_FILE" ]] && grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' "$VERSION_FILE"; then
  current_version="$(<"$VERSION_FILE")"
fi
if [[ "$(printf '%s\n%s\n' "$release_version" "$current_version" | sort -V | sed -n '1p')" == "$release_version" \
  && "$release_version" != "$current_version" ]]; then
  echo "Refusing to downgrade LabSteward from ${current_version} to ${release_version}." >&2
  exit 1
fi
if [[ "$release_version" == "$current_version" ]]; then
  echo "LabSteward is already current at ${release_version}."
  exit 0
fi
if ((check_only)); then
  echo "LabSteward update available: ${current_version} -> ${release_version}."
  exit 0
fi

asset_url="$update_url"
if [[ "$update_url" == "$DEFAULT_UPDATE_URL" ]]; then
  asset_url="https://github.com/donselkirk/LabSteward/releases/download/${release_version}"
fi

download_asset "${asset_url}/SHA256SUMS" "${stage}/SHA256SUMS" "SHA256SUMS"
required_assets=(stewctl self-update.sh labsteward-sanitize.py plugins.json config.schema.json)
optional_runtime_assets=(labsteward-core.py labsteward-mcp.py labsteward.service)
for asset in "${required_assets[@]}"; do
  grep -q " ${asset}$" "${stage}/SHA256SUMS" || {
    echo "LabSteward release is missing required checksum metadata for ${asset}." >&2
    exit 1
  }
  download_asset "${asset_url}/${asset}" "${stage}/${asset}" "$asset"
done
optional_count=0
for asset in "${optional_runtime_assets[@]}"; do
  if grep -q " ${asset}$" "${stage}/SHA256SUMS"; then
    optional_count=$((optional_count + 1))
  fi
done
if ((optional_count != 0 && optional_count != ${#optional_runtime_assets[@]})); then
  echo "LabSteward release contains an incomplete runtime bundle." >&2
  exit 1
fi
if ((optional_count)); then
  runtime_bundle=1
  for asset in "${optional_runtime_assets[@]}"; do
    download_asset "${asset_url}/${asset}" "${stage}/${asset}" "$asset"
  done
fi
(
  cd "$stage"
  grep -q " VERSION$" SHA256SUMS || exit 1
  sha256sum -c --ignore-missing SHA256SUMS >/dev/null
) || {
  echo "LabSteward release assets failed checksum validation." >&2
  exit 1
}

rollback() {
  trap - ERR
  echo "Update validation failed; restoring the previous LabSteward core." >&2
  [[ ! -e "${backup}/manager" ]] || cp -a "${backup}/manager" "$MANAGER_PATH"
  [[ ! -e "${backup}/self-update.sh" ]] || cp -a "${backup}/self-update.sh" "${BASE_DIR}/lib/self-update.sh"
  [[ ! -e "${backup}/labsteward_sanitize.py" ]] || cp -a "${backup}/labsteward_sanitize.py" "$SANITIZER_PATH"
  if ((runtime_bundle)); then
    if [[ -e "${backup}/labsteward_core.py" ]]; then
      cp -a "${backup}/labsteward_core.py" "$CORE_PATH"
    else
      rm -f "$CORE_PATH"
    fi
    if [[ -e "${backup}/labsteward_mcp.py" ]]; then
      cp -a "${backup}/labsteward_mcp.py" "$MCP_PATH"
    else
      rm -f "$MCP_PATH"
    fi
    if [[ -e "${backup}/labsteward.service" ]]; then
      cp -a "${backup}/labsteward.service" "$SYSTEMD_UNIT_PATH"
    else
      rm -f "$SYSTEMD_UNIT_PATH"
    fi
    "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true
    if ((service_was_active)); then
      "$SYSTEMCTL" restart labsteward.service >/dev/null 2>&1 || true
    fi
  fi
  [[ ! -e "${backup}/plugins.json" ]] || cp -a "${backup}/plugins.json" "${BASE_DIR}/catalog/plugins.json"
  [[ ! -e "${backup}/config.schema.json" ]] || cp -a "${backup}/config.schema.json" "${BASE_DIR}/schemas/config.schema.json"
  [[ ! -e "${backup}/VERSION" ]] || cp -a "${backup}/VERSION" "$VERSION_FILE"
  [[ ! -e "${backup}/update.url" ]] || cp -a "${backup}/update.url" "$UPDATE_URL_FILE"
  rm -rf "$backup"
  backup=""
}

backup="$(mktemp -d "${BASE_DIR}/.rollback.XXXXXX")"
trap rollback ERR
install -d -m 0755 "$backup" "${BASE_DIR}/lib" "${BASE_DIR}/catalog" "${BASE_DIR}/schemas"
[[ ! -e "$MANAGER_PATH" ]] || cp -a "$MANAGER_PATH" "${backup}/manager"
[[ ! -e "${BASE_DIR}/lib/self-update.sh" ]] || cp -a "${BASE_DIR}/lib/self-update.sh" "${backup}/self-update.sh"
[[ ! -e "$SANITIZER_PATH" ]] || cp -a "$SANITIZER_PATH" "${backup}/labsteward_sanitize.py"
if ((runtime_bundle)); then
  if "$SYSTEMCTL" is-active --quiet labsteward.service >/dev/null 2>&1; then
    service_was_active=1
  fi
  [[ ! -e "$CORE_PATH" ]] || cp -a "$CORE_PATH" "${backup}/labsteward_core.py"
  [[ ! -e "$MCP_PATH" ]] || cp -a "$MCP_PATH" "${backup}/labsteward_mcp.py"
  [[ ! -e "$SYSTEMD_UNIT_PATH" ]] || cp -a "$SYSTEMD_UNIT_PATH" "${backup}/labsteward.service"
fi
[[ ! -e "${BASE_DIR}/catalog/plugins.json" ]] || cp -a "${BASE_DIR}/catalog/plugins.json" "${backup}/plugins.json"
[[ ! -e "${BASE_DIR}/schemas/config.schema.json" ]] || cp -a "${BASE_DIR}/schemas/config.schema.json" "${backup}/config.schema.json"
[[ ! -e "$VERSION_FILE" ]] || cp -a "$VERSION_FILE" "${backup}/VERSION"
[[ ! -e "$UPDATE_URL_FILE" ]] || cp -a "$UPDATE_URL_FILE" "${backup}/update.url"
install -m 0755 "${stage}/stewctl" "$MANAGER_PATH"
ln -sfn "$MANAGER_PATH" "$MANAGER_ALIAS_PATH"
install -m 0755 "${stage}/self-update.sh" "${BASE_DIR}/lib/self-update.sh"
install -m 0644 "${stage}/labsteward-sanitize.py" "$SANITIZER_PATH"
if ((runtime_bundle)); then
  install -m 0644 "${stage}/labsteward-core.py" "$CORE_PATH"
  install -m 0644 "${stage}/labsteward-mcp.py" "$MCP_PATH"
  install -D -m 0644 "${stage}/labsteward.service" "$SYSTEMD_UNIT_PATH"
  "$SYSTEMCTL" daemon-reload
fi
install -m 0644 "${stage}/plugins.json" "${BASE_DIR}/catalog/plugins.json"
install -m 0644 "${stage}/config.schema.json" "${BASE_DIR}/schemas/config.schema.json"
install -m 0644 "${stage}/VERSION" "$VERSION_FILE"
printf '%s\n' "$update_url" >"$UPDATE_URL_FILE"
chmod 0644 "$UPDATE_URL_FILE"
"$MANAGER_PATH" validate
if ((runtime_bundle && service_was_active)); then
  "$SYSTEMCTL" restart labsteward.service
fi
trap - ERR
rm -rf "$backup"
backup=""
echo "Updated LabSteward core to ${release_version}."
EOF_LABSTEWARD_UPDATE
chmod 0755 /opt/labsteward/lib/self-update.sh
cat >/opt/labsteward/lib/labsteward_sanitize.py <<'EOF_LABSTEWARD_SANITIZER'
#!/usr/bin/env python3
"""Fail-safe output sanitization for LabSteward plugin results.

Plugins must first construct results from an explicit output schema. This module
is the mandatory defense-in-depth pass applied before results are logged or
returned to a caller.
"""

from __future__ import annotations

import math
import re
from typing import Any

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"
MAX_DEPTH = 12
MAX_ITEMS = 256
MAX_STRING_LENGTH = 8192

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "credential",
    "privatekey",
    "cookie",
    "sessionid",
    "csrf",
    "ticket",
)
_SENSITIVE_KEYS = {"auth", "authorization", "pwd", "sid"}
_BEARER_OR_BASIC = re.compile(
    r"(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]+"
)
_URL_USERINFO = re.compile(r"(?i)\b(https?://)[^\s/@]+@")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b([a-z0-9_-]*(?:password|passwd|passphrase|secret|token|apikey|api_key|"
    r"credential|privatekey|cookie|sessionid|csrf|ticket)[a-z0-9_-]*|authorization|"
    r'''pwd|sid)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s&,;]+)'''
)
_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")


def _normalized_key(key: object) -> str:
    if not isinstance(key, str):
        return ""
    return re.sub(r"[^a-z0-9]", "", key.lower())


def is_sensitive_key(key: object) -> bool:
    """Return whether a result field name implies authentication material."""

    normalized = _normalized_key(key)
    return normalized in _SENSITIVE_KEYS or any(
        part in normalized for part in _SENSITIVE_KEY_PARTS
    )


def sanitize_text(value: str, *, max_length: int = MAX_STRING_LENGTH) -> str:
    """Redact common inline secret forms and cap output size."""

    if "PRIVATE KEY-----" in value.upper():
        return REDACTED
    value = _URL_USERINFO.sub(r"\1[REDACTED]@", value)
    value = _BEARER_OR_BASIC.sub(lambda match: f"{match.group(1)} {REDACTED}", value)
    value = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", value)
    value = _JWT.sub(REDACTED, value)
    if len(value) > max_length:
        value = f"{value[:max_length]}{TRUNCATED}"
    return value


def sanitize_result(
    value: Any,
    *,
    max_depth: int = MAX_DEPTH,
    max_items: int = MAX_ITEMS,
    max_string_length: int = MAX_STRING_LENGTH,
) -> Any:
    """Return a JSON-safe, recursively redacted copy of a plugin result."""

    seen: set[int] = set()

    def walk(item: Any, depth: int) -> Any:
        if depth > max_depth:
            return TRUNCATED
        if item is None or isinstance(item, (bool, int)):
            return item
        if isinstance(item, float):
            return item if math.isfinite(item) else "[UNSUPPORTED NUMBER]"
        if isinstance(item, str):
            return sanitize_text(item, max_length=max_string_length)
        if isinstance(item, bytes):
            return "[BINARY OMITTED]"

        identity = id(item)
        if isinstance(item, dict):
            if identity in seen:
                return TRUNCATED
            seen.add(identity)
            result: dict[str, Any] = {}
            entries = list(item.items())
            for key, child in entries[:max_items]:
                if not isinstance(key, str):
                    result["[UNSUPPORTED KEY]"] = REDACTED
                    continue
                output_key = sanitize_text(key, max_length=256)
                result[output_key] = REDACTED if is_sensitive_key(key) else walk(child, depth + 1)
            if len(entries) > max_items:
                result["_labsteward_truncated"] = len(entries) - max_items
            seen.remove(identity)
            return result

        if isinstance(item, (list, tuple)):
            if identity in seen:
                return TRUNCATED
            seen.add(identity)
            entries = list(item)
            result = [walk(child, depth + 1) for child in entries[:max_items]]
            if len(entries) > max_items:
                result.append(TRUNCATED)
            seen.remove(identity)
            return result

        return f"[UNSUPPORTED TYPE: {type(item).__name__}]"

    if max_depth < 0 or max_items < 1 or max_string_length < 1:
        raise ValueError("Sanitizer limits must be positive")
    return walk(value, 0)
EOF_LABSTEWARD_SANITIZER
chmod 0644 /opt/labsteward/lib/labsteward_sanitize.py
cat >/opt/labsteward/lib/labsteward_core.py <<'EOF_LABSTEWARD_CORE'
#!/usr/bin/env python3
"""Shared, allowlisted LabSteward action dispatcher.

The local manager and remote MCP transport both call this module. Plugins will
register additional fixed actions in later releases; arbitrary commands, URLs,
paths, and upstream requests are intentionally outside this interface.
"""

from __future__ import annotations

import json
import os
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

MAX_JSON_FILE_SIZE = 1024 * 1024


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


def tool_definitions() -> list[dict[str, Any]]:
    """Return the complete allowlisted MCP tool catalog for this core release."""

    return [
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


def dispatch_action(action: str, arguments: Any) -> dict[str, Any]:
    """Run one fixed action and return only its declared, sanitized result."""

    if action not in {"core.status", "core_status"}:
        raise DispatchError("unknown_action", "Unknown LabSteward action")
    if not isinstance(arguments, dict) or arguments:
        raise DispatchError("invalid_arguments", "core.status accepts no arguments")
    # _registry_summary constructs the result from an explicit output allowlist.
    return sanitize_result(_registry_summary())
EOF_LABSTEWARD_CORE
chmod 0644 /opt/labsteward/lib/labsteward_core.py
cat >/opt/labsteward/lib/labsteward_mcp.py <<'EOF_LABSTEWARD_MCP'
#!/usr/bin/env python3
"""Authenticated, TLS-only Streamable HTTP MCP transport for LabSteward."""

from __future__ import annotations

import argparse
import collections
import hashlib
import hmac
import ipaddress
import json
import os
import re
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from labsteward_core import DispatchError, dispatch_action, tool_definitions

BASE_DIR = Path(os.environ.get("LABSTEWARD_BASE_DIR", "/opt/labsteward"))
CONFIG_FILE = Path(os.environ.get("LABSTEWARD_CONFIG_FILE", "/etc/labsteward/config.json"))
CLIENT_SECRETS_DIR = Path(
    os.environ.get("LABSTEWARD_CLIENT_SECRETS_DIR", "/etc/labsteward/secrets/clients")
)
VERSION_FILE = Path(os.environ.get("LABSTEWARD_VERSION_FILE", str(BASE_DIR / "VERSION")))
DEFAULT_TRANSPORT_CONFIG = Path(
    os.environ.get("LABSTEWARD_TRANSPORT_CONFIG", "/etc/labsteward/transport.json")
)

MAX_REQUEST_BYTES = 64 * 1024
MAX_JSON_FILE_BYTES = 1024 * 1024
RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60
MAX_RATE_LIMIT_SOURCES = 1024
MAX_CONCURRENT_CONNECTIONS = 32
CONNECTION_TIMEOUT_SECONDS = 15
SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)
SERVER_NAME = "labsteward"
HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


def audit(event: str, **fields: object) -> None:
    record = {"event": event, "service": SERVER_NAME, **fields}
    print(json.dumps(record, separators=(",", ":"), sort_keys=True), file=sys.stderr, flush=True)


def reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def read_object(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_JSON_FILE_BYTES:
        raise ValueError(f"oversized JSON file: {path}")
    value = json.loads(path.read_text(encoding="utf-8"), parse_constant=reject_json_constant)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def normalize_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def source_allowed(source: str, networks: object) -> bool:
    try:
        address = normalize_address(source)
    except ValueError:
        return False
    if not isinstance(networks, list):
        return False
    for item in networks:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except (TypeError, ValueError):
            continue
        if address.version == network.version and address in network:
            return True
    return False


def authenticate_client(token: str, source: str) -> str | None:
    """Return an enabled client ID only when token and socket source both match."""

    try:
        config = read_object(CONFIG_FILE)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    clients = config.get("clients", {})
    if not isinstance(clients, dict):
        return None
    candidate = hashlib.sha256(token.encode("utf-8")).hexdigest()
    matched_id: str | None = None
    matched_sources: object = None
    # Compare every enabled verifier so timing does not reveal its position.
    for client_id, client in sorted(clients.items()):
        if not isinstance(client_id, str) or not isinstance(client, dict):
            continue
        digest = "0" * 64
        try:
            record = read_object(CLIENT_SECRETS_DIR / f"{client_id}.json")
            stored = record.get("digest")
            if (
                record.get("schema") == 1
                and record.get("algorithm") == "sha256"
                and isinstance(stored, str)
                and re.fullmatch(r"[a-f0-9]{64}", stored)
            ):
                digest = stored
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        token_matches = hmac.compare_digest(candidate, digest)
        if token_matches and client.get("enabled") is True:
            matched_id = client_id
            matched_sources = client.get("sources")
    if matched_id is None or not source_allowed(source, matched_sources):
        return None
    return matched_id


def parse_bearer(value: str | None) -> str | None:
    if not value or not value.startswith("Bearer "):
        return None
    token = value[7:]
    if not re.fullmatch(r"lst_[A-Za-z0-9_-]{43}", token):
        return None
    return token


def validate_transport_config(config: dict[str, Any]) -> tuple[str, int, list[str], Path, Path]:
    if config.get("schema") != 1:
        raise ValueError("unsupported transport configuration schema")
    bind = config.get("bind")
    port = config.get("port")
    allowed_hosts = config.get("allowed_hosts")
    cert_file = config.get("cert_file")
    key_file = config.get("key_file")
    try:
        address = normalize_address(bind)
    except (TypeError, ValueError) as exc:
        raise ValueError("transport bind must be a literal IP address") from exc
    if address.is_unspecified or address.is_multicast:
        raise ValueError("transport bind cannot be unspecified or multicast")
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("transport port must be between 1024 and 65535")
    if not isinstance(allowed_hosts, list) or not allowed_hosts or len(allowed_hosts) > 16:
        raise ValueError("transport must define one to sixteen allowed hosts")
    normalized_hosts: list[str] = []
    for host in allowed_hosts:
        if not isinstance(host, str) or not HOSTNAME.fullmatch(host):
            try:
                ipaddress.ip_address(host)
            except (TypeError, ValueError) as exc:
                raise ValueError("transport contains an invalid allowed host") from exc
        normalized_hosts.append(host.lower().rstrip("."))
    if not isinstance(cert_file, str) or not isinstance(key_file, str):
        raise ValueError("transport TLS paths are invalid")
    cert_path = Path(cert_file)
    key_path = Path(key_file)
    if not cert_path.is_absolute() or not key_path.is_absolute():
        raise ValueError("transport TLS paths must be absolute")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    return str(address), port, normalized_hosts, cert_path, key_path


class SourceRateLimiter:
    def __init__(self) -> None:
        self._entries: dict[str, collections.deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, source: str) -> bool:
        now = time.monotonic()
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        with self._lock:
            if source not in self._entries and len(self._entries) >= MAX_RATE_LIMIT_SOURCES:
                oldest = min(
                    self._entries,
                    key=lambda item: self._entries[item][-1] if self._entries[item] else 0,
                )
                self._entries.pop(oldest, None)
            history = self._entries.setdefault(source, collections.deque())
            while history and history[0] < cutoff:
                history.popleft()
            if len(history) >= RATE_LIMIT_REQUESTS:
                return False
            history.append(now)
            return True


class LabStewardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler]):
        super().__init__(server_address, handler)
        self.allowed_hosts: list[str] = []
        self.rate_limiter = SourceRateLimiter()
        self.ssl_context: ssl.SSLContext | None = None
        self.connection_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)

    def process_request(self, request: Any, client_address: tuple[str, int]) -> None:
        if not self.connection_slots.acquire(blocking=False):
            audit("connection_rejected", source=client_address[0], reason="concurrency_limit")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: tuple[str, int]) -> None:
        tls_request = None
        try:
            request.settimeout(CONNECTION_TIMEOUT_SECONDS)
            if self.ssl_context is None:
                raise ssl.SSLError("TLS context is unavailable")
            tls_request = self.ssl_context.wrap_socket(request, server_side=True)
            super().process_request_thread(tls_request, client_address)
        except (OSError, ssl.SSLError):
            audit("tls_handshake_failed", source=client_address[0])
            try:
                request.close()
            except OSError:
                pass
        finally:
            self.connection_slots.release()


class MCPHandler(BaseHTTPRequestHandler):
    server_version = "LabSteward"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        # All logs are emitted through the controlled audit function.
        return

    @property
    def source(self) -> str:
        try:
            return str(normalize_address(self.client_address[0]))
        except ValueError:
            return "invalid"

    def send_empty(self, status: int, *, authenticate: bool = False) -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if authenticate:
            self.send_header("WWW-Authenticate", 'Bearer realm="labsteward"')
        self.send_header("Connection", "close")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        self.close_connection = True
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def jsonrpc_error(self, request_id: object, code: int, message: str) -> None:
        self.send_json(
            200,
            {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        )

    def host_allowed(self) -> bool:
        host_header = self.headers.get("Host", "")
        if host_header.startswith("["):
            host = host_header[1:].split("]", 1)[0]
        else:
            host = host_header.rsplit(":", 1)[0]
        return host.lower().rstrip(".") in self.server.allowed_hosts  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802
        self.send_empty(405)

    def do_DELETE(self) -> None:  # noqa: N802
        self.send_empty(405)

    def do_POST(self) -> None:  # noqa: N802
        source = self.source
        if self.path != "/mcp":
            self.send_empty(404)
            return
        if not self.server.rate_limiter.allow(source):  # type: ignore[attr-defined]
            audit("request_rejected", source=source, reason="rate_limit")
            self.send_empty(429)
            return
        if not self.host_allowed() or self.headers.get("Origin") is not None:
            audit("request_rejected", source=source, reason="host_or_origin")
            self.send_empty(403)
            return
        token = parse_bearer(self.headers.get("Authorization"))
        client_id = authenticate_client(token or "", source) if token else None
        if client_id is None:
            audit("authentication_failed", source=source)
            self.send_empty(401, authenticate=True)
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.send_empty(415)
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self.send_empty(400)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            self.send_empty(411)
            return
        length_text = lengths[0]
        try:
            length = int(length_text or "")
        except ValueError:
            self.send_empty(411)
            return
        if length < 1 or length > MAX_REQUEST_BYTES:
            self.send_empty(413)
            return
        try:
            request = json.loads(
                self.rfile.read(length),
                parse_constant=reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            self.jsonrpc_error(None, -32700, "Parse error")
            return
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            self.jsonrpc_error(None, -32600, "Invalid request")
            return
        method = request.get("method")
        request_id = request.get("id")
        if not isinstance(method, str):
            self.jsonrpc_error(request_id, -32600, "Invalid request")
            return
        if request_id is not None and (
            isinstance(request_id, bool) or not isinstance(request_id, (str, int))
        ):
            self.jsonrpc_error(None, -32600, "Invalid request")
            return
        if request_id is None:
            if method in {"notifications/initialized", "notifications/cancelled"}:
                audit("notification_accepted", source=source, client=client_id, method=method)
                self.send_empty(202)
                return
            self.send_empty(202)
            return
        try:
            result = self.dispatch(method, request.get("params", {}))
        except DispatchError as exc:
            audit(
                "tool_rejected",
                source=source,
                client=client_id,
                method=method,
                reason=exc.code,
            )
            if method == "tools/call":
                result = {
                    "content": [{"type": "text", "text": exc.message}],
                    "isError": True,
                }
            else:
                self.jsonrpc_error(request_id, -32602, exc.message)
                return
        except Exception:
            audit("request_failed", source=source, client=client_id, method=method)
            self.jsonrpc_error(request_id, -32603, "Internal error")
            return
        audit("request_succeeded", source=source, client=client_id, method=method)
        self.send_json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

    def dispatch(self, method: str, params: object) -> dict[str, Any]:
        if method == "initialize":
            if not isinstance(params, dict):
                raise DispatchError("invalid_arguments", "Invalid initialize parameters")
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
            try:
                release = VERSION_FILE.read_text(encoding="utf-8").strip()
            except OSError:
                release = "development"
            return {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": release},
                "instructions": (
                    "LabSteward exposes only fixed, permission-checked home-lab actions. "
                    "Never infer arbitrary command, URL, file, or credential access. "
                    "core_status is read-only and contacts no managed server."
                ),
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": tool_definitions()}
        if method == "tools/call":
            if not isinstance(params, dict):
                raise DispatchError("invalid_arguments", "Invalid tool call")
            name = params.get("name")
            arguments = params.get("arguments", {})
            if name != "core_status":
                raise DispatchError("unknown_action", "Unknown LabSteward tool")
            result = dispatch_action("core.status", arguments)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, separators=(",", ":"), sort_keys=True),
                    }
                ],
                "structuredContent": result,
                "isError": False,
            }
        raise DispatchError("unknown_method", "Method not found")


def build_server(config_path: Path) -> tuple[LabStewardHTTPServer, ssl.SSLContext]:
    config = read_object(config_path)
    bind, port, allowed_hosts, cert_path, key_path = validate_transport_config(config)
    server = LabStewardHTTPServer((bind, port), MCPHandler)
    server.allowed_hosts = allowed_hosts
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(cert_path, key_path)
    server.ssl_context = context
    return server, context


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the LabSteward MCP transport")
    parser.add_argument("--config", type=Path, default=DEFAULT_TRANSPORT_CONFIG)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    try:
        config = read_object(args.config)
        bind, port, allowed_hosts, cert_path, key_path = validate_transport_config(config)
        if args.check_config:
            print(f"valid transport configuration for {bind}:{port}")
            return 0
        server = LabStewardHTTPServer((bind, port), MCPHandler)
        server.allowed_hosts = allowed_hosts
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        context.load_cert_chain(cert_path, key_path)
        server.ssl_context = context
        audit("service_started", bind=bind, port=port)
        server.serve_forever(poll_interval=0.5)
    except (OSError, ValueError, json.JSONDecodeError, ssl.SSLError) as exc:
        audit("service_start_failed", reason=type(exc).__name__)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        if "server" in locals():
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
EOF_LABSTEWARD_MCP
chmod 0644 /opt/labsteward/lib/labsteward_mcp.py
cat >/opt/labsteward/catalog/plugins.json <<'EOF_LABSTEWARD_CATALOG'
{
  "schema": 1,
  "plugins": [
    {
      "id": "proxmox",
      "name": "Proxmox VE",
      "status": "planned",
      "description": "Scoped Proxmox node, LXC, storage, task, and backup access.",
      "permissions": []
    },
    {
      "id": "synology",
      "name": "Synology DSM",
      "status": "planned",
      "description": "Scoped DSM system, pool, volume, disk, snapshot, and job access.",
      "permissions": []
    },
    {
      "id": "unifi",
      "name": "UniFi",
      "status": "planned",
      "description": "Scoped UniFi site, device, WAN, Wi-Fi, and network access.",
      "permissions": []
    }
  ]
}
EOF_LABSTEWARD_CATALOG
cat >/opt/labsteward/schemas/config.schema.json <<'EOF_LABSTEWARD_SCHEMA'
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/donselkirk/LabSteward/schemas/config.schema.json",
  "title": "LabSteward appliance configuration",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "plugins", "servers"],
  "properties": {
    "schema": { "const": 1 },
    "plugins": {
      "type": "object",
      "propertyNames": { "pattern": "^[a-z][a-z0-9-]{0,31}$" },
      "additionalProperties": {
        "type": "object",
        "additionalProperties": false,
        "required": ["version", "enabled"],
        "properties": {
          "version": { "type": "string", "pattern": "^v?[0-9]+\\.[0-9]+\\.[0-9]+$" },
          "enabled": { "type": "boolean" }
        }
      }
    },
    "servers": {
      "type": "object",
      "propertyNames": { "pattern": "^[a-z][a-z0-9._-]{0,63}$" },
      "additionalProperties": {
        "type": "object",
        "additionalProperties": false,
        "required": ["plugin", "endpoint", "permissions"],
        "properties": {
          "plugin": { "type": "string", "pattern": "^[a-z][a-z0-9-]{0,31}$" },
          "endpoint": { "type": "string", "maxLength": 2048 },
          "permissions": {
            "type": "array",
            "uniqueItems": true,
            "items": { "type": "string", "pattern": "^[a-z][a-z0-9.-]{0,63}$" }
          }
        }
      }
    },
    "clients": {
      "type": "object",
      "propertyNames": { "pattern": "^[a-z][a-z0-9-]{0,31}$" },
      "additionalProperties": {
        "type": "object",
        "additionalProperties": false,
        "required": ["enabled", "sources", "grants"],
        "properties": {
          "enabled": { "type": "boolean" },
          "sources": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": true,
            "items": { "type": "string", "maxLength": 64 }
          },
          "grants": {
            "type": "object",
            "propertyNames": { "pattern": "^[a-z][a-z0-9._-]{0,63}$" },
            "additionalProperties": {
              "type": "array",
              "uniqueItems": true,
              "items": { "type": "string", "pattern": "^[a-z][a-z0-9.-]{0,63}$" }
            }
          }
        }
      }
    }
  }
}
EOF_LABSTEWARD_SCHEMA
cat >/etc/systemd/system/labsteward.service <<'EOF_LABSTEWARD_SERVICE'
[Unit]
Description=LabSteward authenticated MCP gateway
Documentation=https://github.com/donselkirk/LabSteward
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/labsteward/transport.json

[Service]
Type=simple
User=labsteward
Group=labsteward
ExecStart=/usr/bin/python3 /opt/labsteward/lib/labsteward_mcp.py --config /etc/labsteward/transport.json
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProtectSystem=strict
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
LimitNOFILE=256
MemoryMax=192M
TasksMax=64
UMask=0027

[Install]
WantedBy=multi-user.target
EOF_LABSTEWARD_SERVICE
chmod 0644 /etc/systemd/system/labsteward.service

if [[ -n "${LABSTEWARD_VERSION_URL:-}" ]]; then
  curl -fsSL --retry 3 --retry-all-errors "$LABSTEWARD_VERSION_URL" -o /opt/labsteward/VERSION
else
  printf 'development\n' >/opt/labsteward/VERSION
fi
printf '%s\n' "${LABSTEWARD_UPDATE_BASE_URL:-https://github.com/donselkirk/LabSteward/releases/latest/download}" >/opt/labsteward/update.url
chown -R root:root /opt/labsteward
find /opt/labsteward -type d -exec chmod 0755 {} +
find /opt/labsteward -type f -exec chmod go-w {} +
systemctl daemon-reload
/usr/local/bin/stewctl status
msg_ok "Created the LabSteward security boundary"

msg_info "Configuring LabSteward login banner"
cat >/etc/profile.d/00-labsteward-details.sh <<'EOF_MOTD'
#!/usr/bin/env bash
[[ "${LABSTEWARD_MOTD_SHOWN:-0}" == "1" ]] && return 0
export LABSTEWARD_MOTD_SHOWN=1
printf '\n\033[1;92mLabSteward LXC Appliance\033[0m\n'
printf ' Version: %s\n' "$(/usr/local/bin/stewctl version 2>/dev/null | sed 's/^LabSteward //')"
printf ' IP Address: %s\n' "$(hostname -I 2>/dev/null | awk '{print $1}')"
printf ' Configure: stewctl plugin list\n'
printf ' Status:    stewctl status\n\n'
EOF_MOTD
chmod 0755 /etc/profile.d/00-labsteward-details.sh
msg_ok "Configured LabSteward login banner"

motd_ssh
customize
