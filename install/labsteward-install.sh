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
getent group labsteward-admin >/dev/null || groupadd --system labsteward-admin
id labsteward-admin >/dev/null 2>&1 || useradd --system --gid labsteward-admin \
  --home-dir /var/lib/labsteward-admin --create-home --shell /usr/sbin/nologin labsteward-admin
install -d -o root -g root -m 0755 /opt/labsteward /opt/labsteward/lib /opt/labsteward/catalog /opt/labsteward/schemas /opt/labsteward/plugins
install -d -o root -g labsteward -m 2750 /etc/labsteward
install -d -o root -g labsteward-admin -m 2750 /etc/labsteward-admin
install -d -o root -g labsteward -m 2750 /etc/labsteward/secrets /etc/labsteward/secrets/clients /etc/labsteward/secrets/servers
install -d -o labsteward -g labsteward -m 0700 /var/lib/labsteward
install -d -o labsteward-admin -g labsteward-admin -m 0700 /var/lib/labsteward-admin

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

This manager owns non-secret registry data and terminal-only plugin credential
entry. Credentials remain in protected files inside the appliance.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import grp
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
SERVER_SECRETS_DIR = Path(
    os.environ.get("LABSTEWARD_SERVER_SECRETS_DIR", "/etc/labsteward/secrets/servers")
)
PLUGINS_DIR = Path(os.environ.get("LABSTEWARD_PLUGINS_DIR", str(BASE_DIR / "plugins")))
TRANSPORT_CONFIG_FILE = Path(
    os.environ.get("LABSTEWARD_TRANSPORT_CONFIG", "/etc/labsteward/transport.json")
)
TLS_DIR = Path(os.environ.get("LABSTEWARD_TLS_DIR", "/etc/labsteward/secrets/tls"))
ADMIN_CONFIG_FILE = Path(
    os.environ.get("LABSTEWARD_ADMIN_CONFIG", "/etc/labsteward-admin/config.json")
)
ADMIN_CREDENTIAL_FILE = Path(
    os.environ.get("LABSTEWARD_ADMIN_CREDENTIAL", "/etc/labsteward-admin/admin.json")
)
ADMIN_TLS_DIR = Path(
    os.environ.get("LABSTEWARD_ADMIN_TLS_DIR", "/etc/labsteward-admin/tls")
)
OAUTH_TOKEN_FILE = Path(
    os.environ.get("LABSTEWARD_OAUTH_TOKEN_FILE", "/etc/labsteward/secrets/oauth-tokens.json")
)
ADMIN_FILE = Path(
    os.environ.get("LABSTEWARD_ADMIN_FILE", str(BASE_DIR / "lib/labsteward_admin.py"))
)
BROKER_FILE = Path(
    os.environ.get("LABSTEWARD_BROKER_FILE", str(BASE_DIR / "lib/labsteward_broker.py"))
)
ADMIN_SYSTEMD_UNIT_FILE = Path(
    os.environ.get("LABSTEWARD_ADMIN_SYSTEMD_UNIT", "/etc/systemd/system/labsteward-admin.service")
)
BROKER_SYSTEMD_UNIT_FILE = Path(
    os.environ.get("LABSTEWARD_BROKER_SYSTEMD_UNIT", "/etc/systemd/system/labsteward-broker.service")
)
ADMIN_USER = os.environ.get("LABSTEWARD_ADMIN_USER", "labsteward-admin")
ADMIN_GROUP = os.environ.get("LABSTEWARD_ADMIN_GROUP", "labsteward-admin")
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
PERMISSION_LEVELS = {"off": 0, "read": 1, "write": 2}
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
        raw_permissions = plugin.get("permissions", {})
        names = raw_permissions if isinstance(raw_permissions, list) else raw_permissions.keys() if isinstance(raw_permissions, dict) else []
        descriptions = plugin.get("permission_descriptions", {})
        if not isinstance(descriptions, dict) or set(str(item) for item in names) != set(descriptions):
            raise UserError("Plugin catalog must describe every declared permission")
        if any(
            not isinstance(description, str) or not description.strip() or len(description) > 240
            for description in descriptions.values()
        ):
            raise UserError("Plugin catalog contains an invalid permission description")
        result[plugin["id"]] = plugin
    return result


def require_identifier(value: str, label: str, pattern: re.Pattern[str]) -> str:
    normalized = value.lower()
    if not pattern.fullmatch(normalized):
        raise UserError(f"Invalid {label}: {value}")
    return normalized


def permission_levels(value: object, label: str = "permissions") -> dict[str, str]:
    """Normalize legacy permission lists to read-only level mappings."""
    if isinstance(value, list):
        value = {str(item): "read" for item in value}
    if not isinstance(value, dict) or len(value) > 64:
        raise UserError(f"Invalid {label}")
    normalized = {}
    for permission, level in value.items():
        name = require_identifier(str(permission), "permission", PERMISSION)
        if level not in {"read", "write"}:
            raise UserError(f"Invalid permission level for {name}")
        normalized[name] = str(level)
    return dict(sorted(normalized.items()))


def parse_permission_levels(values: list[str]) -> dict[str, str]:
    permissions = {}
    for value in values:
        name, separator, level = value.partition("=")
        permission = require_identifier(name, "permission", PERMISSION)
        selected = level.lower() if separator else "read"
        if selected not in PERMISSION_LEVELS:
            raise UserError(f"Permission level must be off, read, or write: {value}")
        if selected == "off":
            permissions.pop(permission, None)
        else:
            permissions[permission] = selected
    return dict(sorted(permissions.items()))


def declared_permissions(plugin: dict) -> set[str]:
    raw = plugin.get("permissions", {})
    values = raw if isinstance(raw, list) else raw.keys() if isinstance(raw, dict) else []
    return {require_identifier(str(item), "permission", PERMISSION) for item in values}


def require_plugin_contract(plugin_id: str, plugin: dict, manifest: dict) -> None:
    if (
        manifest.get("schema") != 1
        or manifest.get("id") != plugin_id
        or manifest.get("version") != plugin.get("version")
        or manifest.get("entrypoint") != "plugin.py"
        or manifest.get("core_api") != 1
    ):
        raise UserError(f"Plugin package metadata is invalid: {plugin_id}")
    manifest_permissions = manifest.get("permissions")
    manifest_actions = manifest.get("actions")
    if not isinstance(manifest_permissions, dict) or not isinstance(manifest_actions, dict):
        raise UserError(f"Plugin package contract is invalid: {plugin_id}")
    catalog_permissions = plugin.get("permissions", {})
    if not isinstance(catalog_permissions, dict) or set(manifest_permissions) != set(catalog_permissions):
        raise UserError(f"Plugin package permissions do not match the release catalog: {plugin_id}")
    for permission, record in manifest_permissions.items():
        if (
            not isinstance(record, dict)
            or record.get("level") != catalog_permissions.get(permission)
            or record.get("description") != plugin.get("permission_descriptions", {}).get(permission)
        ):
            raise UserError(f"Plugin package permissions do not match the release catalog: {plugin_id}")
    for action, record in manifest_actions.items():
        permission_record = manifest_permissions.get(record.get("permission")) if isinstance(record, dict) else None
        if (
            not isinstance(action, str)
            or not isinstance(record, dict)
            or not isinstance(permission_record, dict)
            or record.get("level") not in {"read", "write"}
            or permission_record.get("level") not in {"read", "write"}
            or PERMISSION_LEVELS[record["level"]] > PERMISSION_LEVELS[permission_record["level"]]
            or not isinstance(record.get("tool"), str)
        ):
            raise UserError(f"Plugin package actions are invalid: {plugin_id}")


def require_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    try:
        parsed.port
    except ValueError as exc:
        raise UserError("Server endpoint contains an invalid port") from exc
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


def admin_group_id() -> int:
    override = os.environ.get("LABSTEWARD_ADMIN_GROUP_ID")
    if override is not None:
        return int(override)
    if ALLOW_NON_ROOT:
        return os.getgid()
    try:
        return grp.getgrnam(ADMIN_GROUP).gr_gid
    except KeyError as exc:
        raise UserError("The labsteward-admin service account is unavailable") from exc


def save_admin_json(path: Path, value: dict, mode: int = 0o640) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    owner_id = CONFIG_FILE.stat().st_uid if CONFIG_FILE.exists() else os.getuid()
    os.chmod(path.parent, 0o2750)
    os.chown(path.parent, owner_id, admin_group_id())
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, owner_id, admin_group_id())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def install_admin_tls_file(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(mode=0o2750, parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o2750)
    owner_id = CONFIG_FILE.stat().st_uid if CONFIG_FILE.exists() else os.getuid()
    os.chown(destination.parent, owner_id, admin_group_id())
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(source, temporary)
        os.chmod(temporary, mode)
        os.chown(temporary, owner_id, admin_group_id())
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
    print("  3. stewctl admin tls create --host IP_OR_DNS")
    print("  4. stewctl admin bootstrap --username ADMIN")
    print("  5. stewctl admin configure --bind IP --host IP_OR_DNS --admin-source CIDR")
    print("  6. stewctl transport enable && stewctl admin enable")
    print("  7. Add the MCP URL, authenticate in a browser, and call core_status")
    print("  8. Install and configure plugins only after transport validation")


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
    config["clients"][client_id] = {
        "enabled": True,
        "sources": sources,
        "grants": {},
        "auth": "legacy_token",
        "display_name": client_id,
    }
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
    if OAUTH_TOKEN_FILE.exists():
        tokens = read_json(OAUTH_TOKEN_FILE)
        if tokens.get("schema") == 1 and isinstance(tokens.get("tokens"), list):
            tokens.setdefault("generations", {})
            generation = client.get("auth_generation")
            if isinstance(tokens["generations"], dict) and isinstance(generation, int) and generation > 0:
                previous = tokens["generations"].get(client_id, 0)
                if not isinstance(previous, int) or previous < 0:
                    raise UserError("OAuth access-token registry is invalid")
                tokens["generations"][client_id] = max(
                    generation, previous
                )
            tokens["tokens"] = [
                item
                for item in tokens["tokens"]
                if not isinstance(item, dict) or item.get("client") != client_id
            ]
            save_json(OAUTH_TOKEN_FILE, tokens)
    del config["clients"][client_id]
    save_config(config)
    client_token_path(client_id).unlink(missing_ok=True)
    print(f"Revoked and removed client {client_id} and its token metadata.")


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
    permissions = parse_permission_levels(args.permissions)
    config = load_config()
    client = config["clients"].get(client_id)
    if not client:
        raise UserError(f"Unknown client: {client_id}")
    if not client.get("enabled"):
        raise UserError("Cannot modify a revoked client")
    server = config["servers"].get(alias)
    if not server:
        raise UserError(f"Unknown server alias: {alias}")
    if alias not in client.get("grants", {}):
        raise UserError("Add the server to this client before configuring permissions")
    plugin = catalog_plugins().get(server.get("plugin"), {})
    unauthorized = sorted(set(permissions) - declared_permissions(plugin))
    if unauthorized:
        raise UserError(
            f"Permission is not declared by plugin {server.get('plugin')}: {', '.join(unauthorized)}"
        )
    client["grants"][alias] = permissions
    save_config(config)
    print(f"Set {len(permissions)} permission(s) for client {client_id} on {alias}.")


def command_client_server_add(args: argparse.Namespace) -> None:
    client_id = require_identifier(args.client, "client ID", IDENTIFIER)
    alias = require_identifier(args.server, "server alias", ALIAS)
    config = load_config()
    client = config["clients"].get(client_id)
    if not client or not client.get("enabled"):
        raise UserError(f"Unknown or revoked client: {client_id}")
    if alias not in config["servers"]:
        raise UserError(f"Unknown server alias: {alias}")
    if alias in client.get("grants", {}):
        raise UserError("Server is already assigned to this client")
    client.setdefault("grants", {})[alias] = {}
    save_config(config)
    print(f"Added server {alias} to client {client_id} with all permissions off.")


def command_client_server_remove(args: argparse.Namespace) -> None:
    client_id = require_identifier(args.client, "client ID", IDENTIFIER)
    alias = require_identifier(args.server, "server alias", ALIAS)
    config = load_config()
    client = config["clients"].get(client_id)
    if not client or not client.get("enabled"):
        raise UserError(f"Unknown or revoked client: {client_id}")
    if alias not in client.get("grants", {}):
        raise UserError("Server is not assigned to this client")
    del client["grants"][alias]
    save_config(config)
    print(f"Removed server {alias} from client {client_id}.")


def command_plugin_install(args: argparse.Namespace) -> None:
    plugin_id = require_identifier(args.plugin, "plugin ID", IDENTIFIER)
    plugin = catalog_plugins().get(plugin_id)
    if not plugin:
        raise UserError("Plugin is not in the approved release catalog")
    if plugin.get("status") != "available":
        raise UserError(f"Plugin {plugin_id} is catalogued but not yet available")
    manifest_path = PLUGINS_DIR / plugin_id / "manifest.json"
    entrypoint = PLUGINS_DIR / plugin_id / "plugin.py"
    manifest = read_json(manifest_path)
    require_plugin_contract(plugin_id, plugin, manifest)
    try:
        compile(entrypoint.read_text(encoding="utf-8"), str(entrypoint), "exec")
    except (OSError, SyntaxError) as exc:
        raise UserError(f"Plugin package entrypoint is invalid: {plugin_id}") from exc
    config = load_config()
    if plugin_id in config["plugins"]:
        raise UserError(f"Plugin is already installed: {plugin_id}")
    config["plugins"][plugin_id] = {"enabled": True, "version": plugin["version"]}
    save_config(config)
    print(f"Installed and enabled plugin {plugin_id} {plugin['version']} from the verified core release.")


def command_plugin_remove(args: argparse.Namespace) -> None:
    plugin_id = require_identifier(args.plugin, "plugin ID", IDENTIFIER)
    config = load_config()
    users = [alias for alias, server in config["servers"].items() if server.get("plugin") == plugin_id]
    if users:
        raise UserError(f"Plugin {plugin_id} is still used by: {', '.join(sorted(users))}")
    if plugin_id not in config["plugins"]:
        raise UserError(f"Plugin is not installed: {plugin_id}")
    del config["plugins"][plugin_id]
    save_config(config)
    print(f"Disabled and removed plugin registration {plugin_id}; verified release code remains immutable.")


def command_server_list(_: argparse.Namespace) -> None:
    for alias, server in sorted(load_config()["servers"].items()):
        print(f"{alias}\t{server.get('plugin')}\t{server.get('endpoint')}")


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
    config["servers"][alias] = {"plugin": plugin_id, "endpoint": endpoint}
    save_config(config)
    print(f"Added server {alias} with no permissions. Grant permissions explicitly before use.")


def command_server_remove(args: argparse.Namespace) -> None:
    alias = require_identifier(args.alias, "server alias", ALIAS)
    config = load_config()
    if alias not in config["servers"]:
        raise UserError(f"Unknown server alias: {alias}")
    if not args.yes:
        raise UserError("Server removal requires --yes; credentials are not removed by this command")
    affected = 0
    for client in config["clients"].values():
        if isinstance(client, dict) and isinstance(client.get("grants"), dict):
            affected += int(alias in client["grants"])
            client["grants"].pop(alias, None)
    del config["servers"][alias]
    save_config(config)
    print(f"Removed server registration {alias} from {affected} client(s); inspect protected credentials separately.")


def server_credential_path(alias: str) -> Path:
    return SERVER_SECRETS_DIR / f"{alias}.json"


def server_ca_path(alias: str) -> Path:
    return SERVER_SECRETS_DIR / f"{alias}.ca.crt"


def prepare_server_secrets_dir() -> None:
    SERVER_SECRETS_DIR.mkdir(mode=0o2750, parents=True, exist_ok=True)
    metadata = CONFIG_FILE.stat()
    os.chmod(SERVER_SECRETS_DIR, 0o2750)
    os.chown(SERVER_SECRETS_DIR, metadata.st_uid, metadata.st_gid)


def command_server_credentials_set(args: argparse.Namespace) -> None:
    alias = require_identifier(args.alias, "server alias", ALIAS)
    server = load_config()["servers"].get(alias)
    if not isinstance(server, dict):
        raise UserError(f"Unknown server alias: {alias}")
    plugin_id = server.get("plugin")
    if plugin_id not in {"synology", "unifi", "proxmox"}:
        raise UserError("The selected server plugin has not released credential setup")
    prepare_server_secrets_dir()
    if plugin_id == "synology":
        username = os.environ.get("LABSTEWARD_TEST_SERVER_USERNAME")
        password = os.environ.get("LABSTEWARD_TEST_SERVER_PASSWORD")
        if username is None:
            username = input("DSM username: ").strip()
        if password is None:
            password = getpass.getpass("DSM password: ")
        if not username or len(username) > 128 or any(ord(character) < 32 for character in username):
            raise UserError("DSM username is invalid")
        if not password or len(password) > 1024 or "\x00" in password:
            raise UserError("DSM password is invalid")
        record = {"schema": 1, "username": username, "password": password}
        label = "Synology"
    elif plugin_id == "unifi":
        api_key = os.environ.get("LABSTEWARD_TEST_UNIFI_API_KEY")
        site_id = os.environ.get("LABSTEWARD_TEST_UNIFI_SITE_ID")
        if api_key is None:
            api_key = getpass.getpass("UniFi API key: ")
        if site_id is None:
            site_id = input("UniFi site ID: ").strip()
        if not 16 <= len(api_key) <= 2048 or "\x00" in api_key:
            raise UserError("UniFi API key is invalid")
        if not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            site_id,
        ):
            raise UserError("UniFi site ID must be a UUID from Network > Integrations")
        record = {"schema": 1, "api_key": api_key, "site_id": site_id.lower()}
        label = "UniFi"
    else:
        token_id = os.environ.get("LABSTEWARD_TEST_PROXMOX_TOKEN_ID")
        token_secret = os.environ.get("LABSTEWARD_TEST_PROXMOX_TOKEN_SECRET")
        node = os.environ.get("LABSTEWARD_TEST_PROXMOX_NODE")
        if token_id is None:
            token_id = input("Proxmox API token ID (user@realm!token): ").strip()
        if token_secret is None:
            token_secret = getpass.getpass("Proxmox API token secret: ")
        if node is None:
            node = input("Proxmox API node name: ").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+", token_id or ""):
            raise UserError("Proxmox API token ID is invalid")
        if not isinstance(token_secret, str) or not 8 <= len(token_secret) <= 2048 or "\x00" in token_secret:
            raise UserError("Proxmox API token secret is invalid")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", node or ""):
            raise UserError("Proxmox API node name is invalid")
        record = {"schema": 1, "token_id": token_id, "token_secret": token_secret, "node": node}
        label = "Proxmox"
    if args.ca_file:
        source = Path(args.ca_file)
        try:
            ssl.create_default_context(cafile=str(source))
        except (OSError, ssl.SSLError) as exc:
            raise UserError(f"{label} CA file is unavailable or invalid") from exc
        install_tls_file(source, server_ca_path(alias), 0o640, service_group=True)
    save_json(server_credential_path(alias), record, 0o640)
    print(f"Stored protected {label} credentials for {alias}; no credential value was displayed.")


def command_server_credentials_remove(args: argparse.Namespace) -> None:
    alias = require_identifier(args.alias, "server alias", ALIAS)
    if not args.yes:
        raise UserError("Credential removal requires --yes")
    removed = False
    for path in (server_credential_path(alias), server_ca_path(alias)):
        if path.exists():
            path.unlink()
            removed = True
    if not removed:
        raise UserError(f"No protected credentials are stored for {alias}")
    print(f"Removed protected credentials and CA trust for {alias}.")


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
        ("OAuth administrator", ADMIN_FILE),
        ("administration broker", BROKER_FILE),
    ):
        try:
            source = path.read_text(encoding="utf-8")
            compile(source, str(path), "exec")
        except (OSError, SyntaxError) as exc:
            errors.append(f"{label} is missing or invalid: {exc}")
    for label, unit_path in (
        ("MCP", SYSTEMD_UNIT_FILE),
        ("administrator", ADMIN_SYSTEMD_UNIT_FILE),
        ("broker", BROKER_SYSTEMD_UNIT_FILE),
    ):
        if not unit_path.is_file():
            errors.append(f"{label} service unit is missing: {unit_path}")
        else:
            core_group = BASE_DIR.stat().st_gid
            unit_error = validate_file_security(unit_path, 0o644, core_group)
            if unit_error:
                errors.append(unit_error)
    for path, mode in (
        (SELF_UPDATE, 0o755),
        (SANITIZER_FILE, 0o644),
        (CORE_FILE, 0o644),
        (MCP_FILE, 0o644),
        (ADMIN_FILE, 0o644),
        (BROKER_FILE, 0o644),
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
    if ADMIN_CONFIG_FILE.exists():
        try:
            validate_admin_config()
        except UserError as exc:
            errors.append(str(exc))
        admin_gid = admin_group_id()
        for path, mode in (
            (ADMIN_CONFIG_FILE, 0o640),
            (ADMIN_CREDENTIAL_FILE, 0o640),
            (admin_tls_paths()["server_key"], 0o640),
            (admin_tls_paths()["server_cert"], 0o644),
        ):
            security_error = validate_file_security(path, mode, admin_gid)
            if security_error:
                errors.append(security_error)
    if OAUTH_TOKEN_FILE.exists():
        try:
            oauth_tokens = read_json(OAUTH_TOKEN_FILE)
            generations = oauth_tokens.get("generations", {})
            if (
                oauth_tokens.get("schema") != 1
                or not isinstance(oauth_tokens.get("tokens"), list)
                or not isinstance(generations, dict)
                or any(
                    not isinstance(name, str) or not isinstance(value, int) or value < 1
                    for name, value in generations.items()
                )
            ):
                errors.append("OAuth access-token registry is invalid")
        except UserError as exc:
            errors.append(str(exc))
    for plugin_id, installed in config["plugins"].items():
        if plugin_id not in catalog:
            errors.append(f"installed plugin is absent from catalog: {plugin_id}")
        if not isinstance(installed, dict) or not isinstance(installed.get("enabled"), bool):
            errors.append(f"invalid installed plugin record: {plugin_id}")
            continue
        plugin = catalog.get(plugin_id, {})
        if installed.get("version") != plugin.get("version"):
            errors.append(f"installed plugin version does not match the catalog: {plugin_id}")
        try:
            require_plugin_contract(
                plugin_id,
                plugin,
                read_json(PLUGINS_DIR / plugin_id / "manifest.json"),
            )
            entrypoint = PLUGINS_DIR / plugin_id / "plugin.py"
            compile(entrypoint.read_text(encoding="utf-8"), str(entrypoint), "exec")
        except (UserError, OSError, SyntaxError) as exc:
            errors.append(str(exc))
        for path in (
            PLUGINS_DIR / plugin_id / "manifest.json",
            PLUGINS_DIR / plugin_id / "plugin.py",
        ):
            if not path.is_file():
                errors.append(f"installed plugin file is missing: {path}")
                continue
            security_error = validate_file_security(path, 0o644, BASE_DIR.stat().st_gid)
            if security_error:
                errors.append(security_error)
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
        for path in (server_credential_path(alias), server_ca_path(alias)):
            if path.exists():
                security_error = validate_file_security(path, 0o640, CONFIG_FILE.stat().st_gid)
                if security_error:
                    errors.append(security_error)
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
                try:
                    client_permissions = permission_levels(permissions, "client permissions")
                    plugin = catalog.get(server.get("plugin"), {})
                    allowed = declared_permissions(plugin)
                except UserError as exc:
                    errors.append(f"client {client_id} for {alias}: {exc}")
                    continue
                unauthorized = sorted(set(client_permissions) - allowed)
                if unauthorized:
                    errors.append(
                        f"client {client_id} exceeds the server grant for {alias}: "
                        f"{', '.join(sorted(unauthorized))}"
                    )
        auth_type = client.get("auth", "legacy_token")
        if auth_type not in {"legacy_token", "oauth"}:
            errors.append(f"client {client_id} has an unsupported authentication type")
        if auth_type == "oauth" and not isinstance(client.get("oauth_client_id"), str):
            errors.append(f"client {client_id} has invalid OAuth metadata")
        if auth_type == "oauth" and (
            not isinstance(client.get("auth_generation"), int)
            or client.get("auth_generation", 0) < 1
        ):
            errors.append(f"client {client_id} has invalid OAuth generation metadata")
        if enabled and auth_type == "legacy_token":
            token_error = validate_client_token(client_id)
            if token_error:
                errors.append(token_error)
        elif not enabled and client_token_path(client_id).exists():
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
        arguments = {} if args.action == "core.status" else {"server": args.server}
        if args.action == "unifi.client.summary":
            if args.client_id is None:
                raise UserError("unifi.client.summary requires --client-id")
            arguments["client_id"] = args.client_id
        elif args.action == "unifi.firewall.logging.set":
            if args.policy_id is None or args.logging_enabled is None:
                raise UserError(
                    "unifi.firewall.logging.set requires --policy-id and --logging-enabled"
                )
            arguments["policy_id"] = args.policy_id
            arguments["logging_enabled"] = args.logging_enabled == "true"
        elif args.action in {"proxmox.guest.summary", "proxmox.guest.diagnostics"}:
            if args.kind is None or args.guest_id is None:
                raise UserError(f"{args.action} requires --kind and --guest-id")
            arguments["kind"] = args.kind
            arguments["guest_id"] = args.guest_id
        result = module.dispatch_action(args.action, arguments)
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


def admin_tls_paths() -> dict[str, Path]:
    return {
        "server_key": ADMIN_TLS_DIR / "server.key",
        "server_cert": ADMIN_TLS_DIR / "server.crt",
    }


def url_host(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{address}]" if address.version == 6 else str(address)


def command_admin_bootstrap(args: argparse.Namespace) -> None:
    username = require_identifier(args.username, "administrator username", IDENTIFIER)
    if ADMIN_CREDENTIAL_FILE.exists() and not (args.force and args.yes):
        raise UserError("An administrator already exists; replacement requires --force --yes")
    test_password = os.environ.get("LABSTEWARD_TEST_ADMIN_PASSWORD") if ALLOW_NON_ROOT else None
    password = test_password if test_password is not None else getpass.getpass("New administrator password: ")
    confirmation = test_password if test_password is not None else getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise UserError("Administrator passwords did not match")
    if len(password) < 14 or len(password) > 256:
        raise UserError("Administrator password must contain 14 to 256 characters")
    if username in password.lower():
        raise UserError("Administrator password must not contain the username")
    salt = secrets.token_bytes(16)
    n, r, p = 2**15, 8, 1
    try:
        digest = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32,
            maxmem=64 * 1024 * 1024,
        )
    except ValueError as exc:
        raise UserError("Unable to derive the administrator credential securely") from exc
    record = {
        "schema": 1,
        "algorithm": "scrypt",
        "username": username,
        "salt": base64.b64encode(salt).decode("ascii"),
        "digest": base64.b64encode(digest).decode("ascii"),
        "n": n,
        "r": r,
        "p": p,
    }
    save_admin_json(ADMIN_CREDENTIAL_FILE, record)
    print(f"Configured LabSteward administrator {username}.")
    print("No recovery credential was created; reset access from the LXC console if necessary.")


def command_admin_tls_create(args: argparse.Namespace) -> None:
    hosts = list(dict.fromkeys(require_transport_host(host) for host in args.host))
    ca_paths = tls_paths()
    if not ca_paths["ca_key"].is_file() or not ca_paths["ca_cert"].is_file():
        raise UserError("Create the LabSteward transport CA before creating the admin certificate")
    paths = admin_tls_paths()
    existing = [path for path in paths.values() if path.exists()]
    if existing and not (args.force and args.yes):
        raise UserError("Admin TLS material already exists; replacement requires --force --yes")
    with tempfile.TemporaryDirectory(prefix="labsteward-admin-tls.") as directory:
        work = Path(directory)
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
        run_openssl(
            "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
            "-out", str(server_key),
        )
        run_openssl(
            "req", "-new", "-sha256", "-key", str(server_key), "-out",
            str(server_request), "-subj", f"/CN={hosts[0]}",
        )
        run_openssl(
            "x509", "-req", "-sha256", "-in", str(server_request), "-CA",
            str(ca_paths["ca_cert"]), "-CAkey", str(ca_paths["ca_key"]),
            "-CAcreateserial", "-out", str(server_cert), "-days", "825",
            "-extfile", str(extensions), "-extensions", "server",
        )
        install_admin_tls_file(server_key, paths["server_key"], 0o640)
        install_admin_tls_file(server_cert, paths["server_cert"], 0o644)
    print("Created a separate LabSteward admin server certificate signed by the existing local CA.")


def validate_admin_config() -> dict:
    config = read_json(ADMIN_CONFIG_FILE)
    if config.get("schema") != 1:
        raise UserError("Unsupported administrator configuration schema")
    bind = require_bind_address(str(config.get("bind", "")))
    port = config.get("port")
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise UserError("Administrator port must be between 1024 and 65535")
    hosts = config.get("allowed_hosts")
    if not isinstance(hosts, list) or not hosts or len(hosts) > 16:
        raise UserError("Administrator service must define one to sixteen allowed hosts")
    normalized_hosts = [require_transport_host(str(host)) for host in hosts]
    for label in ("admin_sources", "enrollment_sources"):
        sources = config.get(label)
        if not isinstance(sources, list) or not sources or len(sources) > 16:
            raise UserError(f"Administrator service has invalid {label}")
        config[label] = [require_source(str(source)) for source in sources]
    issuer = require_endpoint(str(config.get("issuer", "")))
    resource = str(config.get("resource", ""))
    parsed_resource = urlsplit(resource)
    try:
        parsed_resource.port
    except ValueError as exc:
        raise UserError("Administrator OAuth resource contains an invalid port") from exc
    if (
        parsed_resource.scheme != "https"
        or not parsed_resource.hostname
        or parsed_resource.path != "/mcp"
        or parsed_resource.query
        or parsed_resource.fragment
        or parsed_resource.username
        or parsed_resource.password
    ):
        raise UserError("Administrator OAuth resource must be the canonical HTTPS MCP URL")
    paths = admin_tls_paths()
    if Path(str(config.get("cert_file", ""))) != paths["server_cert"] or Path(
        str(config.get("key_file", ""))
    ) != paths["server_key"]:
        raise UserError("Administrator service must use the protected admin TLS paths")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(paths["server_cert"], paths["server_key"])
    except (OSError, ssl.SSLError) as exc:
        raise UserError("Administrator TLS certificate and key are unavailable or mismatched") from exc
    return {
        **config,
        "bind": bind,
        "port": port,
        "allowed_hosts": normalized_hosts,
        "issuer": issuer,
        "resource": resource,
    }


def command_admin_configure(args: argparse.Namespace) -> None:
    transport = validate_transport_config()
    bind = require_bind_address(args.bind)
    public_host = require_transport_host(args.host)
    if public_host not in transport["allowed_hosts"]:
        raise UserError("The admin public host must already be allowed by the MCP transport")
    certificate_covers(public_host, admin_tls_paths()["server_cert"])
    admin_sources = sorted({require_source(item) for item in args.admin_source})
    enrollment_sources = sorted(
        {require_source(item) for item in (args.enrollment_source or args.admin_source)}
    )
    host_for_url = url_host(public_host)
    issuer = f"https://{host_for_url}:{args.port}"
    resource = f"https://{host_for_url}:{transport['port']}/mcp"
    record = {
        "schema": 1,
        "bind": bind,
        "port": args.port,
        "allowed_hosts": list(dict.fromkeys([bind, public_host])),
        "admin_sources": admin_sources,
        "enrollment_sources": enrollment_sources,
        "issuer": issuer,
        "resource": resource,
        "cert_file": str(admin_tls_paths()["server_cert"]),
        "key_file": str(admin_tls_paths()["server_key"]),
    }
    save_admin_json(ADMIN_CONFIG_FILE, record)
    validate_admin_config()
    raw_transport = read_transport_config()
    raw_transport["resource"] = resource
    raw_transport["authorization_servers"] = [issuer]
    save_json(TRANSPORT_CONFIG_FILE, raw_transport)
    print(f"Configured the LabSteward administrator and OAuth interface at {issuer}/admin.")
    print("The services remain disabled until an administrator is bootstrapped and admin access is enabled.")


def admin_service_state(unit: str) -> str:
    try:
        result = systemctl("is-active", unit, check=False)
    except UserError:
        return "unknown"
    return result.stdout.strip() or "inactive"


def command_admin_enable(_: argparse.Namespace) -> None:
    validate_transport_config()
    validate_admin_config()
    if not ADMIN_CREDENTIAL_FILE.is_file():
        raise UserError("Bootstrap the administrator before enabling browser access")
    systemctl("daemon-reload")
    systemctl("enable", "--now", "labsteward-broker.service")
    systemctl("enable", "--now", "labsteward-admin.service")
    if transport_service_state() == "active":
        systemctl("restart", "labsteward.service")
    if admin_service_state("labsteward-broker.service") != "active" or admin_service_state(
        "labsteward-admin.service"
    ) != "active":
        raise UserError("LabSteward administrator services did not become active")
    print("Enabled the LabSteward OAuth and administrator interface.")


def command_admin_disable(_: argparse.Namespace) -> None:
    systemctl("disable", "--now", "labsteward-admin.service")
    systemctl("disable", "--now", "labsteward-broker.service")
    print("Disabled the LabSteward OAuth and administrator interface.")


def command_admin_status(_: argparse.Namespace) -> None:
    if not ADMIN_CONFIG_FILE.exists():
        print("LabSteward administrator interface: not configured")
        return
    config = validate_admin_config()
    print("LabSteward administrator interface: configured")
    print(f"  URL: {config['issuer']}/admin")
    print(f"  OAuth issuer: {config['issuer']}")
    print(f"  MCP resource: {config['resource']}")
    print(f"  Web service: {admin_service_state('labsteward-admin.service')}")
    print(f"  Management broker: {admin_service_state('labsteward-broker.service')}")


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
    run_action.add_argument(
        "action",
        choices=[
            "core.status", "synology.system.summary", "synology.storage.summary",
            "unifi.configuration.summary", "unifi.diagnostics.summary",
            "unifi.client.summary", "unifi.clients.list", "unifi.firewall.rules",
            "unifi.firewall.logging.set",
            "proxmox.node.summary", "proxmox.guests.list", "proxmox.guest.summary",
            "proxmox.node.diagnostics", "proxmox.guest.diagnostics",
            "proxmox.storage.summary", "proxmox.tasks.recent",
        ],
    )
    run_action.add_argument("--server")
    run_action.add_argument("--client-id")
    run_action.add_argument("--policy-id")
    run_action.add_argument("--kind", choices=["lxc", "qemu"])
    run_action.add_argument("--guest-id", type=int)
    run_action.add_argument("--logging-enabled", choices=["true", "false"])
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

    admin = commands.add_parser("admin")
    admin_commands = admin.add_subparsers(dest="admin_command", required=True)
    admin_commands.add_parser("status").set_defaults(handler=command_admin_status)
    admin_commands.add_parser("enable").set_defaults(handler=command_admin_enable)
    admin_commands.add_parser("disable").set_defaults(handler=command_admin_disable)
    bootstrap_admin = admin_commands.add_parser("bootstrap")
    bootstrap_admin.add_argument("--username", required=True)
    bootstrap_admin.add_argument("--force", action="store_true")
    bootstrap_admin.add_argument("--yes", action="store_true")
    bootstrap_admin.set_defaults(handler=command_admin_bootstrap)
    configure_admin = admin_commands.add_parser("configure")
    configure_admin.add_argument("--bind", required=True)
    configure_admin.add_argument("--host", required=True)
    configure_admin.add_argument("--port", type=int, default=9444, choices=range(1024, 65536))
    configure_admin.add_argument("--admin-source", action="append", required=True)
    configure_admin.add_argument("--enrollment-source", action="append", default=[])
    configure_admin.set_defaults(handler=command_admin_configure)
    admin_tls = admin_commands.add_parser("tls")
    admin_tls_commands = admin_tls.add_subparsers(dest="admin_tls_command", required=True)
    create_admin_tls = admin_tls_commands.add_parser("create")
    create_admin_tls.add_argument("--host", action="append", required=True)
    create_admin_tls.add_argument("--force", action="store_true")
    create_admin_tls.add_argument("--yes", action="store_true")
    create_admin_tls.set_defaults(handler=command_admin_tls_create)

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
    credentials = server_commands.add_parser("credentials")
    credential_commands = credentials.add_subparsers(
        dest="server_credential_command", required=True
    )
    set_credentials = credential_commands.add_parser("set")
    set_credentials.add_argument("alias")
    set_credentials.add_argument("--ca-file")
    set_credentials.set_defaults(handler=command_server_credentials_set)
    remove_credentials = credential_commands.add_parser("remove")
    remove_credentials.add_argument("alias")
    remove_credentials.add_argument("--yes", action="store_true")
    remove_credentials.set_defaults(handler=command_server_credentials_remove)

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
    client_server = client_commands.add_parser("server")
    client_server_commands = client_server.add_subparsers(dest="client_server_command", required=True)
    add_client_server = client_server_commands.add_parser("add")
    add_client_server.add_argument("client")
    add_client_server.add_argument("server")
    add_client_server.set_defaults(handler=command_client_server_add)
    remove_client_server = client_server_commands.add_parser("remove")
    remove_client_server.add_argument("client")
    remove_client_server.add_argument("server")
    remove_client_server.set_defaults(handler=command_client_server_remove)
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
readonly ADMIN_PATH="${LABSTEWARD_ADMIN_FILE:-${BASE_DIR}/lib/labsteward_admin.py}"
readonly BROKER_PATH="${LABSTEWARD_BROKER_FILE:-${BASE_DIR}/lib/labsteward_broker.py}"
readonly SYN_PLUGIN_DIR="${LABSTEWARD_SYNOLOGY_PLUGIN_DIR:-${BASE_DIR}/plugins/synology}"
readonly UNIFI_PLUGIN_DIR="${LABSTEWARD_UNIFI_PLUGIN_DIR:-${BASE_DIR}/plugins/unifi}"
readonly PROXMOX_PLUGIN_DIR="${LABSTEWARD_PROXMOX_PLUGIN_DIR:-${BASE_DIR}/plugins/proxmox}"
readonly SYSTEMD_UNIT_PATH="${LABSTEWARD_SYSTEMD_UNIT:-/etc/systemd/system/labsteward.service}"
readonly ADMIN_SYSTEMD_UNIT_PATH="${LABSTEWARD_ADMIN_SYSTEMD_UNIT:-/etc/systemd/system/labsteward-admin.service}"
readonly BROKER_SYSTEMD_UNIT_PATH="${LABSTEWARD_BROKER_SYSTEMD_UNIT:-/etc/systemd/system/labsteward-broker.service}"
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
synology_bundle=0
unifi_bundle=0
proxmox_bundle=0
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
optional_runtime_assets=(labsteward-core.py labsteward-mcp.py labsteward-admin.py \
  labsteward-broker.py labsteward-core.service labsteward-admin.service \
  labsteward-broker.service)
optional_synology_assets=(synology-plugin.py synology-manifest.json)
optional_unifi_assets=(unifi-plugin.py unifi-manifest.json)
optional_proxmox_assets=(proxmox-plugin.py proxmox-manifest.json)
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
synology_count=0
for asset in "${optional_synology_assets[@]}"; do
  if grep -q " ${asset}$" "${stage}/SHA256SUMS"; then
    synology_count=$((synology_count + 1))
  fi
done
if ((synology_count != 0 && synology_count != ${#optional_synology_assets[@]})); then
  echo "LabSteward release contains an incomplete Synology plugin bundle." >&2
  exit 1
fi
if ((synology_count)); then
  synology_bundle=1
  for asset in "${optional_synology_assets[@]}"; do
    download_asset "${asset_url}/${asset}" "${stage}/${asset}" "$asset"
  done
fi
unifi_count=0
for asset in "${optional_unifi_assets[@]}"; do
  if grep -q " ${asset}$" "${stage}/SHA256SUMS"; then
    unifi_count=$((unifi_count + 1))
  fi
done
if ((unifi_count != 0 && unifi_count != ${#optional_unifi_assets[@]})); then
  echo "LabSteward release contains an incomplete UniFi plugin bundle." >&2
  exit 1
fi
if ((unifi_count)); then
  unifi_bundle=1
  for asset in "${optional_unifi_assets[@]}"; do
    download_asset "${asset_url}/${asset}" "${stage}/${asset}" "$asset"
  done
fi
proxmox_count=0
for asset in "${optional_proxmox_assets[@]}"; do
  if grep -q " ${asset}$" "${stage}/SHA256SUMS"; then
    proxmox_count=$((proxmox_count + 1))
  fi
done
if ((proxmox_count != 0 && proxmox_count != ${#optional_proxmox_assets[@]})); then
  echo "LabSteward release contains an incomplete Proxmox plugin bundle." >&2
  exit 1
fi
if ((proxmox_count)); then
  proxmox_bundle=1
  for asset in "${optional_proxmox_assets[@]}"; do
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
    for item in \
      "labsteward_admin.py:$ADMIN_PATH" \
      "labsteward_broker.py:$BROKER_PATH" \
      "labsteward-admin.service:$ADMIN_SYSTEMD_UNIT_PATH" \
      "labsteward-broker.service:$BROKER_SYSTEMD_UNIT_PATH"; do
      source_name="${item%%:*}"
      destination="${item#*:}"
      if [[ -e "${backup}/${source_name}" ]]; then
        cp -a "${backup}/${source_name}" "$destination"
      else
        rm -f "$destination"
      fi
    done
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
  if ((synology_bundle)); then
    for item in synology-plugin.py synology-manifest.json; do
      destination="${SYN_PLUGIN_DIR}/${item#synology-}"
      if [[ -e "${backup}/${item}" ]]; then
        cp -a "${backup}/${item}" "$destination"
      else
        rm -f "$destination"
      fi
    done
  fi
  if ((unifi_bundle)); then
    for item in unifi-plugin.py unifi-manifest.json; do
      destination="${UNIFI_PLUGIN_DIR}/${item#unifi-}"
      if [[ -e "${backup}/${item}" ]]; then
        cp -a "${backup}/${item}" "$destination"
      else
        rm -f "$destination"
      fi
    done
  fi
  if ((proxmox_bundle)); then
    for item in proxmox-plugin.py proxmox-manifest.json; do
      destination="${PROXMOX_PLUGIN_DIR}/${item#proxmox-}"
      if [[ -e "${backup}/${item}" ]]; then
        cp -a "${backup}/${item}" "$destination"
      else
        rm -f "$destination"
      fi
    done
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
  [[ ! -e "$ADMIN_PATH" ]] || cp -a "$ADMIN_PATH" "${backup}/labsteward_admin.py"
  [[ ! -e "$BROKER_PATH" ]] || cp -a "$BROKER_PATH" "${backup}/labsteward_broker.py"
  [[ ! -e "$ADMIN_SYSTEMD_UNIT_PATH" ]] || cp -a "$ADMIN_SYSTEMD_UNIT_PATH" "${backup}/labsteward-admin.service"
  [[ ! -e "$BROKER_SYSTEMD_UNIT_PATH" ]] || cp -a "$BROKER_SYSTEMD_UNIT_PATH" "${backup}/labsteward-broker.service"
fi
if ((synology_bundle)); then
  install -d -m 0755 "$SYN_PLUGIN_DIR"
  [[ ! -e "${SYN_PLUGIN_DIR}/plugin.py" ]] || cp -a "${SYN_PLUGIN_DIR}/plugin.py" "${backup}/synology-plugin.py"
  [[ ! -e "${SYN_PLUGIN_DIR}/manifest.json" ]] || cp -a "${SYN_PLUGIN_DIR}/manifest.json" "${backup}/synology-manifest.json"
fi
if ((unifi_bundle)); then
  install -d -m 0755 "$UNIFI_PLUGIN_DIR"
  [[ ! -e "${UNIFI_PLUGIN_DIR}/plugin.py" ]] || cp -a "${UNIFI_PLUGIN_DIR}/plugin.py" "${backup}/unifi-plugin.py"
  [[ ! -e "${UNIFI_PLUGIN_DIR}/manifest.json" ]] || cp -a "${UNIFI_PLUGIN_DIR}/manifest.json" "${backup}/unifi-manifest.json"
fi
if ((proxmox_bundle)); then
  install -d -m 0755 "$PROXMOX_PLUGIN_DIR"
  [[ ! -e "${PROXMOX_PLUGIN_DIR}/plugin.py" ]] || cp -a "${PROXMOX_PLUGIN_DIR}/plugin.py" "${backup}/proxmox-plugin.py"
  [[ ! -e "${PROXMOX_PLUGIN_DIR}/manifest.json" ]] || cp -a "${PROXMOX_PLUGIN_DIR}/manifest.json" "${backup}/proxmox-manifest.json"
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
  if [[ $EUID -eq 0 ]]; then
    getent group labsteward-admin >/dev/null || groupadd --system labsteward-admin
    id labsteward-admin >/dev/null 2>&1 || useradd --system --gid labsteward-admin \
      --home-dir /var/lib/labsteward-admin --create-home --shell /usr/sbin/nologin labsteward-admin
    install -d -o labsteward-admin -g labsteward-admin -m 0700 /var/lib/labsteward-admin
    install -d -o root -g labsteward-admin -m 2750 /etc/labsteward-admin
  fi
  install -m 0644 "${stage}/labsteward-core.py" "$CORE_PATH"
  install -m 0644 "${stage}/labsteward-mcp.py" "$MCP_PATH"
  install -m 0644 "${stage}/labsteward-admin.py" "$ADMIN_PATH"
  install -m 0644 "${stage}/labsteward-broker.py" "$BROKER_PATH"
  install -D -m 0644 "${stage}/labsteward-core.service" "$SYSTEMD_UNIT_PATH"
  install -D -m 0644 "${stage}/labsteward-admin.service" "$ADMIN_SYSTEMD_UNIT_PATH"
  install -D -m 0644 "${stage}/labsteward-broker.service" "$BROKER_SYSTEMD_UNIT_PATH"
  "$SYSTEMCTL" daemon-reload
fi
if ((synology_bundle)); then
  install -m 0644 "${stage}/synology-plugin.py" "${SYN_PLUGIN_DIR}/plugin.py"
  install -m 0644 "${stage}/synology-manifest.json" "${SYN_PLUGIN_DIR}/manifest.json"
fi
if ((unifi_bundle)); then
  install -m 0644 "${stage}/unifi-plugin.py" "${UNIFI_PLUGIN_DIR}/plugin.py"
  install -m 0644 "${stage}/unifi-manifest.json" "${UNIFI_PLUGIN_DIR}/manifest.json"
fi
if ((proxmox_bundle)); then
  install -m 0644 "${stage}/proxmox-plugin.py" "${PROXMOX_PLUGIN_DIR}/plugin.py"
  install -m 0644 "${stage}/proxmox-manifest.json" "${PROXMOX_PLUGIN_DIR}/manifest.json"
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
import importlib.util
import os
import re
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
PLUGINS_DIR = Path(os.environ.get("LABSTEWARD_PLUGINS_DIR", str(BASE_DIR / "plugins")))
SERVER_SECRETS_DIR = Path(
    os.environ.get("LABSTEWARD_SERVER_SECRETS_DIR", "/etc/labsteward/secrets/servers")
)

MAX_JSON_FILE_SIZE = 1024 * 1024
SERVER_ALIAS = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
SYNOLOGY_ACTIONS = {
    "synology.system.summary": "system.read",
    "synology_system_summary": "system.read",
    "synology.storage.summary": "storage.read",
    "synology_storage_summary": "storage.read",
}
UNIFI_ACTIONS = {
    "unifi.configuration.summary": ("config.read", "read"),
    "unifi_configuration_summary": ("config.read", "read"),
    "unifi.diagnostics.summary": ("diagnostics.read", "read"),
    "unifi_diagnostics_summary": ("diagnostics.read", "read"),
    "unifi.client.summary": ("clients.read", "read"),
    "unifi_client_summary": ("clients.read", "read"),
    "unifi.clients.list": ("clients.read", "read"),
    "unifi_clients_list": ("clients.read", "read"),
    "unifi.firewall.rules": ("firewall.rules", "read"),
    "unifi_firewall_rules": ("firewall.rules", "read"),
    "unifi.firewall.logging.set": ("firewall.rules", "write"),
    "unifi_firewall_logging_set": ("firewall.rules", "write"),
}
UNIFI_CANONICAL = {
    "unifi_configuration_summary": "unifi.configuration.summary",
    "unifi_diagnostics_summary": "unifi.diagnostics.summary",
    "unifi_client_summary": "unifi.client.summary",
    "unifi_clients_list": "unifi.clients.list",
    "unifi_firewall_rules": "unifi.firewall.rules",
    "unifi_firewall_logging_set": "unifi.firewall.logging.set",
}
PROXMOX_ACTIONS = {
    "proxmox.node.summary": "node.read",
    "proxmox_node_summary": "node.read",
    "proxmox.guests.list": "guests.read",
    "proxmox_guests_list": "guests.read",
    "proxmox.guest.summary": "guests.read",
    "proxmox_guest_summary": "guests.read",
    "proxmox.node.diagnostics": "diagnostics.read",
    "proxmox_node_diagnostics": "diagnostics.read",
    "proxmox.guest.diagnostics": "diagnostics.read",
    "proxmox_guest_diagnostics": "diagnostics.read",
    "proxmox.storage.summary": "storage.read",
    "proxmox_storage_summary": "storage.read",
    "proxmox.tasks.recent": "tasks.read",
    "proxmox_tasks_recent": "tasks.read",
}
PROXMOX_CANONICAL = {
    "proxmox_node_summary": "proxmox.node.summary",
    "proxmox_guests_list": "proxmox.guests.list",
    "proxmox_guest_summary": "proxmox.guest.summary",
    "proxmox_node_diagnostics": "proxmox.node.diagnostics",
    "proxmox_guest_diagnostics": "proxmox.guest.diagnostics",
    "proxmox_storage_summary": "proxmox.storage.summary",
    "proxmox_tasks_recent": "proxmox.tasks.recent",
}


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


def _load_plugin(plugin_id: str, expected_version: str) -> Any:
    path = PLUGINS_DIR / plugin_id / "plugin.py"
    try:
        spec = importlib.util.spec_from_file_location(f"labsteward_plugin_{plugin_id}", path)
        if spec is None or spec.loader is None:
            raise ImportError("plugin loader is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except (OSError, ImportError, SyntaxError, AttributeError) as exc:
        raise DispatchError("plugin_unavailable", "Requested plugin is unavailable") from exc
    if module.PLUGIN_ID != plugin_id or module.PLUGIN_VERSION != expected_version:
        raise DispatchError("plugin_unavailable", "Requested plugin version is incompatible")
    return module


def _load_synology_plugin() -> Any:
    return _load_plugin("synology", "0.1.0")


def _synology_enabled(config: dict[str, Any]) -> bool:
    record = config.get("plugins", {}).get("synology")
    return isinstance(record, dict) and record.get("enabled") is True


def _synology_tools(config: dict[str, Any]) -> list[dict[str, Any]]:
    if not _synology_enabled(config):
        return []
    return _load_synology_plugin().tool_definitions()


def _unifi_tools(config: dict[str, Any]) -> list[dict[str, Any]]:
    if not _plugin_enabled(config, "unifi"):
        return []
    return _load_plugin("unifi", "0.1.0").tool_definitions()


def _proxmox_tools(config: dict[str, Any]) -> list[dict[str, Any]]:
    if not _plugin_enabled(config, "proxmox"):
        return []
    return _load_plugin("proxmox", "0.1.0").tool_definitions()


def _plugin_enabled(config: dict[str, Any], plugin_id: str) -> bool:
    record = config.get("plugins", {}).get(plugin_id)
    return isinstance(record, dict) and record.get("enabled") is True


def _grant_allows(granted: object, required_level: str) -> bool:
    return granted == "write" or (required_level == "read" and granted == "read")


def _authorized_target(
    config: dict[str, Any], alias: object, plugin_id: str, permission: str,
    required_level: str, client_id: str | None,
) -> tuple[str, dict[str, Any]]:
    if not isinstance(alias, str) or not SERVER_ALIAS.fullmatch(alias):
        raise DispatchError("invalid_arguments", "A valid registered server alias is required")
    if not _plugin_enabled(config, plugin_id):
        raise DispatchError("plugin_unavailable", f"{plugin_id.title()} plugin is not installed and enabled")
    server = config.get("servers", {}).get(alias)
    if not isinstance(server, dict) or server.get("plugin") != plugin_id:
        raise DispatchError("unknown_server", f"Unknown {plugin_id.title()} server")
    if client_id is not None:
        client = config.get("clients", {}).get(client_id)
        grants = client.get("grants", {}) if isinstance(client, dict) else {}
        levels = grants.get(alias, {}) if isinstance(grants, dict) else {}
        if isinstance(levels, list):
            levels = {name: "read" for name in levels if isinstance(name, str)}
        granted = levels.get(permission) if isinstance(levels, dict) else None
        if not _grant_allows(granted, required_level):
            raise DispatchError(
                "permission_denied",
                f"Client is not permitted to perform this {required_level}-level {plugin_id.title()} action",
            )
    return alias, server


def _authorized_synology_target(
    config: dict[str, Any], alias: object, permission: str, client_id: str | None
) -> tuple[str, dict[str, Any]]:
    return _authorized_target(config, alias, "synology", permission, "read", client_id)


def _synology_credentials(alias: str) -> tuple[dict[str, Any], Path | None]:
    credential_path = SERVER_SECRETS_DIR / f"{alias}.json"
    try:
        if credential_path.stat().st_mode & 0o137:
            raise OSError("credential permissions are unsafe")
        credentials = _read_object(credential_path)
    except (OSError, DispatchError) as exc:
        raise DispatchError("credentials_unavailable", "Synology credentials are not configured") from exc
    ca_path = SERVER_SECRETS_DIR / f"{alias}.ca.crt"
    return credentials, ca_path if ca_path.is_file() else None


def tool_definitions() -> list[dict[str, Any]]:
    """Return the complete allowlisted MCP tool catalog for this core release."""

    tools = [
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
    config = _read_object(CONFIG_FILE)
    tools.extend(_synology_tools(config))
    tools.extend(_unifi_tools(config))
    tools.extend(_proxmox_tools(config))
    return tools


def dispatch_action(
    action: str, arguments: Any, *, client_id: str | None = None
) -> dict[str, Any]:
    """Run one fixed action and return only its declared, sanitized result."""

    if action in {"core.status", "core_status"}:
        if not isinstance(arguments, dict) or arguments:
            raise DispatchError("invalid_arguments", "core.status accepts no arguments")
        # _registry_summary constructs the result from an explicit output allowlist.
        return sanitize_result(_registry_summary())
    permission = SYNOLOGY_ACTIONS.get(action)
    if permission is not None:
        if not isinstance(arguments, dict) or set(arguments) != {"server"}:
            raise DispatchError("invalid_arguments", "Synology actions require only a server alias")
        config = _read_object(CONFIG_FILE)
        alias, server = _authorized_synology_target(config, arguments["server"], permission, client_id)
        credentials, ca_file = _synology_credentials(alias)
        plugin = _load_synology_plugin()
        canonical = action.replace("synology_system_summary", "synology.system.summary").replace(
            "synology_storage_summary", "synology.storage.summary"
        )
        try:
            result = plugin.execute(canonical, server.get("endpoint", ""), credentials, ca_file=ca_file)
        except plugin.PluginError as exc:
            raise DispatchError("upstream_error", str(exc)) from exc
        return sanitize_result(result)
    proxmox_permission = PROXMOX_ACTIONS.get(action)
    if proxmox_permission is not None:
        canonical = PROXMOX_CANONICAL.get(action, action)
        required = {"server", "kind", "guest_id"} if canonical in {
            "proxmox.guest.summary", "proxmox.guest.diagnostics"
        } else {"server"}
        if not isinstance(arguments, dict) or set(arguments) != required:
            raise DispatchError("invalid_arguments", "Proxmox action arguments do not match its fixed schema")
        config = _read_object(CONFIG_FILE)
        alias, server = _authorized_target(
            config, arguments["server"], "proxmox", proxmox_permission, "read", client_id
        )
        credentials, ca_file = _synology_credentials(alias)
        plugin = _load_plugin("proxmox", "0.1.0")
        try:
            result = plugin.execute(
                canonical, server.get("endpoint", ""), credentials,
                {key: value for key, value in arguments.items() if key != "server"},
                ca_file=ca_file,
            )
        except plugin.PluginError as exc:
            raise DispatchError("upstream_error", str(exc)) from exc
        return sanitize_result(result)
    unifi_access = UNIFI_ACTIONS.get(action)
    if unifi_access is None:
        raise DispatchError("unknown_action", "Unknown LabSteward action")
    required = {
        "unifi.configuration.summary": {"server"},
        "unifi.diagnostics.summary": {"server"},
        "unifi.firewall.rules": {"server"},
        "unifi.clients.list": {"server"},
        "unifi.client.summary": {"server", "client_id"},
        "unifi.firewall.logging.set": {"server", "policy_id", "logging_enabled"},
    }
    canonical = UNIFI_CANONICAL.get(action, action)
    if not isinstance(arguments, dict) or set(arguments) != required[canonical]:
        raise DispatchError("invalid_arguments", "UniFi action arguments do not match its fixed schema")
    permission, required_level = unifi_access
    config = _read_object(CONFIG_FILE)
    alias, server = _authorized_target(
        config, arguments["server"], "unifi", permission, required_level, client_id
    )
    credentials, ca_file = _synology_credentials(alias)
    plugin = _load_plugin("unifi", "0.1.0")
    try:
        result = plugin.execute(
            canonical,
            server.get("endpoint", ""),
            credentials,
            {key: value for key, value in arguments.items() if key != "server"},
            ca_file=ca_file,
        )
    except plugin.PluginError as exc:
        raise DispatchError("upstream_error", str(exc)) from exc
    return sanitize_result(result)
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
from urllib.parse import urlsplit

from labsteward_core import DispatchError, dispatch_action, tool_definitions

BASE_DIR = Path(os.environ.get("LABSTEWARD_BASE_DIR", "/opt/labsteward"))
CONFIG_FILE = Path(os.environ.get("LABSTEWARD_CONFIG_FILE", "/etc/labsteward/config.json"))
CLIENT_SECRETS_DIR = Path(
    os.environ.get("LABSTEWARD_CLIENT_SECRETS_DIR", "/etc/labsteward/secrets/clients")
)
OAUTH_TOKEN_FILE = Path(
    os.environ.get("LABSTEWARD_OAUTH_TOKEN_FILE", "/etc/labsteward/secrets/oauth-tokens.json")
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
    if token.startswith("lst_"):
        # Compare every legacy verifier so timing does not reveal its position.
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
            if (
                token_matches
                and client.get("enabled") is True
                and client.get("auth", "legacy_token") == "legacy_token"
            ):
                matched_id = client_id
                matched_sources = client.get("sources")
    elif token.startswith("lsa_"):
        now = int(time.time())
        try:
            snapshot = read_object(OAUTH_TOKEN_FILE)
            entries = snapshot.get("tokens", []) if snapshot.get("schema") == 1 else []
        except (OSError, ValueError, json.JSONDecodeError):
            entries = []
        if isinstance(entries, list):
            for entry in entries:
                digest = "0" * 64
                client_id = ""
                expiry = 0
                if isinstance(entry, dict):
                    stored = entry.get("digest")
                    if isinstance(stored, str) and re.fullmatch(r"[a-f0-9]{64}", stored):
                        digest = stored
                    if isinstance(entry.get("client"), str):
                        client_id = entry["client"]
                    if isinstance(entry.get("expires_at"), int):
                        expiry = entry["expires_at"]
                token_matches = hmac.compare_digest(candidate, digest)
                client = clients.get(client_id)
                if (
                    token_matches
                    and expiry > now
                    and isinstance(client, dict)
                    and client.get("enabled") is True
                    and client.get("auth") == "oauth"
                ):
                    matched_id = client_id
                    matched_sources = client.get("sources")
    if matched_id is None or not source_allowed(source, matched_sources):
        return None
    return matched_id


def parse_bearer(value: str | None) -> str | None:
    if not value or not value.startswith("Bearer "):
        return None
    token = value[7:]
    if not re.fullmatch(r"(?:lst|lsa)_[A-Za-z0-9_-]{43}", token):
        return None
    return token


def validate_transport_config(
    config: dict[str, Any],
) -> tuple[str, int, list[str], Path, Path, str | None, list[str]]:
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
    resource = config.get("resource")
    authorization_servers = config.get("authorization_servers", [])
    if resource is None and authorization_servers == []:
        return str(address), port, normalized_hosts, cert_path, key_path, None, []
    parsed_resource = urlsplit(resource if isinstance(resource, str) else "")
    try:
        resource_port = parsed_resource.port
    except ValueError as exc:
        raise ValueError("transport OAuth resource is invalid") from exc
    if (
        parsed_resource.scheme != "https"
        or not parsed_resource.hostname
        or parsed_resource.path != "/mcp"
        or parsed_resource.query
        or parsed_resource.fragment
        or parsed_resource.username
        or parsed_resource.password
    ):
        raise ValueError("transport OAuth resource is invalid")
    if not isinstance(authorization_servers, list) or not authorization_servers or len(authorization_servers) > 4:
        raise ValueError("transport OAuth authorization server list is invalid")
    normalized_authorization_servers = []
    for item in authorization_servers:
        parsed = urlsplit(item if isinstance(item, str) else "")
        try:
            authorization_port = parsed.port
        except ValueError as exc:
            raise ValueError("transport OAuth authorization server is invalid") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("transport OAuth authorization server is invalid")
        normalized_authorization_servers.append(str(item).rstrip("/"))
    return (
        str(address), port, normalized_hosts, cert_path, key_path,
        str(resource), normalized_authorization_servers,
    )


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
        self.resource: str | None = None
        self.authorization_servers: list[str] = []
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
            challenge = 'Bearer realm="labsteward"'
            resource = self.server.resource  # type: ignore[attr-defined]
            if resource:
                metadata_url = resource.rsplit("/mcp", 1)[0] + "/.well-known/oauth-protected-resource/mcp"
                challenge += f', resource_metadata="{metadata_url}"'
            self.send_header("WWW-Authenticate", challenge)
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
        source = self.source
        if not self.server.rate_limiter.allow(source):  # type: ignore[attr-defined]
            self.send_empty(429)
            return
        if not self.host_allowed() or self.headers.get("Origin") is not None:
            self.send_empty(403)
            return
        if self.path in {
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        } and self.server.resource:  # type: ignore[attr-defined]
            self.send_json(
                200,
                {
                    "resource": self.server.resource,  # type: ignore[attr-defined]
                    "authorization_servers": self.server.authorization_servers,  # type: ignore[attr-defined]
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": ["mcp:connect"],
                },
            )
            return
        self.send_empty(404)

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
            result = self.dispatch(method, request.get("params", {}), client_id=client_id)
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

    def dispatch(self, method: str, params: object, *, client_id: str) -> dict[str, Any]:
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
            available_tools = {tool["name"] for tool in tool_definitions()}
            if name not in available_tools:
                raise DispatchError("unknown_action", "Unknown LabSteward tool")
            result = dispatch_action(str(name), arguments, client_id=client_id)
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
    bind, port, allowed_hosts, cert_path, key_path, resource, authorization_servers = validate_transport_config(config)
    server = LabStewardHTTPServer((bind, port), MCPHandler)
    server.allowed_hosts = allowed_hosts
    server.resource = resource
    server.authorization_servers = authorization_servers
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
        bind, port, allowed_hosts, cert_path, key_path, resource, authorization_servers = validate_transport_config(config)
        if args.check_config:
            print(f"valid transport configuration for {bind}:{port}")
            return 0
        server = LabStewardHTTPServer((bind, port), MCPHandler)
        server.allowed_hosts = allowed_hosts
        server.resource = resource
        server.authorization_servers = authorization_servers
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
cat >/opt/labsteward/lib/labsteward_admin.py <<'EOF_LABSTEWARD_ADMIN'
#!/usr/bin/env python3
"""OAuth authorization server and browser admin interface for LabSteward."""

from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import tempfile
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

DEFAULT_CONFIG = Path(
    os.environ.get("LABSTEWARD_ADMIN_CONFIG", "/etc/labsteward-admin/config.json")
)
ADMIN_CREDENTIAL = Path(
    os.environ.get("LABSTEWARD_ADMIN_CREDENTIAL", "/etc/labsteward-admin/admin.json")
)
OAUTH_STATE = Path(
    os.environ.get("LABSTEWARD_OAUTH_STATE", "/var/lib/labsteward-admin/oauth.json")
)
BROKER_SOCKET = Path(
    os.environ.get("LABSTEWARD_BROKER_SOCKET", "/run/labsteward/admin-broker.sock")
)

MAX_BODY_BYTES = 64 * 1024
MAX_JSON_BYTES = 1024 * 1024
ACCESS_TOKEN_SECONDS = 10 * 60
REFRESH_TOKEN_SECONDS = 30 * 24 * 60 * 60
AUTH_CODE_SECONDS = 2 * 60
TRANSACTION_SECONDS = 10 * 60
SESSION_IDLE_SECONDS = 15 * 60
MAX_STATE_ITEMS = 2048
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
TOKEN_VALUE = re.compile(r"^ls[acr]_[A-Za-z0-9_-]{43}$")
BRAND_MARK_PNG = base64.b64decode(
(
    "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6"
    "UTwAAAAGYktHRAD/AP8A/6C9p5MAAAAHdElNRQfqCBUTDxMx+j4QAAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDI2LTA4LTIxVDE5OjA5"
    "OjMyKzAwOjAw8gf2PwAAACV0RVh0ZGF0ZTptb2RpZnkAMjAyNi0wOC0yMVQxOTowOTozMiswMDowMINaToMAAAAodEVYdGRhdGU6"
    "dGltZXN0YW1wADIwMjYtMDgtMjFUMTk6MTU6MTkrMDA6MDBP3wOVAAAP40lEQVR42u2be4xkR3XGf19V3e6Z2RnvO8YO9gJ2TBAO"
    "Lz+E7c3agqxNbCcQHgG/wkORjOIoSISgoASiAHEkEhKkEGSIFJL1GkKCMBDjt4127fWDh4whGDDGD1iv13jfMzs93fdWnfxxb3ff"
    "7pmd2fXsbkLi+mMffaurzvnqq3O+OrcanmvPtf/XTUd7wos3XQt5ObM8PiH+9hP3x0uufi3H7tjPD67ZyE8/d9P/PQAu2HwdwRIG"
    "xMyTdYogU5EkfDI/3ciSS8kEWMi59ey3HxW73NGY5MJNG2lYxJUTyndyDypMnGfozSbi7ee81YR5meFzzwVbPndUADjiDLh400YS"
    "EYcAhcy5Ik8Fwl2VzD5pgMn9zUjRfv9UYwlZKjLlnXzyJaex5NHvUzQLbjvz937xAHjdls/h8wLhMABS5qT8q+su5+JN1/4z4p1G"
    "uSOEgqGvt51/SzPGnU6WxZAVMgwzki+4+ewrfjEAePPXv0or20fWjkQnzMmbS2ZRSXIvgfTvhp1qqAC8ynCYS2QYOw1d5rBbZkaW"
    "0Gy3wg2XXVi85otfo5GDeePWsw4vEIcVgIvv2oilCBJIUrQg53IjkRLvkfj7BDIsF8oAMAMJiQIjCIHcpyZHR9870ZppN1LyLQ/N"
    "RFxZwNaGCMq4ce3v/u8AIFs6zvk3fBpSqhyRksXg5HJiQt69NKV0jWFry62gCPj+CNYzQ5AAnJwD/TTCH41E+0orgE8pROdS+xUn"
    "p+zRHbh9e2hlkU2vXly2eNYArL9vA6HtaEWHbxQ0oxyYC65RRMtx0lJL9sGE/XHlZlE5PjRnCYCqjw1DkEsVQ9CNUXzAp/Td6By+"
    "KHxyXtEpLtvXsKLZYeeSnCU2wY1nv/nIAXDxvV+hY9OMtjp0li0htlpkSQ4zJ0spySUwgs8mYir+ALM/MVhppYNDq153/gCmGEnC"
    "JHmAZGxMTh/zRf49U2AmC4x3ipDLzBwpZoXF7e9kZMU17G8eAz6y+YyFs8eCAPzm3RtQ4cquLjkM58xYf9PjxW0XnQSWMEuY3Clg"
    "7wLehVhtpROzVt3MkLpTW/VZrYNUfVwxQxRA6Jpr2E0Gn5kJzZsnOp2ZXAlzYqQtV4TkknN20X33xz98/z+wfst13Lb28sUBcPHm"
    "DZgJhEuQZODMWL5rmt2rJk4BW58svQmz86yMYACFKsetT+tZ613FvyFTrLcdhloNCAC2Al9Lxg3JcV+zrR0pRJLzuJjceDtP15+7"
    "jDMenGbLWQdmQmCe9u5rb2ErT1MpxmToOGGvN+dO27lq7NVYfGnpZM+TruOhvsLqBbl+wDPqTJhjTaQ+SGX/UI0VwUA834wrhV3p"
    "jb1Fgwcx94BhXzJsczs4tcfuthd+/6R5F3heACoiOikl4BSP7jNYbmbdZwgKkDBzQoGaUzY0lmrOzXo4TMlueuzxp4IB8xUwCUhI"
    "ApYKW4dYJ/SeIoRLzOvfLtx0uu/4Z+J8/h3EWcA58Jj8W0HLgVZJRyWBmVnAqn0u8Cp3gdU81JyAqOpjvb+7fayKFanysjuW08A4"
    "DggC70pKRFALwCe9xZFwJL3sqV+e37v5HmqAoKrsUFYyx1z/sSGJmBJ78jZFSr1FHFxWaq7WZ1Btlbt9as8MihTZ15khWhraNKoo"
    "hTezBhJOyrtfDeaZr827BTQnTa1PR+tFaoqUaPqM3z/5DF659NiKmX0G2Bwbghqx+/2oaYP+MzPjob3P8K+PP8Bk0SZznjTMK6k8"
    "O5hJ6o6UFgGAG37cNbQyse6kxIdeeh6nrzieI9VOmljJyRMreN93biZZybqe+9ZT4DV4QZp/l88fBKsChnqpTBXhKqpauYemig6v"
    "XnUip684npgiW1uT7GxP452jGzBrqNH9cteBeoqsp0dXuZGnyPLGKCeMHcNLlv4SZ606kdue/gnHZCMkS5WjtTXq6Qj68z8rAEg1"
    "JFWGAeuLly5VoyWOHVnSm/+jD23iR5M7GPGBaMZgtpud4+u2UzN4qugQ5PASLxxfwadP+y0CcOzIeMkAM7ABTPs2dgdNiwKgtlOt"
    "b1sy6wuWinZG/5lhjPhA04UyxlervWCrDLcq4l+x5uU8057mpu0PIyBaN7j2I0X/q30OSapEhvVY9CwBUE+XzVbt/T+l2etqFRB9"
    "xhwgDA4NLqAdC140sZK3v/CVTBcdbnn6ka5rg2BVKVSl071hTLUdsQDu80aIf7zi/FlIzzKkSlO9ySsWaFYaZVaim3NwoOkDT07v"
    "45pHvsHfPXwvMcWqqw1/e/b4pYI0DZwxnzUD6ieVQQ5r1iqXJgU5ghytWJTaYK4gZP3E56TyMDUErGH8y2MP9GIAgK8iusq6Q1Vb"
    "75po/VNEL9jaARXnQQPQjXWGdeor2KX2XEr+L099DbvzGXw9ylfBqq/tq/5DW6C+sl3ll6fI0myErAtAnU0D8aCqPpKir8yb8fni"
    "AEiVJkuw1/fXfsBg1VbPMJ43Ms7ybGSOwDe4zgMnijn6uerjZEYmXxNMw6irOrSUodlgylI5xuSSYnEAdKMyYmd3/lmsqgUgSfzp"
    "d2/n+3ufZjRkNSXXY2xP8VmdojVcu8GxFQuCHJjxovGVfOzl6/F1+KuOZTbqHppAcru6Vp609zjuXwwAJtc9t25HqYyr1rd4OEPk"
    "KfH0zCTTMaewQRlaM3Hgs+GIJqAw41cnVjNVtHl0ajc7O9PkKZK5oXKiWS/Si26B1Z7sjTk2vjgGmHNmEiZ+5i3lGBlgErLuCd/q"
    "qycy5/ESoS5Vhxyv/8tKCd+L4u0YecH4cj552kU8MzPFpff+B24opmsoeFTJuuKYe6wCxbbrZ4sDQC5ZMZIRPduae9lmxhrVcwMV"
    "Auonwq6M9XKk4TBc1769lesfe5xEwzv25TM8sPsptrb2YhLBadYwvYFKFpjAIyyXHumfI+dvCwJQEGxi535vopNn2Q+ErQGZKM/r"
    "w0JDElNFzp68xUjKBmXpXED0VJwGcNnTmeHKb30FJwcY+4rOoPM294hmbG019bhPMBKj3blApXhBACbSEtpZR5Tp5R4PrxtU7F06"
    "lN4EOS478WU8OrWLpg+lbFa9/ldHo1YU7T7rplf1Kd9OBSeMLaXp+3moewiobQuTRELfWd3K28L8LhpxAfcWBqCt/SSvCnTdqWQf"
    "NjM3pL17/aMlLjr+lIWGfVatSLGXGruKp5eGJati8x3tUuCKXaMLjrkgAPtDh5HCp9ZokyJz31yxa/8TMlsjlKqq0EDzcmx8/EF+"
    "NLmjxwCpRgGrGd4Ta9ZLjarFhWSGAzop8YLx5bxjzcv7E/VCjlUlSQsmkUu3lmcTS9ny6cUDsOnMK3j3Pdfbk/umAtApxA1eukpY"
    "MiulmfXqeqVqu3H7wzw2tZumDwc4j/el0FyvRlSl0+AcKRkdi6wZX8HbTjiVMefmyiwRzJu5+1e0J3+QpaRto8tTMbbgDjgIIQQ8"
    "E2fIXVmLNrHBR7uKXr1itt4e9w2OCc0+A2aJl2oL90ConSyBwhLLRkf5+Ctex+P7d/PB/7qD8ZANANQbrhcQHCZtmMzGAXyOL+4+"
    "420L+nZQN0R2hZw8+HhMq+3GZzrfSGIL4DDrQzzHWdd6R9ahTrVtMFwJNJXyu+kDx41O8LyRCYQ74KGmgj8g7e747PO5CyQpNphf"
    "Ah8SA5yNA20mR5oOSEl8PJidU/euHginig6TeZuRA22BwRLOoC6oQsWPJ3fyxi2fpxMjU3mb/TGfXVgt/1sgZSb3T6Mx3w2EIlFk"
    "B3n556AAuOPsN3LBXRuZavrixU/tU6vpr9+9pPlNGWcgopCfiSXiwTnWrV7D6uYYo6HRqxB1KW8D54G5iiT9PdJJkSBHkRIvmljR"
    "k8Htqj5QicjM0FQn6eNIeCyKxM3rLjt8AABMj3p8bmxbscSBosk+INntBoyGjAf3bGe66DAWGrz75DMPdthDbkWKfGvXk112FaDM"
    "0NUN0s9lBMMVRXbQbh38LbG7Tr+ELBrH7WzHUBQh5PGOJF0H+IZc/vTMFB99aDO7O60j5vxk3ubqhzbzxP49NJ2PCbKIfnhT59K/"
    "/olfyYwUPcbXf/vKgx7zkC5InPXtDewdn+CEn+93ySkls2Uj0X6MpVWS0nQs3PLGKCeNryiLIbUtDgeMY0PGaEDgdFsCHp3axY6Z"
    "/YyFhhkJk1OBPxu4V5g3FKM37jzn4Oh/yAAArN9yHT4aziwAhUkXOLObMUtOUmFJM6mov+KvnB967V0JoO5b4IFm9bN911DRcJ4g"
    "R/eOUcJ9SGYfATIzy5Nz3HLuwTvPocSAbtvbdKzaX9CIVkTnAuiWJP25SB9NWO7ksvHQHCpSzdFsDlDqbBmoEXRflRvJUkdyDZP/"
    "z+Dyj/jYcdNueT7a2se+sYWl76IZAPAbW67j9Q9Pcv2vLGNZ3nKFcyniPyvsHQnLgWy+71tdDwy8QxzcBgySCCBHygz3vb1x7FXj"
    "FIVc4QyXzCduXXvJ0QEA4Py7N6LkEUnPhOPsxNZPaQd/vbA3gHLD5gRhrncDwyXugesy9NiSI2XgnohqvkoWd4nkMSLATeceuvMs"
    "5q7wrWsvx5khw1YX29yuEc+qTvgdk74EZCpvi8y5A1RNXHe4fvztFTv67/k61co/UqTsTJfiLmcpyIhg7AsHp/oOKwAAk428Ww9L"
    "oxH3o7E2E1FvMvSZWnyJ/XrZ8CuVWpurzC4MrEBqYLqvjXuVVPwcYgArJOiExJZznv3t0UUBcPdZb2fPaNHd1Wl5DO4TT30REa9M"
    "zr23IrEH5XUnGb4oUcsUtR6FQCaFZNqwtJg8K8CkK4EtMOg4445zLj8km4fbYbkqe/Y3r2WiRXkxWqjZiS55H6P4dU/6AuI4Myuq"
    "t+kLgW7VvaPMJBJcFcSnptoNRrLci3LPt724c+2li7b9sPxe4J4zrmD7ePkmVs7Z5NJmpAyCd00Hf4qhz1f3eZwgP/AVKYrqQmIG"
    "7oEC/ZozPhUM38xyUTmfZ/GwOM+RuC1+/j0bWblLTI8ZuSd0goolnUQu3iDxSbDy1pJUYISK9LFKf95M0eT+YiZs+6tmcTwey7ZC"
    "vgojAPtGE/cext8PHJHfC6zfspGsCn1JuLHClIvYaoTRZh4/LHgfMjBLhiVQda9QX07Jv887+8mOdZeyYvN1PiRFZ4nJhnHn2sP/"
    "m4Ej9oOJ8+7fQCN37AmOC7flfGulD8mHwmJOUnhxMLtapDdWF1zuN9OfBZ/uKHKH85aZhaL74j0PPCuR8z8KQLede9cGJsx3qz0i"
    "JZ/wRYaR5M/FtDzz7S+3YyC45ItC5iBJ0AFuPe/QtP2hNn8Yxpi3PfHZ6+mcuobVz38+lhcgl+RwHnPIPQb8sOlbylPwJ7+gGbc+"
    "lcwHmMkit687Mj+Tqbej+rvBdd/+AkumI1NZh7ZLrJ4Z9ZjILUYwvBxWeG5+7VuPplnPtefac+3/cftv5lbtwuJqRB0AAAAASUVO"
    "RK5CYII="
)
)





class AdminError(Exception):
    """A safe request error."""


def read_object(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise AdminError("Stored authorization data exceeds the size limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AdminError("Required authorization data is unavailable") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AdminError("Stored authorization data is invalid") from exc
    if not isinstance(value, dict):
        raise AdminError("Stored authorization data is invalid")
    return value


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        if path.exists():
            metadata = path.stat()
            os.chown(temporary, metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def empty_oauth_state() -> dict[str, Any]:
    return {
        "schema": 1,
        "registrations": {},
        "transactions": {},
        "codes": {},
        "refresh_tokens": {},
    }


def clean_state(state: dict[str, Any]) -> dict[str, Any]:
    now = int(time.time())
    for name in ("transactions", "codes", "refresh_tokens"):
        registry = state.get(name)
        if not isinstance(registry, dict):
            raise AdminError("OAuth state is inconsistent")
        state[name] = {
            key: item
            for key, item in registry.items()
            if isinstance(item, dict) and isinstance(item.get("expires_at"), int) and item["expires_at"] > now
        }
    if not isinstance(state.get("registrations"), dict):
        raise AdminError("OAuth state is inconsistent")
    return state


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def b64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def redirect_with_query(url: str, values: dict[str, str]) -> str:
    parsed = urlsplit(url)
    query = "&".join(item for item in (parsed.query, urlencode(values)) if item)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def normalize_source(value: str) -> str:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def source_allowed(source: str, networks: object) -> bool:
    if not isinstance(networks, list):
        return False
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return False
    for value in networks:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except (TypeError, ValueError):
            continue
        if address.version == network.version and address in network:
            return True
    return False


def require_loopback_redirect(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise AdminError("Invalid redirect URI")
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.fragment or parsed.username or parsed.password:
        raise AdminError("OAuth redirect URIs must be loopback HTTP URLs")
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        redirect_port = parsed.port
    except ValueError as exc:
        raise AdminError("OAuth redirect URIs must use a loopback IP literal") from exc
    if not address.is_loopback or redirect_port is None or not parsed.path.startswith("/"):
        raise AdminError("OAuth redirect URIs must use a loopback IP, port, and path")
    return value


def read_admin_credential() -> dict[str, Any]:
    value = read_object(ADMIN_CREDENTIAL)
    if value.get("schema") != 1 or value.get("algorithm") != "scrypt":
        raise AdminError("Administrator credentials are not initialized")
    return value


def password_matches(username: str, password: str) -> bool:
    try:
        record = read_admin_credential()
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["digest"], validate=True)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(record["n"]),
            r=int(record["r"]),
            p=int(record["p"]),
            dklen=len(expected),
            maxmem=64 * 1024 * 1024,
        )
        name_matches = hmac.compare_digest(username, str(record["username"]))
        digest_matches = hmac.compare_digest(candidate, expected)
        return name_matches and digest_matches
    except (AdminError, KeyError, TypeError, ValueError):
        # Perform comparable work even when the record is malformed.
        hashlib.scrypt(password.encode("utf-8"), salt=b"0" * 16, n=2**14, r=8, p=1, dklen=32)
        return False


def broker_call(operation: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    request = json.dumps(
        {"operation": operation, "arguments": arguments or {}}, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    if len(request) > MAX_BODY_BYTES:
        raise AdminError("Management request exceeds the size limit")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(str(BROKER_SOCKET))
            connection.sendall(request)
            stream = connection.makefile("rb")
            raw = stream.readline(MAX_BODY_BYTES + 1)
    except OSError as exc:
        raise AdminError("The protected management broker is unavailable") from exc
    if not raw or len(raw) > MAX_BODY_BYTES:
        raise AdminError("The protected management broker returned an invalid response")
    try:
        response = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AdminError("The protected management broker returned an invalid response") from exc
    if not isinstance(response, dict) or response.get("ok") is not True:
        message = response.get("error") if isinstance(response, dict) else None
        raise AdminError(message if isinstance(message, str) else "Management operation failed")
    result = response.get("result")
    if not isinstance(result, dict):
        raise AdminError("The protected management broker returned an invalid response")
    return result


class SlidingLimiter:
    def __init__(self, maximum: int, window: int) -> None:
        self.maximum = maximum
        self.window = window
        self.entries: dict[str, collections.deque[float]] = {}
        self.lock = threading.Lock()

    def allow(self, source: str) -> bool:
        now = time.monotonic()
        with self.lock:
            history = self.entries.setdefault(source, collections.deque())
            while history and history[0] < now - self.window:
                history.popleft()
            if len(history) >= self.maximum:
                return False
            history.append(now)
            if len(self.entries) > 1024:
                empty = [key for key, value in self.entries.items() if not value]
                for key in empty:
                    self.entries.pop(key, None)
            return True


class AdminServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]):
        super().__init__(address, handler)
        self.allowed_hosts: list[str] = []
        self.admin_sources: list[str] = []
        self.enrollment_sources: list[str] = []
        self.issuer = ""
        self.resource = ""
        self.ssl_context: ssl.SSLContext | None = None
        self.state_lock = threading.Lock()
        self.sessions: dict[str, dict[str, Any]] = {}
        self.session_lock = threading.Lock()
        self.request_limiter = SlidingLimiter(120, 60)
        self.login_limiter = SlidingLimiter(5, 300)
        self.connection_slots = threading.BoundedSemaphore(32)

    def process_request(self, request: Any, client_address: tuple[str, int]) -> None:
        if not self.connection_slots.acquire(blocking=False):
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
            request.settimeout(15)
            if self.ssl_context is None:
                raise ssl.SSLError("TLS context unavailable")
            tls_request = self.ssl_context.wrap_socket(request, server_side=True)
            super().process_request_thread(tls_request, client_address)
        except (OSError, ssl.SSLError):
            try:
                request.close()
            except OSError:
                pass
        finally:
            self.connection_slots.release()

    def load_state(self) -> dict[str, Any]:
        with self.state_lock:
            if not OAUTH_STATE.exists():
                atomic_write(OAUTH_STATE, empty_oauth_state())
            state = read_object(OAUTH_STATE)
            if state.get("schema") != 1:
                raise AdminError("Unsupported OAuth state")
            cleaned = clean_state(state)
            atomic_write(OAUTH_STATE, cleaned)
            return cleaned

    def update_state(self, operation: Any) -> Any:
        with self.state_lock:
            if not OAUTH_STATE.exists():
                atomic_write(OAUTH_STATE, empty_oauth_state())
            state = clean_state(read_object(OAUTH_STATE))
            result = operation(state)
            for name in ("registrations", "transactions", "codes", "refresh_tokens"):
                if len(state.get(name, {})) > MAX_STATE_ITEMS:
                    raise AdminError("OAuth state registry is full")
            atomic_write(OAUTH_STATE, clean_state(state))
            return result


STYLE = """
:root{color-scheme:dark;--bg:#0b1220;--panel:#131d2f;--line:#2a3850;--text:#e9eef7;--muted:#9aabc1;--accent:#6ee7b7;--danger:#fb7185}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,sans-serif}main{max-width:1100px;margin:0 auto;padding:32px 20px}h1,h2{margin:.2em 0 .7em}h3,h4{margin:.4em 0 .7em}p{line-height:1.5}.muted{color:var(--muted)}
nav,.client-head,.row-actions,.page-tabs,.brand,.login-brand{display:flex;justify-content:space-between;align-items:center;gap:10px}nav{margin-bottom:14px}.brand,.login-brand{justify-content:flex-start}.brand img{width:42px;height:42px}.brand h1,.login-brand h1{margin:0;font-family:Georgia,'Times New Roman',serif;font-weight:700;letter-spacing:.01em}.brand h1{font-size:42px;line-height:1}.login-brand h1{font-size:36px;line-height:1}.login-brand img{width:52px;height:52px}.page-tabs{justify-content:flex-start;margin-bottom:24px;border-bottom:1px solid var(--line)}.page-tabs a{padding:10px 14px;text-decoration:none;color:var(--muted);border-bottom:2px solid transparent}.page-tabs a.active{color:var(--text);border-color:var(--accent)}
.card,section,.client-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin:14px 0}.client-card{background:#101a2b}.client-settings{display:grid;grid-template-columns:minmax(250px,1fr) auto;gap:14px;align-items:end}.row-actions{justify-content:flex-end;white-space:nowrap}
.server-access{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#0d1728}.access-row+.access-row{border-top:1px solid var(--line)}.access-row summary{display:grid;grid-template-columns:minmax(180px,1fr) auto auto;gap:14px;align-items:start;padding:13px 14px;cursor:pointer;list-style:none}.access-row summary::-webkit-details-marker{display:none}.collapse-icon{display:inline-block;width:9px;height:9px;border-right:2px solid var(--accent);border-bottom:2px solid var(--accent);transform:rotate(45deg);transition:transform .15s ease;margin:2px 4px 0}.access-row[open] .collapse-icon{transform:rotate(225deg);margin-top:7px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.access-body{border-top:1px solid var(--line);padding:14px}.permission-list{display:grid;gap:0;margin-bottom:14px}.permission-control{display:grid;grid-template-columns:minmax(220px,1fr) auto;align-items:start;gap:16px;padding:10px 0}.permission-control+.permission-control{border-top:1px solid var(--line)}.permission-name{font-weight:600}.permission-description{display:block;color:var(--muted);font-size:13px;margin-top:3px}.help{display:inline-grid;place-items:center;width:17px;height:17px;border:1px solid var(--line);border-radius:50%;font-size:11px;color:var(--muted);cursor:help;margin-left:5px}.level-toggle{display:inline-flex;border:1px solid var(--line);border-radius:7px;overflow:hidden}.level-choice{display:inline-flex;align-items:center;margin:0;padding:7px 11px;background:#111d31;cursor:pointer}.level-choice+.level-choice{border-left:1px solid var(--line)}.level-choice:has(input:checked){background:#1d6f58;color:#fff}.level-choice input{position:absolute;opacity:0;pointer-events:none}
table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:10px 8px;vertical-align:top}input,select,button,.button-link{font:inherit;border-radius:7px;border:1px solid var(--line);padding:8px 10px;background:#0d1728;color:var(--text)}button{cursor:pointer;background:#1d6f58;border-color:#2ca47e}button.secondary{background:#18243a;border-color:var(--line)}button.danger{background:#7f1d32;border-color:#be3453}button:disabled{cursor:not-allowed;opacity:.55}.button-link{display:inline-block;text-decoration:none;background:#18243a}form.inline{display:inline-flex;gap:8px;flex-wrap:wrap}.notice{border-left:4px solid var(--accent);padding:10px 14px;background:#10251f}.error{border-left-color:var(--danger);background:#2b1118}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 8px;margin:2px}.login{max-width:430px;margin:10vh auto}label{display:block;margin:12px 0 5px}a{color:var(--accent)}
@media(max-width:720px){.client-head{align-items:flex-start;flex-direction:column}.client-settings{grid-template-columns:1fr}.access-row summary{grid-template-columns:1fr}.permission-control{grid-template-columns:1fr}.row-actions{justify-content:flex-start;white-space:normal}.page-tabs{overflow-x:auto}table{display:block;overflow-x:auto}}
""".strip()


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "LabSteward"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    @property
    def source(self) -> str:
        try:
            return normalize_source(self.client_address[0])
        except ValueError:
            return "invalid"

    def host_allowed(self) -> bool:
        header = self.headers.get("Host", "")
        if header.startswith("["):
            host = header[1:].split("]", 1)[0]
        else:
            host = header.rsplit(":", 1)[0]
        return host.lower().rstrip(".") in self.server.allowed_hosts  # type: ignore[attr-defined]

    def security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.close_connection = True
        self.send_response(status)
        self.security_headers(content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        self.send_bytes(
            status,
            json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
            "application/json",
        )

    def send_html(self, status: int, title: str, content: str) -> None:
        page = (
            "<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)} · LABSteward</title>"
            "<link rel=icon type=image/png href=/favicon.png>"
            "<link rel=stylesheet href=/admin/style.css></head><body><main>"
            f"{content}</main></body></html>"
        )
        self.send_bytes(status, page.encode("utf-8"), "text/html; charset=utf-8")

    def redirect(self, location: str, *, cookie: str | None = None) -> None:
        self.close_connection = True
        self.send_response(303)
        self.security_headers("text/plain; charset=utf-8")
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise AdminError("Chunked request bodies are not accepted")
        values = self.headers.get_all("Content-Length", [])
        if len(values) != 1:
            raise AdminError("A single Content-Length header is required")
        try:
            length = int(values[0])
        except ValueError as exc:
            raise AdminError("Invalid Content-Length") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise AdminError("Request body exceeds the size limit")
        return self.rfile.read(length)

    def read_form(self) -> dict[str, str]:
        if self.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/x-www-form-urlencoded":
            raise AdminError("Expected a form request")
        try:
            values = parse_qs(self.read_body().decode("utf-8"), keep_blank_values=True, max_num_fields=128)
        except (UnicodeDecodeError, ValueError) as exc:
            raise AdminError("Invalid form request") from exc
        return {key: items[-1] for key, items in values.items() if items}

    def read_json_body(self) -> dict[str, Any]:
        if self.headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/json":
            raise AdminError("Expected a JSON request")
        try:
            value = json.loads(self.read_body())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdminError("Invalid JSON request") from exc
        if not isinstance(value, dict):
            raise AdminError("Expected a JSON object")
        return value

    def origin_allowed(self) -> bool:
        issuer = str(self.server.issuer).strip().rstrip("/")  # type: ignore[attr-defined]
        origin = self.headers.get("Origin", "").strip().rstrip("/")
        # Some browsers omit Origin (or send an opaque `null` origin) for a
        # same-origin form submission when using a locally trusted/self-signed
        # certificate. In that case require a same-origin HTTPS Referer rather
        # than accepting the request without a browser provenance signal.
        if not origin or origin.lower() == "null":
            origin = self.headers.get("Referer", "").strip().rstrip("/")
        try:
            parsed_origin = urlsplit(origin)
            parsed_issuer = urlsplit(issuer)
            origin_port = parsed_origin.port or (443 if parsed_origin.scheme == "https" else 80)
            issuer_port = parsed_issuer.port or (443 if parsed_issuer.scheme == "https" else 80)
        except ValueError:
            return False
        return (
            parsed_origin.scheme.lower() == parsed_issuer.scheme.lower() == "https"
            and parsed_origin.hostname is not None
            and parsed_issuer.hostname is not None
            and parsed_origin.hostname.lower().rstrip(".") == parsed_issuer.hostname.lower().rstrip(".")
            and origin_port == issuer_port
        )

    def session(self) -> tuple[str, dict[str, Any]] | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
        except cookies.CookieError:
            return None
        morsel = jar.get("labsteward_admin")
        if morsel is None:
            return None
        session_id = morsel.value
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", session_id):
            return None
        now = int(time.time())
        with self.server.session_lock:  # type: ignore[attr-defined]
            session = self.server.sessions.get(token_digest(session_id))  # type: ignore[attr-defined]
            if (
                not isinstance(session, dict)
                or session.get("source") != self.source
                or session.get("last_seen", 0) + SESSION_IDLE_SECONDS <= now
            ):
                return None
            session["last_seen"] = now
            return session_id, dict(session)

    def require_session(self, csrf: str | None = None) -> tuple[str, dict[str, Any]]:
        session = self.session()
        if session is None:
            raise AdminError("Administrator authentication is required")
        if csrf is not None and not hmac.compare_digest(str(session[1].get("csrf", "")), csrf):
            raise AdminError("Invalid form security token")
        return session

    def require_admin_source(self) -> None:
        if not source_allowed(self.source, self.server.admin_sources):  # type: ignore[attr-defined]
            raise AdminError("Administrator access is not allowed from this source")

    def require_enrollment_source(self) -> None:
        if not source_allowed(self.source, self.server.enrollment_sources):  # type: ignore[attr-defined]
            raise AdminError("Client enrollment is not allowed from this source")

    def browser_error(self, message: str, status: int = 400) -> None:
        self.send_html(
            status,
            "Request denied",
            f"<section class='notice error'><h1>Request denied</h1><p>{html.escape(message)}</p></section>",
        )

    def do_GET(self) -> None:  # noqa: N802
        if not self.server.request_limiter.allow(self.source):  # type: ignore[attr-defined]
            self.send_json(429, {"error": "rate_limited"})
            return
        if not self.host_allowed():
            self.send_json(403, {"error": "invalid_host"})
            return
        path = urlsplit(self.path).path
        try:
            if path == "/.well-known/oauth-authorization-server":
                self.oauth_metadata()
            elif path == "/favicon.png":
                self.send_bytes(200, BRAND_MARK_PNG, "image/png")
            elif path == "/admin/style.css":
                self.send_bytes(200, STYLE.encode("utf-8"), "text/css; charset=utf-8")
            elif path == "/admin/login":
                self.require_admin_source()
                self.login_page()
            elif path in {"/admin", "/admin/servers", "/admin/plugins"}:
                self.require_admin_source()
                if self.session() is None:
                    self.redirect("/admin/login")
                else:
                    page = {"/admin": "clients", "/admin/servers": "servers", "/admin/plugins": "plugins"}[path]
                    query = parse_qs(urlsplit(self.path).query, keep_blank_values=True, max_num_fields=8)
                    self.dashboard(page=page, selected_server=query.get("server", [""])[-1])
            elif path == "/authorize":
                self.require_enrollment_source()
                self.authorize_page()
            else:
                self.send_json(404, {"error": "not_found"})
        except AdminError as exc:
            self.browser_error(str(exc), 403 if "not allowed" in str(exc) else 400)

    def do_POST(self) -> None:  # noqa: N802
        if not self.server.request_limiter.allow(self.source):  # type: ignore[attr-defined]
            self.send_json(429, {"error": "rate_limited"})
            return
        if not self.host_allowed():
            self.send_json(403, {"error": "invalid_host"})
            return
        path = urlsplit(self.path).path
        try:
            if path == "/oauth/register":
                self.require_enrollment_source()
                self.oauth_register()
            elif path == "/oauth/token":
                self.require_enrollment_source()
                self.oauth_token()
            elif path == "/oauth/revoke":
                self.require_enrollment_source()
                self.oauth_revoke()
            elif path == "/admin/login":
                self.require_admin_source()
                self.login()
            elif path == "/admin/logout":
                self.require_admin_source()
                form = self.read_form()
                session_id, _session = self.require_session(form.get("csrf"))
                with self.server.session_lock:  # type: ignore[attr-defined]
                    self.server.sessions.pop(token_digest(session_id), None)  # type: ignore[attr-defined]
                self.redirect(
                    "/admin/login",
                    cookie="labsteward_admin=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
                )
            elif path == "/authorize":
                self.require_enrollment_source()
                self.authorize_decision()
            elif path.startswith("/admin/"):
                self.require_admin_source()
                if not self.origin_allowed():
                    raise AdminError("Invalid browser origin")
                self.admin_operation(path)
            else:
                self.send_json(404, {"error": "not_found"})
        except AdminError as exc:
            if path.startswith("/oauth/"):
                self.send_json(400, {"error": "invalid_request", "error_description": str(exc)})
            else:
                self.browser_error(str(exc), 403 if "not allowed" in str(exc) else 400)

    def oauth_metadata(self) -> None:
        issuer = self.server.issuer  # type: ignore[attr-defined]
        self.send_json(
            200,
            {
                "issuer": issuer,
                "authorization_endpoint": f"{issuer}/authorize",
                "token_endpoint": f"{issuer}/oauth/token",
                "registration_endpoint": f"{issuer}/oauth/register",
                "revocation_endpoint": f"{issuer}/oauth/revoke",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": ["mcp:connect"],
            },
        )

    def login_page(self, error: str = "", transaction: str = "") -> None:
        error_html = f"<p class='notice error'>{html.escape(error)}</p>" if error else ""
        transaction_field = (
            f"<input type=hidden name=transaction value='{html.escape(transaction)}'>"
            if transaction
            else ""
        )
        self.send_html(
            200,
            "Administrator sign in",
            "<section class=login><div class=login-brand><img src=/favicon.png alt=''><h1>LABSteward</h1></div><p class=muted>Administrator sign in</p>"
            f"{error_html}<form method=post action=/admin/login>{transaction_field}"
            "<label for=username>Username</label><input id=username name=username required autocomplete=username>"
            "<label for=password>Password</label><input id=password name=password type=password required autocomplete=current-password>"
            "<p><button type=submit>Sign in</button></p></form></section>",
        )

    def login(self) -> None:
        # Login is already restricted by the configured administrator source
        # network and HTTPS listener. Browsers vary in whether they send an
        # Origin/Referer header for a plain form POST, so do not make initial
        # authentication depend on either optional header. Authenticated
        # administrator mutations retain strict origin and CSRF checks.
        form = self.read_form()
        transaction = form.get("transaction", "")
        if not self.server.login_limiter.allow(self.source):  # type: ignore[attr-defined]
            self.login_page("Too many sign-in attempts. Try again later.", transaction)
            return
        if not password_matches(form.get("username", ""), form.get("password", "")):
            time.sleep(0.25)
            self.login_page("Sign-in failed.", transaction)
            return
        now = int(time.time())
        session_id = secrets.token_urlsafe(32)
        with self.server.session_lock:  # type: ignore[attr-defined]
            self.server.sessions = {  # type: ignore[attr-defined]
                key: value
                for key, value in self.server.sessions.items()  # type: ignore[attr-defined]
                if isinstance(value, dict) and value.get("last_seen", 0) + SESSION_IDLE_SECONDS > now
            }
            if len(self.server.sessions) >= 1024:  # type: ignore[attr-defined]
                oldest = min(
                    self.server.sessions,  # type: ignore[attr-defined]
                    key=lambda key: self.server.sessions[key].get("last_seen", 0),  # type: ignore[attr-defined]
                )
                self.server.sessions.pop(oldest, None)  # type: ignore[attr-defined]
            self.server.sessions[token_digest(session_id)] = {  # type: ignore[attr-defined]
                "source": self.source,
                "csrf": secrets.token_urlsafe(32),
                "last_seen": now,
            }
        destination = f"/authorize?transaction={urlencode({'x': transaction})[2:]}" if transaction else "/admin"
        self.redirect(
            destination,
            cookie=(
                f"labsteward_admin={session_id}; Path=/; Secure; HttpOnly; SameSite=Strict; "
                f"Max-Age={SESSION_IDLE_SECONDS}"
            ),
        )

    def dashboard(
        self, notice: str = "", page: str = "clients", selected_server: str = ""
    ) -> None:
        """Render the focused Clients, Servers, or Plugins administration page."""
        _session_id, session = self.require_session()
        state = broker_call("state.get")
        csrf = html.escape(str(session["csrf"]))
        notice_html = f"<p class=notice>{html.escape(notice)}</p>" if notice else ""
        clients = {
            client_id: client
            for client_id, client in state.get("clients", {}).items()
            if isinstance(client, dict) and client.get("enabled") is True
        }
        servers = state.get("servers", {})
        installed = state.get("plugins", {})
        catalog_by_id = {
            str(item.get("id")): item
            for item in state.get("catalog", [])
            if isinstance(item, dict)
        }

        def level_mapping(value: object) -> dict[str, str]:
            if isinstance(value, list):
                return {str(item): "read" for item in value}
            if isinstance(value, dict):
                return {str(key): str(level) for key, level in value.items()}
            return {}

        def permission_names(plugin_id: str) -> list[str]:
            raw = catalog_by_id.get(plugin_id, {}).get("permissions", {})
            values = raw if isinstance(raw, list) else raw.keys() if isinstance(raw, dict) else []
            return sorted(str(item) for item in values)

        def permission_controls(plugin_id: str, selected: object, form_id: str) -> str:
            active = level_mapping(selected)
            raw_descriptions = catalog_by_id.get(plugin_id, {}).get(
                "permission_descriptions", {}
            )
            descriptions = raw_descriptions if isinstance(raw_descriptions, dict) else {}
            controls = []
            for permission in permission_names(plugin_id):
                description = str(
                    descriptions.get(permission, "Plugin-defined capability.")
                )
                choices = "".join(
                    "<label class=level-choice>"
                    f"<input type=radio name='permission.{html.escape(permission)}' value='{level}'"
                    f" aria-label='{html.escape(permission)} {level}'"
                    f" {'checked' if active.get(permission, 'off') == level else ''}"
                    f" form='{html.escape(form_id)}'><span>{level.title()}</span></label>"
                    for level in ("off", "read", "write")
                )
                controls.append(
                    "<div class=permission-control><div>"
                    f"<span class=permission-name>{html.escape(permission)}</span>"
                    f"<span class=help title='{html.escape(description)}' aria-label='{html.escape(description)}'>?</span>"
                    f"<span class=permission-description>{html.escape(description)}</span>"
                    f"</div><span class=level-toggle>{choices}</span></div>"
                )
            return "".join(controls) or "<span class=muted>No permissions are declared by this plugin.</span>"

        navigation = (
            "<nav><div class=brand><img src=/favicon.png alt=''><h1>LABSteward</h1></div>"
            "<form method=post action=/admin/logout>"
            f"<input type=hidden name=csrf value='{csrf}'><button type=submit>Sign out</button></form></nav>"
            "<div class=page-tabs>"
            f"<a href=/admin class='{'active' if page == 'clients' else ''}'>Clients</a>"
            f"<a href=/admin/servers class='{'active' if page == 'servers' else ''}'>Servers</a>"
            f"<a href=/admin/plugins class='{'active' if page == 'plugins' else ''}'>Plugins</a></div>"
        )

        if page == "clients":
            client_cards = []
            for client_id, client in sorted(clients.items()):
                sources = ", ".join(client.get("sources", []))
                grants = client.get("grants", {}) if isinstance(client.get("grants"), dict) else {}
                source_form_id = f"client-sources-{client_id}"
                access_rows = []
                for alias, granted in sorted(grants.items()):
                    server = servers.get(alias)
                    if not isinstance(server, dict):
                        continue
                    plugin_id = str(server.get("plugin", ""))
                    form_id = f"client-grants-{client_id}-{alias}"
                    configured_count = len(level_mapping(granted))
                    controls = permission_controls(plugin_id, granted, form_id)
                    access_rows.append(
                        "<details class=access-row><summary>"
                        f"<span><strong>{html.escape(alias)}</strong><br><span class=muted>{html.escape(plugin_id)}</span></span>"
                        f"<span class=muted>{configured_count} permission(s)</span><span><span class=sr-only>Toggle server permissions</span><span class=collapse-icon aria-hidden=true></span></span></summary>"
                        "<div class=access-body>"
                        f"<form id='{html.escape(form_id)}' method=post action=/admin/client/grants>"
                        f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=client value='{html.escape(client_id)}'>"
                        f"<input type=hidden name=server value='{html.escape(alias)}'><div class=permission-list>{controls}</div></form>"
                        "<div class=row-actions>"
                        f"<button type=submit form='{html.escape(form_id)}'>Save</button>"
                        "<form class=inline method=post action=/admin/client/server/remove>"
                        f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=client value='{html.escape(client_id)}'>"
                        f"<input type=hidden name=server value='{html.escape(alias)}'>"
                        "<button class=danger type=submit>Remove server</button></form></div></div></details>"
                    )
                access_content = (
                    "<div class=server-access>" + "".join(access_rows) + "</div>"
                    if access_rows
                    else "<p class=muted>No servers have been added to this client.</p>"
                )
                unassigned = [alias for alias in sorted(servers) if alias not in grants]
                server_options = "".join(
                    f"<option value='{html.escape(alias)}'>{html.escape(alias)} — {html.escape(str(servers[alias].get('plugin','')))}</option>"
                    for alias in unassigned
                )
                add_server = (
                    "<form class=inline method=post action=/admin/client/server/add>"
                    f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=client value='{html.escape(client_id)}'>"
                    f"<select name=server aria-label='Server to add' required>{server_options or '<option value="">No more servers available</option>'}</select>"
                    f"<button type=submit {'disabled' if not server_options else ''}>Add server</button></form>"
                )
                client_cards.append(
                    "<div class=client-card><div class=client-head><div>"
                    f"<h3>{html.escape(str(client.get('display_name', client_id)))}</h3>"
                    f"<span class=muted>{html.escape(client_id)} · {html.escape(str(client.get('auth','legacy_token')))}</span>"
                    "</div><span class=pill>Enabled</span></div>"
                    "<div class=client-settings><div><h4>Allowed sources</h4>"
                    f"<form id='{html.escape(source_form_id)}' class=inline method=post action=/admin/client/sources>"
                    f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=client value='{html.escape(client_id)}'>"
                    f"<input name=sources value='{html.escape(sources)}' aria-label='Allowed source CIDRs'></form></div>"
                    f"<div class=row-actions><span class=muted>{len(grants)} server(s)</span>"
                    f"<button type=submit form='{html.escape(source_form_id)}'>Save</button>"
                    "<form class=inline method=post action=/admin/client/revoke>"
                    f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=client value='{html.escape(client_id)}'>"
                    "<button class=danger type=submit>Revoke &amp; remove</button></form></div></div>"
                    f"<h4>Server access</h4>{access_content}<h4>Add server</h4>{add_server}</div>"
                )
            content = (
                "<section><h2>Clients</h2><p class=muted>Manage source restrictions and explicitly assigned servers. Expand a server only when you need to change its permissions.</p>"
                + ("".join(client_cards) or "<p>No clients</p>") + "</section>"
            )
        elif page == "servers":
            plugin_options = "".join(
                f"<option value='{html.escape(plugin_id)}'>{html.escape(plugin_id)}</option>"
                for plugin_id, record in sorted(installed.items())
                if isinstance(record, dict) and record.get("enabled") is True and plugin_id in catalog_by_id
            )
            server_rows = []
            for alias, server in sorted(servers.items()):
                server_rows.append(
                    f"<tr><td><strong>{html.escape(alias)}</strong></td><td>{html.escape(str(server.get('plugin','')))}</td>"
                    f"<td>{html.escape(str(server.get('endpoint','')))}</td><td><div class=row-actions>"
                    f"<a class=button-link href='/admin/servers?server={html.escape(alias)}'>Configure access</a>"
                    "<form class=inline method=post action=/admin/server/remove>"
                    f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=server value='{html.escape(alias)}'>"
                    "<button class=danger type=submit>Remove</button></form></div></td></tr>"
                )
            configuration = ""
            if selected_server in servers:
                selected = servers[selected_server]
                plugin_id = str(selected.get("plugin", ""))
                access_help = (
                    "<p class=notice>Configure a least-privilege DSM account from the LabSteward terminal with "
                    f"<code>stewctl server credentials set {html.escape(selected_server)}</code>. "
                    "Add <code>--ca-file /path/to/dsm-ca.crt</code> when DSM uses a private CA. "
                    "Credential values are never accepted or displayed by this page.</p>"
                    if plugin_id == "synology"
                    else (
                        "<p class=notice>Configure an official Network API key and site ID from the LabSteward terminal with "
                        f"<code>stewctl server credentials set {html.escape(selected_server)}</code>. "
                        "Add <code>--ca-file /path/to/unifi-ca.crt</code> when the console uses a private CA. "
                        "Credential values are never accepted or displayed by this page.</p>"
                        if plugin_id == "unifi"
                        else (
                            "<p class=notice>Configure a privilege-separated, audit-only Proxmox API token and node name from the LabSteward terminal with "
                            f"<code>stewctl server credentials set {html.escape(selected_server)}</code>. "
                            "Add <code>--ca-file /path/to/proxmox-ca.crt</code> for the node's private CA. "
                            "Do not grant this token mutation privileges; credential values are never accepted or displayed by this page.</p>"
                            if plugin_id == "proxmox"
                            else "<p class=notice>This plugin has not released its credential setup yet.</p>"
                        )
                    )
                )
                configuration = (
                    f"<section><h2>Configure {html.escape(selected_server)} access</h2>"
                    f"<p class=muted>{html.escape(plugin_id)} at {html.escape(str(selected.get('endpoint','')))}</p>"
                    f"{access_help}</section>"
                )
            content = (
                "<section><h2>Servers</h2><p class=muted>Register each server once. Removing it automatically removes it from every client.</p>"
                "<table><thead><tr><th>Server</th><th>Plugin</th><th>Endpoint</th><th>Actions</th></tr></thead><tbody>"
                + ("".join(server_rows) or "<tr><td colspan=4>No servers</td></tr>")
                + "</tbody></table><h3>Add server</h3><form class=inline method=post action=/admin/server/add>"
                f"<input type=hidden name=csrf value='{csrf}'><input name=server placeholder='server-name' required>"
                f"<select name=plugin required>{plugin_options or '<option value="">No installed plugins</option>'}</select>"
                "<input name=endpoint type=url placeholder='https://server.example:443' required>"
                f"<button type=submit {'disabled' if not plugin_options else ''}>Add</button></form></section>{configuration}"
            )
        elif page == "plugins":
            plugin_rows = []
            for plugin_id, plugin in sorted(catalog_by_id.items()):
                status = (
                    f"installed {installed[plugin_id].get('version','')}"
                    if plugin_id in installed
                    else str(plugin.get("status", "unavailable"))
                )
                raw_descriptions = plugin.get("permission_descriptions", {})
                descriptions = raw_descriptions if isinstance(raw_descriptions, dict) else {}
                permissions = "".join(
                    f"<span class=pill title='{html.escape(str(descriptions.get(name, 'Plugin-defined capability.')))}'>{html.escape(name)}</span>"
                    for name in permission_names(plugin_id)
                ) or "<span class=muted>None released</span>"
                if plugin_id in installed:
                    action = (
                        "<form class=inline method=post action=/admin/plugin/remove>"
                        f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=plugin value='{html.escape(plugin_id)}'>"
                        "<button class=danger type=submit>Remove</button></form>"
                    )
                elif plugin.get("status") == "available":
                    action = (
                        "<form class=inline method=post action=/admin/plugin/install>"
                        f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=plugin value='{html.escape(plugin_id)}'>"
                        "<button type=submit>Install</button></form>"
                    )
                else:
                    action = "<span class=muted>Not available</span>"
                plugin_rows.append(
                    f"<tr><td>{html.escape(str(plugin.get('name', plugin_id)))}</td><td>{html.escape(status)}</td><td>{permissions}</td><td>{action}</td></tr>"
                )
            content = (
                "<section><h2>Plugins</h2><p class=muted>Plugins define available capabilities and their descriptions.</p>"
                "<table><thead><tr><th>Plugin</th><th>Status</th><th>Permissions</th><th>Actions</th></tr></thead><tbody>"
                + ("".join(plugin_rows) or "<tr><td colspan=4>No catalogue entries</td></tr>")
                + "</tbody></table></section>"
            )
        else:
            raise AdminError("Unknown administration page")
        self.send_html(200, f"LABSteward {page.title()}", navigation + notice_html + content)

    def admin_operation(self, path: str) -> None:
        form = self.read_form()
        self.require_session(form.get("csrf"))
        def comma_values(name: str) -> list[str]:
            raw = form.get(name, "")
            values = [item.strip() for item in raw.split(",") if item.strip()]
            if len(values) > 64:
                raise AdminError("Too many values")
            return values
        def selected_permissions() -> dict[str, str]:
            prefix = "permission."
            values = {
                key[len(prefix):]: value
                for key, value in form.items()
                if key.startswith(prefix) and value in {"read", "write"}
            }
            if len(values) > 64:
                raise AdminError("Too many permissions")
            return values
        if path == "/admin/client/revoke":
            broker_call("client.revoke", {"client": form.get("client", "")})
            self.dashboard("Client revoked, removed, and all active OAuth access tokens removed.")
        elif path == "/admin/client/sources":
            broker_call(
                "client.sources",
                {"client": form.get("client", ""), "sources": comma_values("sources")},
            )
            self.dashboard("Client source restrictions updated; active access tokens were revoked.")
        elif path == "/admin/client/server/add":
            broker_call(
                "client.server.add",
                {"client": form.get("client", ""), "server": form.get("server", "")},
            )
            self.dashboard("Server added to client with all permissions off.")
        elif path == "/admin/client/server/remove":
            broker_call(
                "client.server.remove",
                {"client": form.get("client", ""), "server": form.get("server", "")},
            )
            self.dashboard("Server removed from client.")
        elif path == "/admin/client/grants":
            broker_call(
                "client.grants",
                {
                    "client": form.get("client", ""),
                    "server": form.get("server", ""),
                    "permissions": selected_permissions(),
                },
            )
            self.dashboard("Client permissions updated.")
        elif path == "/admin/server/add":
            broker_call(
                "server.add",
                {
                    "server": form.get("server", ""),
                    "plugin": form.get("plugin", ""),
                    "endpoint": form.get("endpoint", ""),
                },
            )
            self.dashboard("Server registered.", page="servers")
        elif path == "/admin/server/remove":
            broker_call("server.remove", {"server": form.get("server", "")})
            self.dashboard(
                "Server removed from every client. Protected credentials were not deleted.",
                page="servers",
            )
        elif path == "/admin/plugin/install":
            broker_call("plugin.install", {"plugin": form.get("plugin", "")})
            self.dashboard("Plugin installed and enabled from the verified release package.", page="plugins")
        elif path == "/admin/plugin/remove":
            broker_call("plugin.remove", {"plugin": form.get("plugin", "")})
            self.dashboard("Plugin disabled; its immutable release code was retained.", page="plugins")
        else:
            raise AdminError("Unsupported administration operation")

    def oauth_register(self) -> None:
        payload = self.read_json_body()
        redirect_values = payload.get("redirect_uris")
        if not isinstance(redirect_values, list) or not 1 <= len(redirect_values) <= 8:
            raise AdminError("One to eight redirect URIs are required")
        redirects = [require_loopback_redirect(item) for item in redirect_values]
        methods = payload.get("token_endpoint_auth_method", "none")
        if methods != "none":
            raise AdminError("Only public OAuth clients are supported")
        name = payload.get("client_name", "MCP client")
        if not isinstance(name, str) or not name.strip() or len(name) > 80:
            raise AdminError("Invalid client name")
        client_id = f"lsd_{secrets.token_urlsafe(24)}"
        def register(state: dict[str, Any]) -> None:
            state["registrations"][client_id] = {
                "name": name.strip(),
                "redirect_uris": redirects,
                "created_at": int(time.time()),
            }
        self.server.update_state(register)  # type: ignore[attr-defined]
        self.send_json(
            201,
            {
                "client_id": client_id,
                "client_name": name.strip(),
                "redirect_uris": redirects,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )

    def validated_authorize(self, query: dict[str, list[str]]) -> dict[str, str]:
        required = (
            "response_type",
            "client_id",
            "redirect_uri",
            "code_challenge",
            "code_challenge_method",
            "state",
            "scope",
            "resource",
        )
        values = {}
        for key in required:
            items = query.get(key, [])
            if len(items) != 1 or not items[0] or len(items[0]) > 2048:
                raise AdminError(f"Invalid OAuth {key}")
            values[key] = items[0]
        if values["response_type"] != "code" or values["code_challenge_method"] != "S256":
            raise AdminError("Only authorization code with PKCE S256 is supported")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", values["code_challenge"]):
            raise AdminError("Invalid PKCE challenge")
        if values["scope"] != "mcp:connect" or values["resource"] != self.server.resource:  # type: ignore[attr-defined]
            raise AdminError("Invalid OAuth scope or resource")
        state = self.server.load_state()  # type: ignore[attr-defined]
        registration = state["registrations"].get(values["client_id"])
        if not isinstance(registration, dict) or values["redirect_uri"] not in registration.get("redirect_uris", []):
            raise AdminError("Unknown OAuth client or redirect URI")
        values["client_name"] = str(registration.get("name", "MCP client"))
        return values

    def authorize_page(self) -> None:
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True, max_num_fields=32)
        existing = query.get("transaction", [])
        state = self.server.load_state()  # type: ignore[attr-defined]
        if len(existing) == 1:
            transaction_id = existing[0]
            transaction = state["transactions"].get(token_digest(transaction_id))
            if not isinstance(transaction, dict) or transaction.get("source") != self.source:
                raise AdminError("Enrollment request expired")
        else:
            values = self.validated_authorize(query)
            transaction_id = secrets.token_urlsafe(32)
            transaction = {**values, "source": self.source, "expires_at": int(time.time()) + TRANSACTION_SECONDS}
            def save_transaction(current: dict[str, Any]) -> None:
                current["transactions"][token_digest(transaction_id)] = transaction
            self.server.update_state(save_transaction)  # type: ignore[attr-defined]
        session = self.session()
        if session is None:
            self.login_page(transaction=transaction_id)
            return
        csrf = html.escape(str(session[1]["csrf"]))
        suggested = re.sub(r"[^a-z0-9-]+", "-", str(transaction["client_name"]).lower()).strip("-")
        if not IDENTIFIER.fullmatch(suggested):
            suggested = "mcp-client"
        source = ipaddress.ip_address(self.source)
        source_cidr = f"{source}/{32 if source.version == 4 else 128}"
        self.send_html(
            200,
            "Trust client",
            "<section class=login><h1>Trust this MCP client?</h1>"
            f"<p><strong>{html.escape(str(transaction['client_name']))}</strong> is requesting access to LABSteward.</p>"
            "<p class=notice>Approval grants only the sanitized built-in health check. It does not grant access to any server or plugin.</p>"
            f"<p>Observed source: <code>{html.escape(self.source)}</code><br>Callback: <code>{html.escape(str(transaction['redirect_uri']))}</code></p>"
            "<form method=post action=/authorize>"
            f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=transaction value='{html.escape(transaction_id)}'>"
            f"<label for=client>Client name</label><input id=client name=client value='{html.escape(suggested)}' required pattern='[a-z][a-z0-9-]{{0,31}}'>"
            f"<label for=source>Allowed source</label><input id=source name=source value='{html.escape(source_cidr)}' required>"
            "<p><button type=submit name=decision value=approve>Trust client</button> "
            "<button class=danger type=submit name=decision value=deny>Deny</button></p></form></section>",
        )

    def authorize_decision(self) -> None:
        if not self.origin_allowed():
            raise AdminError("Invalid browser origin")
        form = self.read_form()
        self.require_session(form.get("csrf"))
        transaction_id = form.get("transaction", "")
        decision = form.get("decision")
        client_id = form.get("client", "")
        source = form.get("source", "")
        def decide(state: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
            transaction = state["transactions"].pop(token_digest(transaction_id), None)
            if not isinstance(transaction, dict) or transaction.get("source") != self.source:
                raise AdminError("Enrollment request expired")
            if decision != "approve":
                return transaction, None
            if not IDENTIFIER.fullmatch(client_id):
                raise AdminError("Invalid client name")
            approved = broker_call(
                "client.approve",
                {
                    "client": client_id,
                    "display_name": transaction["client_name"],
                    "source": source,
                    "oauth_client_id": transaction["client_id"],
                },
            )
            code_value = f"lsc_{secrets.token_urlsafe(32)}"
            state["codes"][token_digest(code_value)] = {
                "client_id": transaction["client_id"],
                "device_id": client_id,
                "redirect_uri": transaction["redirect_uri"],
                "challenge": transaction["code_challenge"],
                "scope": "mcp:connect",
                "resource": self.server.resource,  # type: ignore[attr-defined]
                "auth_generation": approved["auth_generation"],
                "expires_at": int(time.time()) + AUTH_CODE_SECONDS,
            }
            return transaction, code_value
        transaction, code = self.server.update_state(decide)  # type: ignore[attr-defined]
        redirect_uri = str(transaction["redirect_uri"])
        response_state = str(transaction["state"])
        if code is None:
            self.redirect(redirect_with_query(redirect_uri, {"error": "access_denied", "state": response_state}))
            return
        self.redirect(redirect_with_query(redirect_uri, {"code": code, "state": response_state}))

    def oauth_form(self) -> dict[str, str]:
        return self.read_form()

    def issue_tokens(
        self, state: dict[str, Any], client_id: str, device_id: str, auth_generation: int
    ) -> dict[str, Any]:
        access = f"lsa_{secrets.token_urlsafe(32)}"
        refresh = f"lsr_{secrets.token_urlsafe(32)}"
        now = int(time.time())
        broker_call(
            "token.put",
            {
                "digest": token_digest(access), "client": device_id,
                "expires_at": now + ACCESS_TOKEN_SECONDS,
                "auth_generation": auth_generation,
            },
        )
        state["refresh_tokens"][token_digest(refresh)] = {
            "client_id": client_id,
            "device_id": device_id,
            "auth_generation": auth_generation,
            "expires_at": now + REFRESH_TOKEN_SECONDS,
        }
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_SECONDS,
            "refresh_token": refresh,
            "scope": "mcp:connect",
        }

    def oauth_token(self) -> None:
        form = self.oauth_form()
        grant_type = form.get("grant_type")
        client_id = form.get("client_id", "")
        def exchange(state: dict[str, Any]) -> dict[str, Any]:
            if client_id not in state["registrations"]:
                raise AdminError("Unknown OAuth client")
            if grant_type == "authorization_code":
                code = form.get("code", "")
                record = state["codes"].pop(token_digest(code), None) if TOKEN_VALUE.fullmatch(code) else None
                if not isinstance(record, dict):
                    raise AdminError("Invalid or expired authorization code")
                if record.get("client_id") != client_id or record.get("redirect_uri") != form.get("redirect_uri"):
                    raise AdminError("Authorization code binding mismatch")
                verifier = form.get("code_verifier", "")
                if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier) or not hmac.compare_digest(
                    b64url_sha256(verifier), str(record.get("challenge", ""))
                ):
                    raise AdminError("PKCE verification failed")
                if not isinstance(record.get("auth_generation"), int):
                    raise AdminError("Authorization code metadata is invalid")
                return self.issue_tokens(
                    state, client_id, str(record["device_id"]), record["auth_generation"]
                )
            if grant_type == "refresh_token":
                refresh = form.get("refresh_token", "")
                record = (
                    state["refresh_tokens"].pop(token_digest(refresh), None)
                    if TOKEN_VALUE.fullmatch(refresh)
                    else None
                )
                if not isinstance(record, dict) or record.get("client_id") != client_id:
                    raise AdminError("Invalid or expired refresh token")
                if not isinstance(record.get("auth_generation"), int):
                    raise AdminError("Refresh token metadata is invalid")
                return self.issue_tokens(
                    state, client_id, str(record["device_id"]), record["auth_generation"]
                )
            raise AdminError("Unsupported OAuth grant type")
        payload = self.server.update_state(exchange)  # type: ignore[attr-defined]
        self.send_json(200, payload)

    def oauth_revoke(self) -> None:
        form = self.oauth_form()
        value = form.get("token", "")
        if not TOKEN_VALUE.fullmatch(value):
            self.send_bytes(200, b"", "application/json")
            return
        digest = token_digest(value)
        def revoke(state: dict[str, Any]) -> None:
            state["refresh_tokens"].pop(digest, None)
        self.server.update_state(revoke)  # type: ignore[attr-defined]
        broker_call("token.revoke", {"digest": digest})
        self.send_bytes(200, b"", "application/json")


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    if config.get("schema") != 1:
        raise AdminError("Unsupported admin configuration")
    bind = str(ipaddress.ip_address(config.get("bind")))
    port = config.get("port")
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise AdminError("Invalid admin port")
    allowed_hosts = config.get("allowed_hosts")
    if not isinstance(allowed_hosts, list) or not allowed_hosts or len(allowed_hosts) > 16:
        raise AdminError("Invalid admin Host allowlist")
    normalized_hosts = []
    for host in allowed_hosts:
        if not isinstance(host, str) or not host or len(host) > 253:
            raise AdminError("Invalid admin Host allowlist")
        normalized_hosts.append(host.lower().rstrip("."))
    for name in ("admin_sources", "enrollment_sources"):
        networks = config.get(name)
        if not isinstance(networks, list) or not networks or len(networks) > 16:
            raise AdminError(f"Invalid {name}")
        for network in networks:
            parsed = ipaddress.ip_network(network, strict=False)
            if parsed.prefixlen == 0 or parsed.is_multicast or parsed.is_unspecified:
                raise AdminError(f"Invalid {name}")
    issuer = config.get("issuer")
    resource = config.get("resource")
    for label, value in (("issuer", issuer), ("resource", resource)):
        parsed = urlsplit(value if isinstance(value, str) else "")
        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise AdminError(f"Invalid OAuth {label}") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise AdminError(f"Invalid OAuth {label}")
    if urlsplit(str(issuer)).path not in ("", "/") or urlsplit(str(issuer)).query:
        raise AdminError("OAuth issuer must be an HTTPS origin")
    if urlsplit(str(resource)).path != "/mcp" or urlsplit(str(resource)).query:
        raise AdminError("OAuth resource must be the canonical MCP URL")
    cert_file = Path(str(config.get("cert_file", "")))
    key_file = Path(str(config.get("key_file", "")))
    if not cert_file.is_absolute() or not key_file.is_absolute():
        raise AdminError("Admin TLS paths must be absolute")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    return {
        **config,
        "bind": bind,
        "port": port,
        "allowed_hosts": normalized_hosts,
        "issuer": str(issuer).rstrip("/"),
        "resource": str(resource),
        "cert_file": str(cert_file),
        "key_file": str(key_file),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the LabSteward OAuth and admin interface")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    try:
        config = validate_config(read_object(args.config))
        read_admin_credential()
        if args.check_config:
            print(f"valid LabSteward admin configuration for {config['issuer']}")
            return 0
        server = AdminServer((config["bind"], config["port"]), AdminHandler)
        server.allowed_hosts = config["allowed_hosts"]
        server.admin_sources = config["admin_sources"]
        server.enrollment_sources = config["enrollment_sources"]
        server.issuer = config["issuer"]
        server.resource = config["resource"]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        context.load_cert_chain(config["cert_file"], config["key_file"])
        server.ssl_context = context
        server.serve_forever(poll_interval=0.5)
    except (AdminError, OSError, ValueError, ssl.SSLError) as exc:
        print(json.dumps({"event": "admin_service_failed", "reason": type(exc).__name__}), flush=True)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        if "server" in locals():
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
EOF_LABSTEWARD_ADMIN
chmod 0644 /opt/labsteward/lib/labsteward_admin.py
cat >/opt/labsteward/lib/labsteward_broker.py <<'EOF_LABSTEWARD_BROKER'
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
PLUGINS_DIR = Path(os.environ.get("LABSTEWARD_PLUGINS_DIR", "/opt/labsteward/plugins"))
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


def verified_plugin(plugin_id: str) -> dict[str, Any]:
    plugin = next(
        (
            item for item in load_catalog()["plugins"]
            if isinstance(item, dict) and item.get("id") == plugin_id
        ),
        None,
    )
    if not isinstance(plugin, dict) or plugin.get("status") != "available":
        raise BrokerError("Plugin is not available in the approved release catalog")
    manifest = read_object(PLUGINS_DIR / plugin_id / "manifest.json")
    entrypoint = PLUGINS_DIR / plugin_id / "plugin.py"
    if (
        manifest.get("schema") != 1
        or manifest.get("id") != plugin_id
        or manifest.get("version") != plugin.get("version")
        or manifest.get("entrypoint") != "plugin.py"
        or manifest.get("core_api") != 1
    ):
        raise BrokerError("Plugin package metadata does not match the approved release")
    manifest_permissions = manifest.get("permissions")
    actions = manifest.get("actions")
    catalog_permissions = plugin.get("permissions", {})
    descriptions = plugin.get("permission_descriptions", {})
    if (
        not isinstance(manifest_permissions, dict)
        or not isinstance(actions, dict)
        or not isinstance(catalog_permissions, dict)
        or not isinstance(descriptions, dict)
        or set(manifest_permissions) != set(catalog_permissions)
    ):
        raise BrokerError("Plugin package contract does not match the approved release")
    for permission, record in manifest_permissions.items():
        if (
            not isinstance(record, dict)
            or record.get("level") != catalog_permissions.get(permission)
            or record.get("description") != descriptions.get(permission)
        ):
            raise BrokerError("Plugin package permissions do not match the approved release")
    for action, record in actions.items():
        permission_record = manifest_permissions.get(record.get("permission")) if isinstance(record, dict) else None
        if (
            not isinstance(action, str)
            or not isinstance(record, dict)
            or not isinstance(permission_record, dict)
            or record.get("level") not in {"read", "write"}
            or permission_record.get("level") not in {"read", "write"}
            or {"read": 1, "write": 2}[record["level"]]
            > {"read": 1, "write": 2}[permission_record["level"]]
            or not isinstance(record.get("tool"), str)
        ):
            raise BrokerError("Plugin package actions are invalid")
    try:
        compile(entrypoint.read_text(encoding="utf-8"), str(entrypoint), "exec")
    except (OSError, SyntaxError) as exc:
        raise BrokerError("Plugin package entrypoint is invalid") from exc
    return plugin


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


def operation_plugin_install(arguments: dict[str, Any]) -> dict[str, Any]:
    plugin_id = require_id(arguments.get("plugin"), "plugin ID", IDENTIFIER)
    plugin = verified_plugin(plugin_id)
    config = load_config()
    if plugin_id in config["plugins"]:
        raise BrokerError("Plugin is already installed")
    config["plugins"][plugin_id] = {
        "enabled": True,
        "version": plugin["version"],
    }
    atomic_write(CONFIG_FILE, config)
    return {"plugin": plugin_id}


def operation_plugin_remove(arguments: dict[str, Any]) -> dict[str, Any]:
    plugin_id = require_id(arguments.get("plugin"), "plugin ID", IDENTIFIER)
    config = load_config()
    if plugin_id not in config["plugins"]:
        raise BrokerError("Plugin is not installed")
    users = sorted(
        alias for alias, server in config["servers"].items()
        if isinstance(server, dict) and server.get("plugin") == plugin_id
    )
    if users:
        raise BrokerError("Remove servers using this plugin before removing it")
    del config["plugins"][plugin_id]
    atomic_write(CONFIG_FILE, config)
    return {"plugin": plugin_id}


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
    "plugin.install": operation_plugin_install,
    "plugin.remove": operation_plugin_remove,
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
EOF_LABSTEWARD_BROKER
chmod 0644 /opt/labsteward/lib/labsteward_broker.py
install -d -m 0755 /opt/labsteward/plugins/synology
cat >/opt/labsteward/plugins/synology/manifest.json <<'EOF_LABSTEWARD_SYNOLOGY_MANIFEST'
{
  "schema": 1,
  "id": "synology",
  "name": "Synology DSM",
  "version": "0.1.0",
  "core_api": 1,
  "entrypoint": "plugin.py",
  "permissions": {
    "system.read": {
      "level": "read",
      "description": "Read DSM system health and bounded resource utilization."
    },
    "storage.read": {
      "level": "read",
      "description": "Read storage pool, volume, capacity, and aggregate disk health."
    }
  },
  "actions": {
    "synology.system.summary": {
      "tool": "synology_system_summary",
      "permission": "system.read",
      "level": "read"
    },
    "synology.storage.summary": {
      "tool": "synology_storage_summary",
      "permission": "storage.read",
      "level": "read"
    }
  }
}
EOF_LABSTEWARD_SYNOLOGY_MANIFEST
cat >/opt/labsteward/plugins/synology/plugin.py <<'EOF_LABSTEWARD_SYNOLOGY_PLUGIN'
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
EOF_LABSTEWARD_SYNOLOGY_PLUGIN
chmod 0644 /opt/labsteward/plugins/synology/manifest.json /opt/labsteward/plugins/synology/plugin.py
install -d -m 0755 /opt/labsteward/plugins/unifi
cat >/opt/labsteward/plugins/unifi/manifest.json <<'EOF_LABSTEWARD_UNIFI_MANIFEST'
{
  "schema": 1,
  "id": "unifi",
  "name": "UniFi Network",
  "version": "0.1.0",
  "core_api": 1,
  "entrypoint": "plugin.py",
  "permissions": {
    "config.read": {
      "level": "read",
      "description": "Read bounded network and WiFi configuration summaries without credentials or WiFi keys."
    },
    "diagnostics.read": {
      "level": "read",
      "description": "Read device state and resource health with bounded diagnostic findings."
    },
    "clients.read": {
      "level": "read",
      "description": "Read current connection and access context for a specific connected client."
    },
    "firewall.rules": {
      "level": "write",
      "description": "Read firewall policy summaries; at Write level, change only one policy's syslog logging state."
    }
  },
  "actions": {
    "unifi.configuration.summary": {
      "tool": "unifi_configuration_summary",
      "permission": "config.read",
      "level": "read"
    },
    "unifi.diagnostics.summary": {
      "tool": "unifi_diagnostics_summary",
      "permission": "diagnostics.read",
      "level": "read"
    },
    "unifi.client.summary": {
      "tool": "unifi_client_summary",
      "permission": "clients.read",
      "level": "read"
    },
    "unifi.clients.list": {
      "tool": "unifi_clients_list",
      "permission": "clients.read",
      "level": "read"
    },
    "unifi.firewall.rules": {
      "tool": "unifi_firewall_rules",
      "permission": "firewall.rules",
      "level": "read"
    },
    "unifi.firewall.logging.set": {
      "tool": "unifi_firewall_logging_set",
      "permission": "firewall.rules",
      "level": "write"
    }
  }
}
EOF_LABSTEWARD_UNIFI_MANIFEST
cat >/opt/labsteward/plugins/unifi/plugin.py <<'EOF_LABSTEWARD_UNIFI_PLUGIN'
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
EOF_LABSTEWARD_UNIFI_PLUGIN
chmod 0644 /opt/labsteward/plugins/unifi/manifest.json /opt/labsteward/plugins/unifi/plugin.py
install -d -m 0755 /opt/labsteward/plugins/proxmox
cat >/opt/labsteward/plugins/proxmox/manifest.json <<'EOF_LABSTEWARD_PROXMOX_MANIFEST'
{
  "schema": 1,
  "id": "proxmox",
  "name": "Proxmox VE",
  "version": "0.1.0",
  "core_api": 1,
  "entrypoint": "plugin.py",
  "permissions": {
    "node.read": {
      "level": "read",
      "description": "Read bounded Proxmox node health, version, and resource utilization."
    },
    "guests.read": {
      "level": "read",
      "description": "List and inspect sanitized LXC and virtual-machine state and configuration."
    },
    "diagnostics.read": {
      "level": "read",
      "description": "Diagnose node, storage, task, LXC, and virtual-machine health from bounded API data."
    },
    "storage.read": {
      "level": "read",
      "description": "Read bounded Proxmox storage status and capacity without paths or credentials."
    },
    "tasks.read": {
      "level": "read",
      "description": "Read recent task outcomes without worker identities or raw logs."
    }
  },
  "actions": {
    "proxmox.node.summary": {"tool": "proxmox_node_summary", "permission": "node.read", "level": "read"},
    "proxmox.guests.list": {"tool": "proxmox_guests_list", "permission": "guests.read", "level": "read"},
    "proxmox.guest.summary": {"tool": "proxmox_guest_summary", "permission": "guests.read", "level": "read"},
    "proxmox.node.diagnostics": {"tool": "proxmox_node_diagnostics", "permission": "diagnostics.read", "level": "read"},
    "proxmox.guest.diagnostics": {"tool": "proxmox_guest_diagnostics", "permission": "diagnostics.read", "level": "read"},
    "proxmox.storage.summary": {"tool": "proxmox_storage_summary", "permission": "storage.read", "level": "read"},
    "proxmox.tasks.recent": {"tool": "proxmox_tasks_recent", "permission": "tasks.read", "level": "read"}
  }
}
EOF_LABSTEWARD_PROXMOX_MANIFEST
cat >/opt/labsteward/plugins/proxmox/plugin.py <<'EOF_LABSTEWARD_PROXMOX_PLUGIN'
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
EOF_LABSTEWARD_PROXMOX_PLUGIN
chmod 0644 /opt/labsteward/plugins/proxmox/manifest.json /opt/labsteward/plugins/proxmox/plugin.py
cat >/opt/labsteward/catalog/plugins.json <<'EOF_LABSTEWARD_CATALOG'
{
  "schema": 1,
  "plugins": [
    {
      "id": "proxmox",
      "name": "Proxmox VE",
      "status": "available",
      "version": "0.1.0",
      "description": "Audit-only Proxmox node, LXC, virtual-machine, storage, task, and diagnostic access.",
      "permissions": {
        "diagnostics.read": "read",
        "guests.read": "read",
        "node.read": "read",
        "storage.read": "read",
        "tasks.read": "read"
      },
      "permission_descriptions": {
        "diagnostics.read": "Diagnose node, storage, task, LXC, and virtual-machine health from bounded API data.",
        "guests.read": "List and inspect sanitized LXC and virtual-machine state and configuration.",
        "node.read": "Read bounded Proxmox node health, version, and resource utilization.",
        "storage.read": "Read bounded Proxmox storage status and capacity without paths or credentials.",
        "tasks.read": "Read recent task outcomes without worker identities or raw logs."
      }
    },
    {
      "id": "synology",
      "name": "Synology DSM",
      "status": "available",
      "version": "0.1.0",
      "description": "Read-only DSM system resources, storage capacity, and health summaries.",
      "permissions": {
        "storage.read": "read",
        "system.read": "read"
      },
      "permission_descriptions": {
        "storage.read": "Read storage pool, volume, capacity, and aggregate disk health.",
        "system.read": "Read DSM system health and bounded resource utilization."
      }
    },
    {
      "id": "unifi",
      "name": "UniFi Network",
      "status": "available",
      "version": "0.1.0",
      "description": "Official local API access for configuration, diagnostics, connected clients, and firewall policy logging.",
      "permissions": {
        "clients.read": "read",
        "config.read": "read",
        "diagnostics.read": "read",
        "firewall.rules": "write"
      },
      "permission_descriptions": {
        "clients.read": "Read current connection and access context for a specific connected client.",
        "config.read": "Read bounded network and WiFi configuration summaries without credentials or WiFi keys.",
        "diagnostics.read": "Read device state and resource health with bounded diagnostic findings.",
        "firewall.rules": "Read firewall policy summaries; at Write level, change only one policy's syslog logging state."
      }
    }
  ]
}
EOF_LABSTEWARD_CATALOG
cat >/opt/labsteward/schemas/config.schema.json <<'EOF_LABSTEWARD_SCHEMA'
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/donselkirk/LabSteward/schemas/config.schema.json",
  "title": "LabSteward appliance configuration",
  "$defs": {
    "permissionLevels": {
      "oneOf": [
        {
          "type": "object",
          "propertyNames": { "pattern": "^[a-z][a-z0-9.-]{0,63}$" },
          "additionalProperties": { "enum": ["read", "write"] },
          "maxProperties": 64
        },
        {
          "description": "Legacy read-only permission list accepted during upgrades",
          "type": "array",
          "uniqueItems": true,
          "items": { "type": "string", "pattern": "^[a-z][a-z0-9.-]{0,63}$" },
          "maxItems": 64
        }
      ]
    }
  },
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
        "required": ["plugin", "endpoint"],
        "properties": {
          "plugin": { "type": "string", "pattern": "^[a-z][a-z0-9-]{0,31}$" },
          "endpoint": { "type": "string", "maxLength": 2048 },
          "permissions": { "$ref": "#/$defs/permissionLevels" }
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
          "auth": { "enum": ["legacy_token", "oauth"] },
          "display_name": { "type": "string", "minLength": 1, "maxLength": 80 },
          "oauth_client_id": { "type": "string", "minLength": 1, "maxLength": 2048 },
          "auth_generation": { "type": "integer", "minimum": 1 },
          "sources": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": true,
            "items": { "type": "string", "maxLength": 64 }
          },
          "grants": {
            "type": "object",
            "propertyNames": { "pattern": "^[a-z][a-z0-9._-]{0,63}$" },
            "additionalProperties": { "$ref": "#/$defs/permissionLevels" }
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
cat >/etc/systemd/system/labsteward-admin.service <<'EOF_LABSTEWARD_ADMIN_SERVICE'
[Unit]
Description=LabSteward OAuth and administrator interface
Documentation=https://github.com/donselkirk/LabSteward
After=network-online.target labsteward-broker.service
Wants=network-online.target
Requires=labsteward-broker.service
ConditionPathExists=/etc/labsteward-admin/config.json
ConditionPathExists=/etc/labsteward-admin/admin.json

[Service]
Type=simple
User=labsteward-admin
Group=labsteward-admin
ExecStart=/usr/bin/python3 /opt/labsteward/lib/labsteward_admin.py --config /etc/labsteward-admin/config.json
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
ReadWritePaths=/var/lib/labsteward-admin
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
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
UMask=0077

[Install]
WantedBy=multi-user.target
EOF_LABSTEWARD_ADMIN_SERVICE
chmod 0644 /etc/systemd/system/labsteward-admin.service
cat >/etc/systemd/system/labsteward-broker.service <<'EOF_LABSTEWARD_BROKER_SERVICE'
[Unit]
Description=LabSteward fixed-operation administration broker
Documentation=https://github.com/donselkirk/LabSteward
After=local-fs.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 /opt/labsteward/lib/labsteward_broker.py --socket /run/labsteward/admin-broker.sock
Restart=on-failure
RestartSec=5s
RuntimeDirectory=labsteward
RuntimeDirectoryMode=0755
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
ReadWritePaths=/etc/labsteward /run/labsteward
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER
AmbientCapabilities=
LimitNOFILE=128
MemoryMax=96M
TasksMax=32
UMask=0027

[Install]
WantedBy=multi-user.target
EOF_LABSTEWARD_BROKER_SERVICE
chmod 0644 /etc/systemd/system/labsteward-broker.service

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
