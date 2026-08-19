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
$STD apt-get install -y ca-certificates curl jq python3
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
import ipaddress
import json
import os
import re
import secrets
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
CLIENT_SECRETS_DIR = Path(
    os.environ.get("LABSTEWARD_CLIENT_SECRETS_DIR", "/etc/labsteward/secrets/clients")
)
ALLOW_NON_ROOT = os.environ.get("LABSTEWARD_ALLOW_NON_ROOT") == "1"

IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
ALIAS = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
PERMISSION = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")


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
    print("  1. stewctl plugin install PLUGIN")
    print("  2. stewctl server add ALIAS --plugin PLUGIN --endpoint HTTPS_ORIGIN")
    print("  3. Use the plugin credential command inside this LXC")
    print("  4. stewctl permission set ALIAS PERMISSION ...")
    print("  5. stewctl client add CLIENT --source IP_OR_CIDR")
    print("  6. stewctl status")


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
    try:
        source = SANITIZER_FILE.read_text(encoding="utf-8")
        compile(source, str(SANITIZER_FILE), "exec")
    except (OSError, SyntaxError) as exc:
        errors.append(f"output sanitizer is missing or invalid: {exc}")
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
    print("  Remote transport: not configured")


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

if [[ -n "${LABSTEWARD_VERSION_URL:-}" ]]; then
  curl -fsSL --retry 3 --retry-all-errors "$LABSTEWARD_VERSION_URL" -o /opt/labsteward/VERSION
else
  printf 'development\n' >/opt/labsteward/VERSION
fi
printf '%s\n' "${LABSTEWARD_UPDATE_BASE_URL:-https://github.com/donselkirk/LabSteward/releases/latest/download}" >/opt/labsteward/update.url
chown -R root:root /opt/labsteward
find /opt/labsteward -type d -exec chmod 0755 {} +
find /opt/labsteward -type f -exec chmod go-w {} +
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
