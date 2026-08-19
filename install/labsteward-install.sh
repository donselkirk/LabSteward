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
install -d -o root -g labsteward -m 0750 /etc/labsteward /etc/labsteward/secrets
install -d -o labsteward -g labsteward -m 0700 /var/lib/labsteward

cat >/etc/labsteward/config.json <<'EOF_CONFIG'
{
  "schema": 1,
  "plugins": {},
  "servers": {}
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
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(os.environ.get("LABSTEWARD_BASE_DIR", "/opt/labsteward"))
CONFIG_FILE = Path(os.environ.get("LABSTEWARD_CONFIG_FILE", "/etc/labsteward/config.json"))
CATALOG_FILE = Path(os.environ.get("LABSTEWARD_CATALOG_FILE", str(BASE_DIR / "catalog/plugins.json")))
VERSION_FILE = Path(os.environ.get("LABSTEWARD_VERSION_FILE", str(BASE_DIR / "VERSION")))
SELF_UPDATE = Path(os.environ.get("LABSTEWARD_SELF_UPDATE", str(BASE_DIR / "lib/self-update.sh")))
SANITIZER_FILE = Path(
    os.environ.get("LABSTEWARD_SANITIZER_FILE", str(BASE_DIR / "lib/labsteward_sanitize.py"))
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
    if not isinstance(config.get("plugins"), dict) or not isinstance(config.get("servers"), dict):
        raise UserError("Configuration must contain plugin and server registries")
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
    print("  5. stewctl validate")


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
    server["permissions"] = permissions
    save_config(config)
    print(f"Set {len(permissions)} permission(s) for {alias}.")


def command_validate(_: argparse.Namespace) -> None:
    config = load_config()
    catalog = catalog_plugins()
    errors = []
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
        try:
            require_identifier(alias, "server alias", ALIAS)
            require_endpoint(server.get("endpoint", ""))
        except (UserError, AttributeError) as exc:
            errors.append(str(exc))
            continue
        plugin_id = server.get("plugin")
        if plugin_id not in config["plugins"]:
            errors.append(f"server {alias} uses an uninstalled plugin: {plugin_id}")
            continue
        allowed = set(catalog.get(plugin_id, {}).get("permissions", []))
        unknown = set(server.get("permissions", [])) - allowed
        if unknown:
            errors.append(f"server {alias} has undeclared permissions: {', '.join(sorted(unknown))}")
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        raise UserError(f"Validation failed with {len(errors)} error(s)")
    print("PASS: LabSteward registry is internally consistent")


def command_self_update(_: argparse.Namespace) -> None:
    if not SELF_UPDATE.is_file():
        raise UserError(f"Self-update helper is missing: {SELF_UPDATE}")
    os.execv(str(SELF_UPDATE), [str(SELF_UPDATE)])


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="stewctl", description="Manage the LabSteward appliance")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("version").set_defaults(handler=command_version)
    commands.add_parser("configure").set_defaults(handler=command_configure)
    commands.add_parser("validate").set_defaults(handler=command_validate)
    commands.add_parser("self-update").set_defaults(handler=command_self_update)

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
readonly VERSION_FILE="${LABSTEWARD_VERSION_FILE:-${BASE_DIR}/VERSION}"
readonly UPDATE_URL_FILE="${BASE_DIR}/update.url"
readonly DEFAULT_UPDATE_URL="https://github.com/donselkirk/LabSteward/releases/latest/download"

[[ $EUID -eq 0 || "${LABSTEWARD_ALLOW_NON_ROOT:-0}" == "1" ]] || {
  echo "Run stewctl self-update as root." >&2
  exit 1
}

update_url="${LABSTEWARD_UPDATE_BASE_URL:-}"
if [[ -z "$update_url" && -r "$UPDATE_URL_FILE" ]]; then
  update_url="$(<"$UPDATE_URL_FILE")"
fi
update_url="${update_url:-$DEFAULT_UPDATE_URL}"
update_url="${update_url%/}"

stage="$(mktemp -d)"
backup="$(mktemp -d "${BASE_DIR}/.rollback.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

curl -fsSL --retry 3 --retry-all-errors "${update_url}/VERSION" -o "${stage}/VERSION"
grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' "${stage}/VERSION" || {
  echo "Release version metadata is invalid." >&2
  exit 1
}
release_version="$(<"${stage}/VERSION")"
asset_url="$update_url"
if [[ "$update_url" == "$DEFAULT_UPDATE_URL" ]]; then
  asset_url="https://github.com/donselkirk/LabSteward/releases/download/${release_version}"
fi

for asset in SHA256SUMS stewctl self-update.sh labsteward-sanitize.py plugins.json config.schema.json; do
  curl -fsSL --retry 3 --retry-all-errors "${asset_url}/${asset}" -o "${stage}/${asset}"
done
(
  cd "$stage"
  for asset in VERSION stewctl self-update.sh labsteward-sanitize.py plugins.json config.schema.json; do
    grep -q " ${asset}$" SHA256SUMS || exit 1
  done
  sha256sum -c --ignore-missing SHA256SUMS >/dev/null
) || {
  echo "LabSteward release assets failed checksum validation." >&2
  exit 1
}

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

rollback() {
  trap - ERR
  echo "Update validation failed; restoring the previous LabSteward core." >&2
  [[ ! -e "${backup}/manager" ]] || cp -a "${backup}/manager" "$MANAGER_PATH"
  [[ ! -e "${backup}/self-update.sh" ]] || cp -a "${backup}/self-update.sh" "${BASE_DIR}/lib/self-update.sh"
  [[ ! -e "${backup}/labsteward_sanitize.py" ]] || cp -a "${backup}/labsteward_sanitize.py" "$SANITIZER_PATH"
  [[ ! -e "${backup}/plugins.json" ]] || cp -a "${backup}/plugins.json" "${BASE_DIR}/catalog/plugins.json"
  [[ ! -e "${backup}/config.schema.json" ]] || cp -a "${backup}/config.schema.json" "${BASE_DIR}/schemas/config.schema.json"
  [[ ! -e "${backup}/VERSION" ]] || cp -a "${backup}/VERSION" "$VERSION_FILE"
  [[ ! -e "${backup}/update.url" ]] || cp -a "${backup}/update.url" "$UPDATE_URL_FILE"
  rm -rf "$backup"
}

install -d -m 0755 "$backup" "${BASE_DIR}/lib" "${BASE_DIR}/catalog" "${BASE_DIR}/schemas"
[[ ! -e "$MANAGER_PATH" ]] || cp -a "$MANAGER_PATH" "${backup}/manager"
[[ ! -e "${BASE_DIR}/lib/self-update.sh" ]] || cp -a "${BASE_DIR}/lib/self-update.sh" "${backup}/self-update.sh"
[[ ! -e "$SANITIZER_PATH" ]] || cp -a "$SANITIZER_PATH" "${backup}/labsteward_sanitize.py"
[[ ! -e "${BASE_DIR}/catalog/plugins.json" ]] || cp -a "${BASE_DIR}/catalog/plugins.json" "${backup}/plugins.json"
[[ ! -e "${BASE_DIR}/schemas/config.schema.json" ]] || cp -a "${BASE_DIR}/schemas/config.schema.json" "${backup}/config.schema.json"
[[ ! -e "$VERSION_FILE" ]] || cp -a "$VERSION_FILE" "${backup}/VERSION"
[[ ! -e "$UPDATE_URL_FILE" ]] || cp -a "$UPDATE_URL_FILE" "${backup}/update.url"
trap rollback ERR
install -m 0755 "${stage}/stewctl" "$MANAGER_PATH"
ln -sfn "$MANAGER_PATH" "$MANAGER_ALIAS_PATH"
install -m 0755 "${stage}/self-update.sh" "${BASE_DIR}/lib/self-update.sh"
install -m 0644 "${stage}/labsteward-sanitize.py" "$SANITIZER_PATH"
install -m 0644 "${stage}/plugins.json" "${BASE_DIR}/catalog/plugins.json"
install -m 0644 "${stage}/config.schema.json" "${BASE_DIR}/schemas/config.schema.json"
install -m 0644 "${stage}/VERSION" "$VERSION_FILE"
printf '%s\n' "$update_url" >"$UPDATE_URL_FILE"
chmod 0644 "$UPDATE_URL_FILE"
"$MANAGER_PATH" validate
trap - ERR
rm -rf "$backup"
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
/usr/local/bin/stewctl validate
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
printf ' Validate:  stewctl validate\n\n'
EOF_MOTD
chmod 0755 /etc/profile.d/00-labsteward-details.sh
msg_ok "Configured LabSteward login banner"

motd_ssh
customize
