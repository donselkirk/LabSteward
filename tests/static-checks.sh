#!/usr/bin/env bash
# This test intentionally searches for literal shell expressions in generated inputs.
# shellcheck disable=SC2016
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

bash tools/build-artifacts.sh --check
bash -n labsteward.sh ct/labsteward.sh install/labsteward-install.sh src/self-update.sh \
  tests/mock-systemctl.sh tools/build-artifacts.sh tools/build-release-assets.sh \
  tools/build-updater-bridge.sh tools/fetch-community-helpers.sh

python3 -c 'compile(open("src/labsteward-manager.py", encoding="utf-8").read(), "src/labsteward-manager.py", "exec")'
python3 -c 'compile(open("src/labsteward_sanitize.py", encoding="utf-8").read(), "src/labsteward_sanitize.py", "exec")'
python3 -c 'compile(open("src/labsteward_core.py", encoding="utf-8").read(), "src/labsteward_core.py", "exec")'
python3 -c 'compile(open("src/labsteward_mcp.py", encoding="utf-8").read(), "src/labsteward_mcp.py", "exec")'
python3 -c 'compile(open("src/labsteward_admin.py", encoding="utf-8").read(), "src/labsteward_admin.py", "exec")'
python3 -c 'compile(open("src/labsteward_broker.py", encoding="utf-8").read(), "src/labsteward_broker.py", "exec")'
python3 -c 'compile(open("plugins/synology/plugin.py", encoding="utf-8").read(), "plugins/synology/plugin.py", "exec")'
python3 -c 'compile(open("plugins/unifi/plugin.py", encoding="utf-8").read(), "plugins/unifi/plugin.py", "exec")'
python3 -c 'compile(open("plugins/proxmox/plugin.py", encoding="utf-8").read(), "plugins/proxmox/plugin.py", "exec")'
python3 tests/sanitizer-behavior.py
python3 tests/synology-plugin-behavior.py
python3 tests/unifi-plugin-behavior.py
python3 tests/proxmox-plugin-behavior.py
python3 tests/mcp-behavior.py
python3 tests/oauth-behavior.py
bash tests/updater-bridge-behavior.sh
python3 -m json.tool catalog/plugins.json >/dev/null
python3 -m json.tool plugins/synology/manifest.json >/dev/null
python3 -m json.tool plugins/unifi/manifest.json >/dev/null
python3 -m json.tool plugins/proxmox/manifest.json >/dev/null
python3 -m json.tool schemas/config.schema.json >/dev/null

grep -q 'var_unprivileged="${var_unprivileged:-1}"' ct/labsteward.sh
grep -q 'var_nesting="${var_nesting:-1}"' ct/labsteward.sh
grep -q 'LABSTEWARD_INSTALL_URL' labsteward.sh
grep -q 'sha256sum -c --ignore-missing SHA256SUMS' labsteward.sh
grep -q 'Refusing to downgrade LabSteward' src/self-update.sh
grep -q 'Private GitHub releases are unavailable' src/self-update.sh
grep -q 'optional_runtime_assets=(labsteward-core.py labsteward-mcp.py labsteward-admin.py' src/self-update.sh
grep -q 'update_commands.add_parser("check")' src/labsteward-manager.py
grep -q 'update.set_defaults(handler=command_self_update)' src/labsteward-manager.py
grep -q 'commands.add_parser("logs"' src/labsteward-manager.py
grep -q 'ln -sfn /usr/local/bin/stewctl /usr/local/bin/labsteward' tools/build-artifacts.sh
grep -q 'prog="stewctl"' src/labsteward-manager.py
grep -q 'commands.add_parser("status"' src/labsteward-manager.py
grep -q 'client_commands.add_parser("revoke")' src/labsteward-manager.py
grep -q 'transport_commands.add_parser("enable")' src/labsteward-manager.py
grep -q 'create_transport_tls' src/labsteward-manager.py
grep -q '/usr/local/bin/stewctl status' src/labsteward-install.sh.in
grep -q '"clients": {}' src/labsteward-install.sh.in
grep -q -- '-m 2750 /etc/labsteward/secrets /etc/labsteward/secrets/clients' src/labsteward-install.sh.in
grep -q 'LABSTEWARD_INSTALL_SANITIZER' src/labsteward-install.sh.in
grep -q 'LABSTEWARD_INSTALL_MCP' src/labsteward-install.sh.in
grep -q 'LABSTEWARD_INSTALL_ADMIN' src/labsteward-install.sh.in
grep -q 'LABSTEWARD_INSTALL_BROKER' src/labsteward-install.sh.in
grep -q 'LABSTEWARD_INSTALL_SYNOLOGY_PLUGIN' src/labsteward-install.sh.in
grep -q 'LABSTEWARD_INSTALL_UNIFI_PLUGIN' src/labsteward-install.sh.in
grep -q 'LABSTEWARD_INSTALL_PROXMOX_PLUGIN' src/labsteward-install.sh.in
grep -q -- '--shell /usr/sbin/nologin labsteward' src/labsteward-install.sh.in
grep -q 'Plugin is not in the approved release catalog' src/labsteward-manager.py
grep -q 'Server endpoints must be HTTPS origins without embedded credentials' src/labsteward-manager.py
grep -q 'User=labsteward' src/labsteward.service
grep -q 'User=labsteward-admin' src/labsteward-admin.service
grep -q 'RestrictAddressFamilies=AF_UNIX' src/labsteward-broker.service
grep -q '/var/log/labsteward' src/labsteward-broker.service
grep -q 'LABSTEWARD_INSTALL_LOGGER' src/labsteward-install.sh.in
grep -q 'labsteward-log.py' tools/build-release-assets.sh src/self-update.sh
grep -q 'ProtectSystem=strict' src/labsteward.service
grep -q 'authenticate_client(token or "", source)' src/labsteward_mcp.py
if grep -q 'X-Forwarded-For' src/labsteward_mcp.py src/labsteward_admin.py; then
  echo "The MCP transport must not trust forwarding headers." >&2
  exit 1
fi
if grep -Eq 'os\.system|subprocess\.(run|Popen)|shell=True' src/labsteward_admin.py src/labsteward_broker.py; then
  echo "Network-facing administration code must not execute processes." >&2
  exit 1
fi

temporary_build="$(mktemp)"
trap 'rm -f "$temporary_build"' EXIT
cp vendor/community-scripts/misc/build.func "$temporary_build"
sed -i \
  -e 's|"$COMMUNITY_SCRIPTS_URL/install/${var_install}.sh"|"$LABSTEWARD_INSTALL_URL"|g' \
  -e 's|"https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/install/${var_install}.sh"|"$LABSTEWARD_INSTALL_URL"|g' \
  "$temporary_build"
[[ "$(grep -c 'curl -fsSL "$LABSTEWARD_INSTALL_URL"' "$temporary_build")" -ge 2 ]]
echo "Static checks passed."
