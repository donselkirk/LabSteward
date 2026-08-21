#!/usr/bin/env bash
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/opt/catalog" "$fixture/opt/lib" "$fixture/opt/schemas" \
  "$fixture/opt/plugins/synology" "$fixture/opt/plugins/unifi" "$fixture/opt/plugins/proxmox" "$fixture/etc/secrets/clients" \
  "$fixture/etc/secrets/servers" "$fixture/systemd"
cp "$project_root/catalog/plugins.json" "$fixture/opt/catalog/plugins.json"
cp "$project_root/src/labsteward_sanitize.py" "$fixture/opt/lib/labsteward_sanitize.py"
cp "$project_root/src/labsteward_core.py" "$fixture/opt/lib/labsteward_core.py"
cp "$project_root/src/labsteward_mcp.py" "$fixture/opt/lib/labsteward_mcp.py"
cp "$project_root/src/labsteward_admin.py" "$fixture/opt/lib/labsteward_admin.py"
cp "$project_root/src/labsteward_broker.py" "$fixture/opt/lib/labsteward_broker.py"
cp "$project_root/src/self-update.sh" "$fixture/opt/lib/self-update.sh"
cp "$project_root/plugins/synology/manifest.json" "$fixture/opt/plugins/synology/manifest.json"
cp "$project_root/plugins/synology/plugin.py" "$fixture/opt/plugins/synology/plugin.py"
cp "$project_root/plugins/unifi/manifest.json" "$fixture/opt/plugins/unifi/manifest.json"
cp "$project_root/plugins/unifi/plugin.py" "$fixture/opt/plugins/unifi/plugin.py"
cp "$project_root/plugins/proxmox/manifest.json" "$fixture/opt/plugins/proxmox/manifest.json"
cp "$project_root/plugins/proxmox/plugin.py" "$fixture/opt/plugins/proxmox/plugin.py"
cp "$project_root/src/labsteward.service" "$fixture/systemd/labsteward.service"
cp "$project_root/src/labsteward-admin.service" "$fixture/systemd/labsteward-admin.service"
cp "$project_root/src/labsteward-broker.service" "$fixture/systemd/labsteward-broker.service"
cp "$project_root/schemas/config.schema.json" "$fixture/opt/schemas/config.schema.json"
printf 'v0.1.0\n' >"$fixture/opt/VERSION"
printf '{"schema":1,"plugins":{},"servers":{},"clients":{}}\n' >"$fixture/etc/config.json"

run_manager() {
  LABSTEWARD_ALLOW_NON_ROOT=1 \
  LABSTEWARD_BASE_DIR="$fixture/opt" \
  LABSTEWARD_CONFIG_FILE="$fixture/etc/config.json" \
  LABSTEWARD_CATALOG_FILE="$fixture/opt/catalog/plugins.json" \
  LABSTEWARD_VERSION_FILE="$fixture/opt/VERSION" \
  LABSTEWARD_CLIENT_SECRETS_DIR="$fixture/etc/secrets/clients" \
  LABSTEWARD_SERVER_SECRETS_DIR="$fixture/etc/secrets/servers" \
  LABSTEWARD_PLUGINS_DIR="$fixture/opt/plugins" \
  LABSTEWARD_TRANSPORT_CONFIG="$fixture/etc/transport.json" \
  LABSTEWARD_TLS_DIR="$fixture/etc/secrets/tls" \
  LABSTEWARD_ADMIN_CONFIG="$fixture/etc/admin.json" \
  LABSTEWARD_ADMIN_CREDENTIAL="$fixture/etc/secrets/admin.json" \
  LABSTEWARD_ADMIN_TLS_DIR="$fixture/etc/secrets/admin-tls" \
  LABSTEWARD_OAUTH_TOKEN_FILE="$fixture/etc/secrets/oauth-tokens.json" \
  LABSTEWARD_ADMIN_FILE="$fixture/opt/lib/labsteward_admin.py" \
  LABSTEWARD_BROKER_FILE="$fixture/opt/lib/labsteward_broker.py" \
  LABSTEWARD_ADMIN_SYSTEMD_UNIT="$fixture/systemd/labsteward-admin.service" \
  LABSTEWARD_BROKER_SYSTEMD_UNIT="$fixture/systemd/labsteward-broker.service" \
  LABSTEWARD_ADMIN_GROUP_ID="$(id -g)" \
  LABSTEWARD_SYSTEMD_UNIT="$fixture/systemd/labsteward.service" \
  LABSTEWARD_SYSTEMCTL="$project_root/tests/mock-systemctl.sh" \
  LABSTEWARD_TEST_SYSTEMCTL_STATE="$fixture/systemctl.state" \
  LABSTEWARD_ALLOW_LOOPBACK=1 \
  python3 "$project_root/src/labsteward-manager.py" "$@"
}

[[ "$(run_manager version)" == "LabSteward v0.1.0" ]]
run_manager configure | grep -q '^LabSteward configuration$'
run_manager update --help | grep -q '{check,apply}'
run_manager validate | grep -q '^PASS:'
run_manager status | grep -q '^LabSteward core: healthy$'
run_manager action run core.status | grep -q '"status": "healthy"'
run_manager plugin list | grep -q $'^synology\tavailable\tSynology DSM$'
run_manager plugin install synology | grep -q '^Installed and enabled plugin synology 0.1.0'
run_manager plugin install unifi | grep -q '^Installed and enabled plugin unifi 0.1.0'
run_manager plugin install proxmox | grep -q '^Installed and enabled plugin proxmox 0.1.0'
run_manager server add nas-test --plugin synology --endpoint 'https://nas.example.test:5001' | grep -q '^Added server nas-test'
run_manager server add network-test --plugin unifi --endpoint 'https://unifi.example.test' | grep -q '^Added server network-test'
run_manager server add level-test --plugin proxmox --endpoint 'https://pve.example.test:8006' | grep -q '^Added server level-test'
LABSTEWARD_TEST_SERVER_USERNAME='readonly-user' \
  LABSTEWARD_TEST_SERVER_PASSWORD='test-only-password' \
  run_manager server credentials set nas-test | grep -q '^Stored protected Synology credentials'
[[ "$(stat -c '%a' "$fixture/etc/secrets/servers/nas-test.json")" == "640" ]]
LABSTEWARD_TEST_UNIFI_API_KEY='test-only-api-key-value' \
  LABSTEWARD_TEST_UNIFI_SITE_ID='11111111-1111-4111-8111-111111111111' \
  run_manager server credentials set network-test | grep -q '^Stored protected UniFi credentials'
[[ "$(stat -c '%a' "$fixture/etc/secrets/servers/network-test.json")" == "640" ]]
LABSTEWARD_TEST_PROXMOX_TOKEN_ID='audit@pve!labsteward' \
  LABSTEWARD_TEST_PROXMOX_TOKEN_SECRET='test-only-proxmox-secret' \
  LABSTEWARD_TEST_PROXMOX_NODE='pve-test' \
  run_manager server credentials set level-test | grep -q '^Stored protected Proxmox credentials'
[[ "$(stat -c '%a' "$fixture/etc/secrets/servers/level-test.json")" == "640" ]]
if run_manager plugin remove synology 2>"$fixture/plugin-in-use-error"; then
  echo "An in-use plugin must not be removed." >&2
  exit 1
fi
grep -q 'still used by: nas-test' "$fixture/plugin-in-use-error"
run_manager validate | grep -q '^PASS:'
mv "$fixture/opt/lib/labsteward_sanitize.py" "$fixture/opt/lib/labsteward_sanitize.py.missing"
if run_manager validate 2>"$fixture/sanitizer-error"; then
  echo "Validation must reject a missing output sanitizer." >&2
  exit 1
fi
grep -q 'output sanitizer is missing or invalid' "$fixture/sanitizer-error"
mv "$fixture/opt/lib/labsteward_sanitize.py.missing" "$fixture/opt/lib/labsteward_sanitize.py"
run_manager client add agent1 --source 192.0.2.40 >"$fixture/client-add"
token="$(tail -n 1 "$fixture/client-add")"
[[ "$token" =~ ^lst_[A-Za-z0-9_-]{43}$ ]]
grep -q $'^agent1\tenabled\t192.0.2.40/32\t0 server grant(s)$' < <(run_manager client list)
if grep -qF "$token" "$fixture/etc/config.json" "$fixture/etc/secrets/clients/agent1.json"; then
  echo "A plaintext client token must never be stored." >&2
  exit 1
fi
run_manager validate | grep -q '^PASS:'
run_manager client rotate-token agent1 >"$fixture/client-rotate"
rotated_token="$(tail -n 1 "$fixture/client-rotate")"
[[ "$rotated_token" =~ ^lst_[A-Za-z0-9_-]{43}$ ]]
[[ "$rotated_token" != "$token" ]]
if grep -qF "$rotated_token" "$fixture/etc/config.json" "$fixture/etc/secrets/clients/agent1.json"; then
  echo "A rotated plaintext client token must never be stored." >&2
  exit 1
fi
run_manager client source set agent1 192.0.2.41/32 | grep -q '^Set 1 source restriction'
grep -q $'^agent1\tenabled\t192.0.2.41/32\t0 server grant(s)$' < <(run_manager client list)
if run_manager client permission set agent1 level-test node.read=read 2>"$fixture/assign-error"; then
  echo "Permissions must not be configured before assigning a server." >&2
  exit 1
fi
grep -q 'Add the server to this client' "$fixture/assign-error"
run_manager client server add agent1 level-test | grep -q '^Added server level-test'
if run_manager client server add agent1 level-test 2>"$fixture/duplicate-error"; then
  echo "A server must not be assigned to the same client twice." >&2
  exit 1
fi
grep -q 'already assigned' "$fixture/duplicate-error"
run_manager client permission set agent1 level-test node.read=read guests.read=read diagnostics.read=read storage.read=read tasks.read=read | grep -q '^Set 5 permission(s)'
run_manager client server add agent1 nas-test | grep -q '^Added server nas-test'
run_manager client permission set agent1 nas-test system.read=read storage.read=read | grep -q '^Set 2 permission(s)'
run_manager client server add agent1 network-test | grep -q '^Added server network-test'
run_manager client permission set agent1 network-test config.read=read diagnostics.read=read clients.read=read firewall.rules=write | grep -q '^Set 4 permission(s)'
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["clients"]["agent1"]["grants"]["level-test"] == {"diagnostics.read":"read","guests.read":"read","node.read":"read","storage.read":"read","tasks.read":"read"}' "$fixture/etc/config.json"
if run_manager client permission set agent1 level-test audit.unknown=read 2>"$fixture/permission-error"; then
  echo "An undeclared plugin permission must be rejected." >&2
  exit 1
fi
grep -q 'not declared' "$fixture/permission-error"
if run_manager client permission set agent1 missing node.read 2>"$fixture/grant-error"; then
  echo "A client grant must reference a registered server." >&2
  exit 1
fi
grep -q 'Unknown server alias' "$fixture/grant-error"
if run_manager client source set agent1 0.0.0.0/0 2>"$fixture/source-error"; then
  echo "A catch-all client source must be rejected." >&2
  exit 1
fi
grep -q 'cannot be catch-all' "$fixture/source-error"
if run_manager client revoke agent1 2>"$fixture/revoke-error"; then
  echo "Client revocation must require confirmation." >&2
  exit 1
fi
grep -q 'requires --yes' "$fixture/revoke-error"
run_manager server remove level-test --yes | grep -q '^Removed server registration level-test from 1 client(s)'
run_manager server remove nas-test --yes | grep -q '^Removed server registration nas-test from 1 client(s)'
run_manager server remove network-test --yes | grep -q '^Removed server registration network-test from 1 client(s)'
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["clients"]["agent1"]["grants"] == {}' "$fixture/etc/config.json"
[[ -s "$fixture/etc/secrets/servers/nas-test.json" ]]
run_manager server credentials remove nas-test --yes | grep -q '^Removed protected credentials'
[[ ! -e "$fixture/etc/secrets/servers/nas-test.json" ]]
run_manager plugin remove synology | grep -q '^Disabled and removed plugin registration synology'
run_manager server credentials remove network-test --yes | grep -q '^Removed protected credentials'
run_manager plugin remove unifi | grep -q '^Disabled and removed plugin registration unifi'
run_manager server credentials remove level-test --yes | grep -q '^Removed protected credentials'
run_manager plugin remove proxmox | grep -q '^Disabled and removed plugin registration proxmox'
run_manager client revoke agent1 --yes | grep -q '^Revoked and removed client agent1'
[[ ! -e "$fixture/etc/secrets/clients/agent1.json" ]]
run_manager client list | grep -q '^No remote clients are registered.$'
run_manager validate | grep -q '^PASS:'
run_manager plugin list | grep -q $'^proxmox\tavailable\tProxmox VE$'
if run_manager server add pve1 --plugin proxmox --endpoint 'https://user:pass@example.test' 2>"$fixture/error"; then
  echo "An endpoint containing credentials must be rejected." >&2
  exit 1
fi
grep -q 'without embedded credentials' "$fixture/error"
if run_manager server add pve1 --plugin proxmox --endpoint 'https://example.test:not-a-port' 2>"$fixture/error"; then
  echo "An endpoint containing an invalid port must be rejected." >&2
  exit 1
fi
grep -q 'invalid port' "$fixture/error"
if run_manager server add pve1 --plugin proxmox --endpoint 'https://pve1.example.test:8006' 2>"$fixture/error"; then
  echo "A server must not use an uninstalled plugin." >&2
  exit 1
fi
grep -q 'installed and enabled first' "$fixture/error"
run_manager transport tls create --host 127.0.0.1 | grep -q '^Created a private LabSteward CA'
[[ -s "$fixture/etc/secrets/tls/labsteward-ca.crt" ]]
[[ "$(stat -c '%a' "$fixture/etc/secrets/tls/labsteward-ca.key")" == "600" ]]
[[ "$(stat -c '%a' "$fixture/etc/secrets/tls/server.key")" == "640" ]]
if run_manager transport tls create --host 127.0.0.1 2>"$fixture/tls-overwrite-error"; then
  echo "TLS creation must not overwrite existing material by default." >&2
  exit 1
fi
grep -q 'replacement requires --force --yes' "$fixture/tls-overwrite-error"
run_manager transport configure --bind 127.0.0.1 | grep -q '^Configured TLS-only MCP transport'
LABSTEWARD_TEST_ADMIN_PASSWORD='correct horse battery staple' run_manager admin bootstrap --username steward | grep -q '^Configured LabSteward administrator steward'
run_manager admin tls create --host 127.0.0.1 | grep -q '^Created a separate LabSteward admin server certificate'
run_manager admin configure --bind 127.0.0.1 --host 127.0.0.1 --admin-source 127.0.0.1/32 | grep -q '^Configured the LabSteward administrator'
run_manager admin status | grep -q '^  OAuth issuer: https://127.0.0.1:9444$'
run_manager transport status | grep -q '^  Service: inactive$'
run_manager validate | grep -q '^PASS:'
run_manager transport enable | grep -q '^Enabled and started'
run_manager transport status | grep -q '^  Service: active$'
run_manager admin enable | grep -q '^Enabled the LabSteward OAuth'
run_manager admin status | grep -q '^  Web service: active$'
run_manager admin disable | grep -q '^Disabled the LabSteward OAuth'
run_manager transport disable | grep -q '^Disabled and stopped'
echo "Manager behavior checks passed."
