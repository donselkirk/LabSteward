#!/usr/bin/env bash
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/opt/catalog" "$fixture/opt/lib" "$fixture/opt/schemas" "$fixture/etc/secrets/clients" "$fixture/systemd"
cp "$project_root/catalog/plugins.json" "$fixture/opt/catalog/plugins.json"
cp "$project_root/src/labsteward_sanitize.py" "$fixture/opt/lib/labsteward_sanitize.py"
cp "$project_root/src/labsteward_core.py" "$fixture/opt/lib/labsteward_core.py"
cp "$project_root/src/labsteward_mcp.py" "$fixture/opt/lib/labsteward_mcp.py"
cp "$project_root/src/self-update.sh" "$fixture/opt/lib/self-update.sh"
cp "$project_root/src/labsteward.service" "$fixture/systemd/labsteward.service"
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
  LABSTEWARD_TRANSPORT_CONFIG="$fixture/etc/transport.json" \
  LABSTEWARD_TLS_DIR="$fixture/etc/secrets/tls" \
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
if run_manager client permission set agent1 missing audit.node 2>"$fixture/grant-error"; then
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
run_manager client revoke agent1 --yes | grep -q '^Revoked client agent1'
[[ ! -e "$fixture/etc/secrets/clients/agent1.json" ]]
run_manager validate | grep -q '^PASS:'
run_manager plugin list | grep -q $'^proxmox\tplanned\tProxmox VE$'
if run_manager plugin install proxmox 2>"$fixture/error"; then
  echo "A planned plugin must not install." >&2
  exit 1
fi
grep -q 'not yet available' "$fixture/error"
if run_manager server add pve1 --plugin proxmox --endpoint 'https://user:pass@example.test' 2>"$fixture/error"; then
  echo "An endpoint containing credentials must be rejected." >&2
  exit 1
fi
grep -q 'without embedded credentials' "$fixture/error"
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
run_manager transport status | grep -q '^  Service: inactive$'
run_manager validate | grep -q '^PASS:'
run_manager transport enable | grep -q '^Enabled and started'
run_manager transport status | grep -q '^  Service: active$'
run_manager transport disable | grep -q '^Disabled and stopped'
echo "Manager behavior checks passed."
