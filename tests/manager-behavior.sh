#!/usr/bin/env bash
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/opt/catalog" "$fixture/etc"
cp "$project_root/catalog/plugins.json" "$fixture/opt/catalog/plugins.json"
printf 'v0.1.0\n' >"$fixture/opt/VERSION"
printf '{"schema":1,"plugins":{},"servers":{}}\n' >"$fixture/etc/config.json"

run_manager() {
  LABSTEWARD_ALLOW_NON_ROOT=1 \
  LABSTEWARD_BASE_DIR="$fixture/opt" \
  LABSTEWARD_CONFIG_FILE="$fixture/etc/config.json" \
  LABSTEWARD_CATALOG_FILE="$fixture/opt/catalog/plugins.json" \
  LABSTEWARD_VERSION_FILE="$fixture/opt/VERSION" \
  python3 "$project_root/src/labsteward-manager.py" "$@"
}

[[ "$(run_manager version)" == "LabSteward v0.1.0" ]]
run_manager configure | grep -q '^LabSteward configuration$'
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
echo "Manager behavior checks passed."
