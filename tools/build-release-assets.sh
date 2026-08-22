#!/usr/bin/env bash
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:?usage: build-release-assets.sh VERSION [OUTPUT_DIR]}"
output="${2:-${project_root}/dist}"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "Invalid release version: $version" >&2
  exit 2
}

mkdir -p "$output"
if [[ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "Release output directory must be empty: $output" >&2
  exit 1
fi
for helper in build.func install.func tools.func core.func api.func error_handler.func; do
  [[ -s "${project_root}/vendor/community-scripts/misc/${helper}" ]] || {
    echo "Missing reviewed helper ${helper}; run: bash tools/fetch-community-helpers.sh" >&2
    exit 1
  }
done
printf '%s\n' "$version" >"${output}/VERSION"
install -m 0755 "${project_root}/labsteward.sh" "${output}/labsteward.sh"
install -m 0755 "${project_root}/ct/labsteward.sh" "${output}/labsteward-ct.sh"
install -m 0755 "${project_root}/install/labsteward-install.sh" "${output}/labsteward-install.sh"
install -m 0755 "${project_root}/src/labsteward-manager.py" "${output}/stewctl"
install -m 0755 "${project_root}/src/self-update.sh" "${output}/self-update.sh"
install -m 0644 "${project_root}/src/labsteward_sanitize.py" "${output}/labsteward-sanitize.py"
install -m 0644 "${project_root}/src/labsteward_core.py" "${output}/labsteward-core.py"
install -m 0644 "${project_root}/src/labsteward_mcp.py" "${output}/labsteward-mcp.py"
install -m 0644 "${project_root}/src/labsteward_admin.py" "${output}/labsteward-admin.py"
install -m 0644 "${project_root}/src/labsteward_broker.py" "${output}/labsteward-broker.py"
install -m 0644 "${project_root}/src/labsteward_log.py" "${output}/labsteward-log.py"
install -m 0644 "${project_root}/src/labsteward.service" "${output}/labsteward-core.service"
install -m 0644 "${project_root}/src/labsteward-admin.service" "${output}/labsteward-admin.service"
install -m 0644 "${project_root}/src/labsteward-broker.service" "${output}/labsteward-broker.service"
install -m 0644 "${project_root}/plugins/synology/plugin.py" "${output}/synology-plugin.py"
install -m 0644 "${project_root}/plugins/synology/manifest.json" "${output}/synology-manifest.json"
install -m 0644 "${project_root}/plugins/unifi/plugin.py" "${output}/unifi-plugin.py"
install -m 0644 "${project_root}/plugins/unifi/manifest.json" "${output}/unifi-manifest.json"
install -m 0644 "${project_root}/plugins/proxmox/plugin.py" "${output}/proxmox-plugin.py"
install -m 0644 "${project_root}/plugins/proxmox/manifest.json" "${output}/proxmox-manifest.json"
install -m 0644 "${project_root}/catalog/plugins.json" "${output}/plugins.json"
install -m 0644 "${project_root}/schemas/config.schema.json" "${output}/config.schema.json"
install -m 0644 "${project_root}/release/COMPATIBILITY" "${output}/COMPATIBILITY"
for helper in build.func install.func tools.func core.func api.func error_handler.func; do
  install -m 0644 "${project_root}/vendor/community-scripts/misc/${helper}" "${output}/${helper}"
done
(
  cd "$output"
  sha256sum VERSION COMPATIBILITY api.func build.func config.schema.json core.func \
    error_handler.func labsteward-admin.py labsteward-admin.service labsteward-broker.py labsteward-log.py \
    labsteward-broker.service labsteward-core.py labsteward-ct.sh labsteward-install.sh \
    labsteward-mcp.py labsteward-sanitize.py labsteward-core.service labsteward.sh \
    install.func plugins.json self-update.sh stewctl synology-manifest.json \
    synology-plugin.py tools.func unifi-manifest.json unifi-plugin.py \
    proxmox-manifest.json proxmox-plugin.py >SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)
