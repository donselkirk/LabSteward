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
install -m 0644 "${project_root}/src/labsteward.service" "${output}/labsteward.service"
install -m 0644 "${project_root}/catalog/plugins.json" "${output}/plugins.json"
install -m 0644 "${project_root}/schemas/config.schema.json" "${output}/config.schema.json"
install -m 0644 "${project_root}/release/COMPATIBILITY" "${output}/COMPATIBILITY"
for helper in build.func install.func tools.func core.func api.func error_handler.func; do
  install -m 0644 "${project_root}/vendor/community-scripts/misc/${helper}" "${output}/${helper}"
done
(
  cd "$output"
  sha256sum VERSION COMPATIBILITY api.func build.func config.schema.json core.func \
    error_handler.func labsteward-core.py labsteward-ct.sh labsteward-install.sh \
    labsteward-mcp.py labsteward-sanitize.py labsteward.service labsteward.sh \
    install.func plugins.json self-update.sh stewctl tools.func >SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)
