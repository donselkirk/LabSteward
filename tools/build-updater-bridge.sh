#!/usr/bin/env bash
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:?usage: build-updater-bridge.sh VERSION [OUTPUT_DIR]}"
output="${2:-${project_root}/dist-bridge}"
source_commit="$(sed -n 's/^bridge_source_commit=//p' "${project_root}/release/COMPATIBILITY")"
[[ "$version" =~ ^v0\.1\.[0-9]+$ ]] || {
  echo "Bridge version must remain in the v0.1 patch line: ${version}" >&2
  exit 2
}
[[ "$source_commit" =~ ^[a-f0-9]{40}$ ]] || {
  echo "release/COMPATIBILITY does not contain a valid bridge source commit." >&2
  exit 1
}
git -C "$project_root" cat-file -e "${source_commit}^{commit}"

mkdir -p "$output"
if [[ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "Bridge output directory must be empty: $output" >&2
  exit 1
fi
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

extract() {
  local repository_path="$1"
  local output_name="$2"
  git -C "$project_root" show "${source_commit}:${repository_path}" >"${temporary}/${output_name}"
}

extract src/labsteward-manager.py stewctl
extract src/labsteward_sanitize.py labsteward-sanitize.py
extract src/labsteward_core.py labsteward-core.py
extract src/labsteward_mcp.py labsteward-mcp.py
extract src/labsteward.service labsteward.service
extract catalog/plugins.json plugins.json
extract schemas/config.schema.json config.schema.json

printf '%s\n' "$version" >"${output}/VERSION"
install -m 0644 "${project_root}/release/COMPATIBILITY" "${output}/COMPATIBILITY"
install -m 0755 "${temporary}/stewctl" "${output}/stewctl"
install -m 0755 "${project_root}/src/self-update.sh" "${output}/self-update.sh"
install -m 0644 "${temporary}/labsteward-sanitize.py" "${output}/labsteward-sanitize.py"
install -m 0644 "${temporary}/labsteward-core.py" "${output}/labsteward-core.py"
install -m 0644 "${temporary}/labsteward-mcp.py" "${output}/labsteward-mcp.py"
install -m 0644 "${temporary}/labsteward.service" "${output}/labsteward.service"
install -m 0644 "${temporary}/plugins.json" "${output}/plugins.json"
install -m 0644 "${temporary}/config.schema.json" "${output}/config.schema.json"
(
  cd "$output"
  sha256sum VERSION COMPATIBILITY config.schema.json labsteward-core.py \
    labsteward-mcp.py labsteward-sanitize.py labsteward.service plugins.json \
    self-update.sh stewctl >SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)
printf '%s\n' "Built updater-only bridge ${version} from ${source_commit}."
printf '%s\n' "Do not use this bridge for a fresh installation."
