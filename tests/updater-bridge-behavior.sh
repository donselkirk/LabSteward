#!/usr/bin/env bash
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

bridge_version="$(sed -n 's/^bridge_version=//p' "$project_root/release/COMPATIBILITY")"
source_commit="$(sed -n 's/^bridge_source_commit=//p' "$project_root/release/COMPATIBILITY")"

bash "$project_root/tools/build-updater-bridge.sh" "$bridge_version" "$fixture/dist"
(
  cd "$fixture/dist"
  sha256sum -c SHA256SUMS >/dev/null
)

grep -qx "$bridge_version" "$fixture/dist/VERSION"
cmp "$project_root/src/self-update.sh" "$fixture/dist/self-update.sh"
git -C "$project_root" show "${source_commit}:src/labsteward-manager.py" >"$fixture/source-stewctl"
cmp "$fixture/source-stewctl" "$fixture/dist/stewctl"
[[ -s "$fixture/dist/labsteward.service" ]]
[[ ! -e "$fixture/dist/labsteward-core.service" ]]

bash "$project_root/tools/build-release-assets.sh" v0.2.0 "$fixture/core"
[[ -s "$fixture/core/labsteward-core.service" ]]
[[ ! -e "$fixture/core/labsteward.service" ]]
git -C "$project_root" show "${source_commit}:src/self-update.sh" >"$fixture/source-self-update"
grep -q 'optional_runtime_assets=(labsteward-core.py labsteward-mcp.py labsteward.service)' \
  "$fixture/source-self-update"
legacy_runtime_count=0
for legacy_asset in labsteward-core.py labsteward-mcp.py labsteward.service; do
  [[ ! -e "$fixture/core/$legacy_asset" ]] || legacy_runtime_count=$((legacy_runtime_count + 1))
done
[[ "$legacy_runtime_count" -eq 2 ]]

if bash "$project_root/tools/build-release-assets.sh" v0.2.0 "$fixture/core" \
  >"$fixture/nonempty-output" 2>"$fixture/nonempty-error"; then
  echo "Release builder must reject a non-empty output directory." >&2
  exit 1
fi
grep -q 'output directory must be empty' "$fixture/nonempty-error"

for forbidden in labsteward-admin.py labsteward-broker.py labsteward-admin.service labsteward-broker.service; do
  if [[ -e "$fixture/dist/$forbidden" ]]; then
    echo "Updater bridge unexpectedly contains a v0.2 runtime asset: $forbidden" >&2
    exit 1
  fi
done

echo "Updater bridge behavior checks passed."
