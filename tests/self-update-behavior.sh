#!/usr/bin/env bash
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
base="$fixture/opt"
manager="$fixture/bin/stewctl"
manager_alias="$fixture/bin/labsteward"
config="$fixture/etc/config.json"
release="$fixture/release"
mkdir -p "$base/lib" "$base/catalog" "$base/schemas" "$(dirname "$manager")" "$(dirname "$config")" "$release"

install -m 0755 "$project_root/src/labsteward-manager.py" "$manager"
install -m 0755 "$project_root/src/self-update.sh" "$base/lib/self-update.sh"
install -m 0644 "$project_root/src/labsteward_sanitize.py" "$base/lib/labsteward_sanitize.py"
install -m 0644 "$project_root/catalog/plugins.json" "$base/catalog/plugins.json"
install -m 0644 "$project_root/schemas/config.schema.json" "$base/schemas/config.schema.json"
printf 'v0.1.0\n' >"$base/VERSION"
printf 'file://%s\n' "$release" >"$base/update.url"
printf '{"schema":1,"plugins":{},"servers":{}}\n' >"$config"

build_release() {
  local version="$1"
  printf '%s\n' "$version" >"$release/VERSION"
  install -m 0755 "$project_root/src/labsteward-manager.py" "$release/stewctl"
  install -m 0755 "$project_root/src/self-update.sh" "$release/self-update.sh"
  install -m 0644 "$project_root/src/labsteward_sanitize.py" "$release/labsteward-sanitize.py"
  install -m 0644 "$project_root/catalog/plugins.json" "$release/plugins.json"
  install -m 0644 "$project_root/schemas/config.schema.json" "$release/config.schema.json"
  (cd "$release" && sha256sum VERSION stewctl self-update.sh labsteward-sanitize.py plugins.json config.schema.json >SHA256SUMS)
}

run_update() {
  LABSTEWARD_ALLOW_NON_ROOT=1 \
  LABSTEWARD_BASE_DIR="$base" \
  LABSTEWARD_MANAGER_PATH="$manager" \
  LABSTEWARD_MANAGER_ALIAS_PATH="$manager_alias" \
  LABSTEWARD_CONFIG_FILE="$config" \
  LABSTEWARD_CATALOG_FILE="$base/catalog/plugins.json" \
  LABSTEWARD_VERSION_FILE="$base/VERSION" \
  bash "$base/lib/self-update.sh" "$@"
}

assert_no_rollback_dirs() {
  local rollback_dir
  rollback_dir="$(find "$base" -maxdepth 1 -type d -name '.rollback.*' -print -quit)"
  if [[ -n "$rollback_dir" ]]; then
    echo "The updater left a rollback directory behind: $rollback_dir" >&2
    exit 1
  fi
}

build_release v0.1.1
run_update --check | grep -q 'update available: v0.1.0 -> v0.1.1.'
grep -qx 'v0.1.0' "$base/VERSION"
assert_no_rollback_dirs
run_update | grep -q 'Updated LabSteward core to v0.1.1.'
grep -qx 'v0.1.1' "$base/VERSION"
[[ "$(readlink "$manager_alias")" == "$manager" ]]
assert_no_rollback_dirs

build_release v0.1.1
rm "$release/SHA256SUMS" "$release/stewctl" "$release/self-update.sh" \
  "$release/labsteward-sanitize.py" "$release/plugins.json" "$release/config.schema.json"
run_update --check | grep -q 'already current at v0.1.1.'
run_update | grep -q 'already current at v0.1.1.'
assert_no_rollback_dirs

build_release v0.1.0
if run_update 2>"$fixture/downgrade-error"; then
  echo "The updater must reject downgrades." >&2
  exit 1
fi
grep -q 'Refusing to downgrade' "$fixture/downgrade-error"
grep -qx 'v0.1.1' "$base/VERSION"
assert_no_rollback_dirs

build_release v0.1.2
printf '{"schema":999,"plugins":[]}\n' >"$release/plugins.json"
(cd "$release" && sha256sum VERSION stewctl self-update.sh labsteward-sanitize.py plugins.json config.schema.json >SHA256SUMS)
if run_update >"$fixture/rollback-output" 2>"$fixture/rollback-error"; then
  echo "Post-update validation must reject an invalid catalog." >&2
  exit 1
fi
grep -q 'restoring the previous LabSteward core' "$fixture/rollback-error"
grep -qx 'v0.1.1' "$base/VERSION"
python3 -m json.tool "$base/catalog/plugins.json" >/dev/null
assert_no_rollback_dirs

build_release v0.1.3
printf 'this is not valid python\n' >"$release/labsteward-sanitize.py"
(cd "$release" && sha256sum VERSION stewctl self-update.sh labsteward-sanitize.py plugins.json config.schema.json >SHA256SUMS)
if run_update >"$fixture/sanitizer-rollback-output" 2>"$fixture/sanitizer-rollback-error"; then
  echo "Post-update validation must reject an invalid sanitizer." >&2
  exit 1
fi
grep -q 'restoring the previous LabSteward core' "$fixture/sanitizer-rollback-error"
grep -qx 'v0.1.1' "$base/VERSION"
python3 -m py_compile "$base/lib/labsteward_sanitize.py"
assert_no_rollback_dirs

printf 'file://%s/missing-release\n' "$fixture" >"$base/update.url"
if run_update --check >"$fixture/missing-output" 2>"$fixture/missing-error"; then
  echo "An inaccessible update source must fail clearly." >&2
  exit 1
fi
grep -q 'Unable to download release metadata' "$fixture/missing-error"
assert_no_rollback_dirs
echo "Self-update behavior checks passed."
