#!/usr/bin/env bash
set +u
set -Eeo pipefail

readonly DEFAULT_COMMUNITY_RAW_URL="https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main"
readonly DEFAULT_RELEASE_BASE_URL="https://github.com/donselkirk/LabSteward/releases/latest/download"

bootstrap_dir=""
patched_build=""
cleanup() {
  [[ -z "$bootstrap_dir" ]] || rm -rf "$bootstrap_dir"
  [[ -z "$patched_build" ]] || rm -f "$patched_build"
}
trap cleanup EXIT

if [[ -n "${LABSTEWARD_REPOSITORY_RAW_URL:-}" ]]; then
  source_base_url="${LABSTEWARD_REPOSITORY_RAW_URL%/}"
  ct_url="${source_base_url}/ct/labsteward.sh"
  install_url="${source_base_url}/install/labsteward-install.sh"
  version_url=""
else
  release_base_url="${LABSTEWARD_RELEASE_BASE_URL:-$DEFAULT_RELEASE_BASE_URL}"
  release_base_url="${release_base_url%/}"
  bootstrap_dir="$(mktemp -d)"
  curl -fsSL --retry 3 --retry-all-errors "${release_base_url}/VERSION" -o "${bootstrap_dir}/VERSION"
  grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' "${bootstrap_dir}/VERSION" || {
    echo "LabSteward release version metadata is invalid." >&2
    exit 1
  }
  release_version="$(<"${bootstrap_dir}/VERSION")"
  if [[ "$release_base_url" == "$DEFAULT_RELEASE_BASE_URL" ]]; then
    release_base_url="https://github.com/donselkirk/LabSteward/releases/download/${release_version}"
  fi
  curl -fsSL --retry 3 --retry-all-errors "${release_base_url}/SHA256SUMS" -o "${bootstrap_dir}/SHA256SUMS"
  for asset in labsteward-ct.sh labsteward-install.sh build.func install.func tools.func core.func api.func error_handler.func; do
    curl -fsSL --retry 3 --retry-all-errors "${release_base_url}/${asset}" -o "${bootstrap_dir}/${asset}"
  done
  (
    cd "$bootstrap_dir"
    for asset in VERSION labsteward-ct.sh labsteward-install.sh build.func install.func tools.func core.func api.func error_handler.func; do
      grep -q " ${asset}$" SHA256SUMS || exit 1
    done
    sha256sum -c --ignore-missing SHA256SUMS >/dev/null
  ) || {
    echo "LabSteward bootstrap assets failed checksum validation." >&2
    exit 1
  }
  ct_url="${bootstrap_dir}/labsteward-ct.sh"
  install_url="${release_base_url}/labsteward-install.sh"
  version_url="${release_base_url}/VERSION"
  build_func="${bootstrap_dir}/build.func"
  export LABSTEWARD_UPDATE_BASE_URL="${LABSTEWARD_UPDATE_BASE_URL:-$DEFAULT_RELEASE_BASE_URL}"
fi

if [[ -n "${COMMUNITY_SCRIPTS_URL:-}" || -n "${LABSTEWARD_REPOSITORY_RAW_URL:-}" ]]; then
  community_raw_url="${COMMUNITY_SCRIPTS_URL:-$DEFAULT_COMMUNITY_RAW_URL}"
  community_raw_url="${community_raw_url%/}"
  bootstrap_dir="${bootstrap_dir:-$(mktemp -d)}"
  build_func="${bootstrap_dir}/build.func"
  curl -fsSL --retry 3 --retry-all-errors "${community_raw_url}/misc/build.func" -o "$build_func"
fi

patched_build="$(mktemp)"
cp "$build_func" "$patched_build"
sed -i \
  -e 's|"$COMMUNITY_SCRIPTS_URL/install/${var_install}.sh"|"$LABSTEWARD_INSTALL_URL"|g' \
  -e 's|"https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/install/${var_install}.sh"|"$LABSTEWARD_INSTALL_URL"|g' \
  "$patched_build"
redirect_count="$(grep -c 'curl -fsSL "$LABSTEWARD_INSTALL_URL"' "$patched_build" || true)"
if [[ "$redirect_count" -lt 2 ]]; then
  echo "Unable to redirect the Community Scripts installer URL; review upstream build.func." >&2
  exit 1
fi

export LABSTEWARD_BUILD_FUNC_PATH="$patched_build"
export LABSTEWARD_INSTALL_URL="$install_url"
export LABSTEWARD_VERSION_URL="$version_url"

if [[ -f "$ct_url" ]]; then
  source "$ct_url"
else
  source <(curl -fsSL --retry 3 --retry-all-errors "$ct_url")
fi
