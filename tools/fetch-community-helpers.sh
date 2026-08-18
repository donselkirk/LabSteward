#!/usr/bin/env bash
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
destination="${project_root}/vendor/community-scripts/misc"
base_url="${COMMUNITY_SCRIPTS_RAW_URL:-https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/misc}"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

declare -A expected=(
  [build.func]="9e8aedfd1ad5770e296c90d0c2a7e41dbfcd3087ec095f88ee9a8b597c292c29"
  [install.func]="b6c0e7ae09c0610eb5f9be78fa47b9194b232bea3175694f01c766998b22ed10"
  [tools.func]="9d176fc13fc728792650b22bfdfb015657226bffc5fb7ce32a6322489a9df37e"
  [core.func]="412a1a646752595a76b176268331789cb481460d1d7afcb95a8b9803e469f516"
  [api.func]="8beac6d809dd449e94a59d23bf015d48e3aee079c34b1fefb678782e5d65bdad"
  [error_handler.func]="2bf0af36fa79f176a0a326974e1c96d9e7130d047f12bdf19c05481fb1bfedc2"
)

for helper in "${!expected[@]}"; do
  curl -fsSL --retry 3 --retry-all-errors "${base_url}/${helper}" -o "${stage}/${helper}"
  actual="$(sha256sum "${stage}/${helper}" | awk '{print $1}')"
  [[ "$actual" == "${expected[$helper]}" ]] || {
    echo "Community Scripts ${helper} changed upstream; review it before updating the pin." >&2
    exit 1
  }
done

install -d -m 0755 "$destination"
for helper in build.func install.func tools.func core.func api.func error_handler.func; do
  install -m 0644 "${stage}/${helper}" "${destination}/${helper}"
done
echo "Fetched the reviewed Community Scripts helper set."
