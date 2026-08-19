#!/usr/bin/env bash
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

bash tools/build-artifacts.sh --check
bash -n labsteward.sh ct/labsteward.sh install/labsteward-install.sh src/self-update.sh \
  tools/build-artifacts.sh tools/build-release-assets.sh tools/fetch-community-helpers.sh
python3 -c 'compile(open("src/labsteward-manager.py", encoding="utf-8").read(), "src/labsteward-manager.py", "exec")'
python3 -c 'compile(open("src/labsteward_sanitize.py", encoding="utf-8").read(), "src/labsteward_sanitize.py", "exec")'
python3 tests/sanitizer-behavior.py
python3 -m json.tool catalog/plugins.json >/dev/null
python3 -m json.tool schemas/config.schema.json >/dev/null

grep -q 'var_unprivileged="${var_unprivileged:-1}"' ct/labsteward.sh
grep -q 'var_nesting="${var_nesting:-1}"' ct/labsteward.sh
grep -q 'LABSTEWARD_INSTALL_URL' labsteward.sh
grep -q 'sha256sum -c --ignore-missing SHA256SUMS' labsteward.sh
grep -q 'Refusing to downgrade LabSteward' src/self-update.sh
grep -q 'ln -sfn /usr/local/bin/stewctl /usr/local/bin/labsteward' tools/build-artifacts.sh
grep -q 'prog="stewctl"' src/labsteward-manager.py
grep -q 'LABSTEWARD_INSTALL_SANITIZER' src/labsteward-install.sh.in
grep -q -- '--shell /usr/sbin/nologin labsteward' src/labsteward-install.sh.in
grep -q 'Plugin is not in the approved release catalog' src/labsteward-manager.py
grep -q 'Server endpoints must be HTTPS origins without embedded credentials' src/labsteward-manager.py

temporary_build="$(mktemp)"
trap 'rm -f "$temporary_build"' EXIT
cp vendor/community-scripts/misc/build.func "$temporary_build"
sed -i \
  -e 's|"$COMMUNITY_SCRIPTS_URL/install/${var_install}.sh"|"$LABSTEWARD_INSTALL_URL"|g' \
  -e 's|"https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/install/${var_install}.sh"|"$LABSTEWARD_INSTALL_URL"|g' \
  "$temporary_build"
[[ "$(grep -c 'curl -fsSL "$LABSTEWARD_INSTALL_URL"' "$temporary_build")" -ge 2 ]]
echo "Static checks passed."
