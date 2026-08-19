#!/usr/bin/env bash

if [[ -n "${LABSTEWARD_BUILD_FUNC_PATH:-}" ]]; then
  source "$LABSTEWARD_BUILD_FUNC_PATH"
else
  source <(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/misc/build.func)
fi

APP="LabSteward"
var_tags="${var_tags:-management;gateway}"
var_cpu="${var_cpu:-1}"
var_ram="${var_ram:-512}"
var_disk="${var_disk:-5}"
var_os="${var_os:-debian}"
var_version="${var_version:-13}"
var_arm64="${var_arm64:-yes}"
var_unprivileged="${var_unprivileged:-1}"
var_nesting="${var_nesting:-1}"

header_info "$APP"
variables
color
catch_errors

function update_script() {
  header_info
  check_container_storage
  check_container_resources
  if [[ ! -x /usr/local/bin/stewctl ]]; then
    msg_error "No ${APP} installation found!"
    exit 1
  fi
  /usr/local/bin/stewctl self-update
  exit
}

start
build_container
description

msg_ok "Completed successfully!\n"
echo -e "${CREATING}${GN}${APP} core has been initialized.${CL}"
echo -e "${INFO}${YW}Inside the LXC, start with:${CL} ${BGN}stewctl status${CL}"
echo -e "${INFO}${YW}No management credentials or live plugins were installed.${CL}"
