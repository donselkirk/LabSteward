#!/usr/bin/env bash
set -Eeuo pipefail

readonly BASE_DIR="${LABSTEWARD_BASE_DIR:-/opt/labsteward}"
readonly MANAGER_PATH="${LABSTEWARD_MANAGER_PATH:-/usr/local/bin/stewctl}"
readonly MANAGER_ALIAS_PATH="${LABSTEWARD_MANAGER_ALIAS_PATH:-/usr/local/bin/labsteward}"
readonly SANITIZER_PATH="${LABSTEWARD_SANITIZER_PATH:-${BASE_DIR}/lib/labsteward_sanitize.py}"
readonly CORE_PATH="${LABSTEWARD_CORE_FILE:-${BASE_DIR}/lib/labsteward_core.py}"
readonly MCP_PATH="${LABSTEWARD_MCP_FILE:-${BASE_DIR}/lib/labsteward_mcp.py}"
readonly ADMIN_PATH="${LABSTEWARD_ADMIN_FILE:-${BASE_DIR}/lib/labsteward_admin.py}"
readonly BROKER_PATH="${LABSTEWARD_BROKER_FILE:-${BASE_DIR}/lib/labsteward_broker.py}"
readonly LOG_PATH="${LABSTEWARD_LOG_FILE:-${BASE_DIR}/lib/labsteward_log.py}"
readonly SYN_PLUGIN_DIR="${LABSTEWARD_SYNOLOGY_PLUGIN_DIR:-${BASE_DIR}/plugins/synology}"
readonly UNIFI_PLUGIN_DIR="${LABSTEWARD_UNIFI_PLUGIN_DIR:-${BASE_DIR}/plugins/unifi}"
readonly PROXMOX_PLUGIN_DIR="${LABSTEWARD_PROXMOX_PLUGIN_DIR:-${BASE_DIR}/plugins/proxmox}"
readonly SYSTEMD_UNIT_PATH="${LABSTEWARD_SYSTEMD_UNIT:-/etc/systemd/system/labsteward.service}"
readonly ADMIN_SYSTEMD_UNIT_PATH="${LABSTEWARD_ADMIN_SYSTEMD_UNIT:-/etc/systemd/system/labsteward-admin.service}"
readonly BROKER_SYSTEMD_UNIT_PATH="${LABSTEWARD_BROKER_SYSTEMD_UNIT:-/etc/systemd/system/labsteward-broker.service}"
readonly SYSTEMCTL="${LABSTEWARD_SYSTEMCTL:-/usr/bin/systemctl}"
readonly VERSION_FILE="${LABSTEWARD_VERSION_FILE:-${BASE_DIR}/VERSION}"
readonly UPDATE_URL_FILE="${BASE_DIR}/update.url"
readonly DEFAULT_UPDATE_URL="https://github.com/donselkirk/LabSteward/releases/latest/download"

check_only=0
case "${1:-}" in
  "") ;;
  --check) check_only=1 ;;
  *)
    echo "Usage: stewctl update check | stewctl update apply" >&2
    exit 2
    ;;
esac

[[ $EUID -eq 0 || "${LABSTEWARD_ALLOW_NON_ROOT:-0}" == "1" ]] || {
  echo "Run LabSteward update commands as root." >&2
  exit 1
}

update_url="${LABSTEWARD_UPDATE_BASE_URL:-}"
if [[ -z "$update_url" && -r "$UPDATE_URL_FILE" ]]; then
  update_url="$(<"$UPDATE_URL_FILE")"
fi
update_url="${update_url:-$DEFAULT_UPDATE_URL}"
update_url="${update_url%/}"

stage="$(mktemp -d)"
backup=""
runtime_bundle=0
synology_bundle=0
unifi_bundle=0
proxmox_bundle=0
log_bundle=0
service_was_active=0
admin_service_was_active=0
broker_service_was_active=0
cleanup() {
  rm -rf "$stage"
  [[ -z "$backup" ]] || rm -rf "$backup"
}
trap cleanup EXIT

download_asset() {
  local url="$1"
  local destination="$2"
  local label="$3"
  if curl -fsSL --retry 3 --retry-all-errors "$url" -o "$destination"; then
    return 0
  fi
  echo "Unable to download ${label} from the configured update source." >&2
  if [[ "$url" == https://github.com/donselkirk/LabSteward/* ]]; then
    echo "Private GitHub releases are unavailable to the unauthenticated updater; use a reviewed manual upgrade until the repository is public." >&2
  fi
  return 1
}

download_asset "${update_url}/VERSION" "${stage}/VERSION" "release metadata"
grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' "${stage}/VERSION" || {
  echo "Release version metadata is invalid." >&2
  exit 1
}
release_version="$(<"${stage}/VERSION")"
current_version="v0.0.0"
if [[ -r "$VERSION_FILE" ]] && grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' "$VERSION_FILE"; then
  current_version="$(<"$VERSION_FILE")"
fi
if [[ "$(printf '%s\n%s\n' "$release_version" "$current_version" | sort -V | sed -n '1p')" == "$release_version" \
  && "$release_version" != "$current_version" ]]; then
  echo "Refusing to downgrade LabSteward from ${current_version} to ${release_version}." >&2
  exit 1
fi
if [[ "$release_version" == "$current_version" ]]; then
  echo "LabSteward is already current at ${release_version}."
  exit 0
fi
if ((check_only)); then
  echo "LabSteward update available: ${current_version} -> ${release_version}."
  exit 0
fi

asset_url="$update_url"
if [[ "$update_url" == "$DEFAULT_UPDATE_URL" ]]; then
  asset_url="https://github.com/donselkirk/LabSteward/releases/download/${release_version}"
fi

download_asset "${asset_url}/SHA256SUMS" "${stage}/SHA256SUMS" "SHA256SUMS"
required_assets=(stewctl self-update.sh labsteward-sanitize.py plugins.json config.schema.json)
optional_log_assets=(labsteward-log.py)
optional_runtime_assets=(labsteward-core.py labsteward-mcp.py labsteward-admin.py \
  labsteward-broker.py labsteward-core.service labsteward-admin.service \
  labsteward-broker.service)
optional_synology_assets=(synology-plugin.py synology-manifest.json)
optional_unifi_assets=(unifi-plugin.py unifi-manifest.json)
optional_proxmox_assets=(proxmox-plugin.py proxmox-manifest.json)
for asset in "${required_assets[@]}"; do
  grep -q " ${asset}$" "${stage}/SHA256SUMS" || {
    echo "LabSteward release is missing required checksum metadata for ${asset}." >&2
    exit 1
  }
  download_asset "${asset_url}/${asset}" "${stage}/${asset}" "$asset"
done
optional_count=0
for asset in "${optional_runtime_assets[@]}"; do
  if grep -q " ${asset}$" "${stage}/SHA256SUMS"; then
    optional_count=$((optional_count + 1))
  fi
done
if ((optional_count != 0 && optional_count != ${#optional_runtime_assets[@]})); then
  echo "LabSteward release contains an incomplete runtime bundle." >&2
  exit 1
fi
if ((optional_count)); then
  runtime_bundle=1
  for asset in "${optional_runtime_assets[@]}"; do
    download_asset "${asset_url}/${asset}" "${stage}/${asset}" "$asset"
  done
fi
synology_count=0
for asset in "${optional_synology_assets[@]}"; do
  if grep -q " ${asset}$" "${stage}/SHA256SUMS"; then
    synology_count=$((synology_count + 1))
  fi
done
if ((synology_count != 0 && synology_count != ${#optional_synology_assets[@]})); then
  echo "LabSteward release contains an incomplete Synology plugin bundle." >&2
  exit 1
fi
if ((synology_count)); then
  synology_bundle=1
  for asset in "${optional_synology_assets[@]}"; do
    download_asset "${asset_url}/${asset}" "${stage}/${asset}" "$asset"
  done
fi
unifi_count=0
for asset in "${optional_unifi_assets[@]}"; do
  if grep -q " ${asset}$" "${stage}/SHA256SUMS"; then
    unifi_count=$((unifi_count + 1))
  fi
done
if ((unifi_count != 0 && unifi_count != ${#optional_unifi_assets[@]})); then
  echo "LabSteward release contains an incomplete UniFi plugin bundle." >&2
  exit 1
fi
if ((unifi_count)); then
  unifi_bundle=1
  for asset in "${optional_unifi_assets[@]}"; do
    download_asset "${asset_url}/${asset}" "${stage}/${asset}" "$asset"
  done
fi
proxmox_count=0
for asset in "${optional_proxmox_assets[@]}"; do
  if grep -q " ${asset}$" "${stage}/SHA256SUMS"; then
    proxmox_count=$((proxmox_count + 1))
  fi
done
if ((proxmox_count != 0 && proxmox_count != ${#optional_proxmox_assets[@]})); then
  echo "LabSteward release contains an incomplete Proxmox plugin bundle." >&2
  exit 1
fi
if ((proxmox_count)); then
  proxmox_bundle=1
  for asset in "${optional_proxmox_assets[@]}"; do
    download_asset "${asset_url}/${asset}" "${stage}/${asset}" "$asset"
  done
fi
log_count=0
for asset in "${optional_log_assets[@]}"; do
  if grep -q " ${asset}$" "${stage}/SHA256SUMS"; then log_count=$((log_count + 1)); fi
done
if ((log_count)); then
  log_bundle=1
  for asset in "${optional_log_assets[@]}"; do download_asset "${asset_url}/${asset}" "${stage}/${asset}" "$asset"; done
fi
(
  cd "$stage"
  grep -q " VERSION$" SHA256SUMS || exit 1
  sha256sum -c --ignore-missing SHA256SUMS >/dev/null
) || {
  echo "LabSteward release assets failed checksum validation." >&2
  exit 1
}

rollback() {
  trap - ERR
  echo "Update validation failed; restoring the previous LabSteward core." >&2
  [[ ! -e "${backup}/manager" ]] || cp -a "${backup}/manager" "$MANAGER_PATH"
  [[ ! -e "${backup}/self-update.sh" ]] || cp -a "${backup}/self-update.sh" "${BASE_DIR}/lib/self-update.sh"
  [[ ! -e "${backup}/labsteward_sanitize.py" ]] || cp -a "${backup}/labsteward_sanitize.py" "$SANITIZER_PATH"
  if ((log_bundle)); then
    [[ ! -e "${backup}/labsteward_log.py" ]] || cp -a "${backup}/labsteward_log.py" "$LOG_PATH"
  fi
  if ((runtime_bundle)); then
    if [[ -e "${backup}/labsteward_core.py" ]]; then
      cp -a "${backup}/labsteward_core.py" "$CORE_PATH"
    else
      rm -f "$CORE_PATH"
    fi
    if [[ -e "${backup}/labsteward_mcp.py" ]]; then
      cp -a "${backup}/labsteward_mcp.py" "$MCP_PATH"
    else
      rm -f "$MCP_PATH"
    fi
    for item in \
      "labsteward_admin.py:$ADMIN_PATH" \
      "labsteward_broker.py:$BROKER_PATH" \
      "labsteward-admin.service:$ADMIN_SYSTEMD_UNIT_PATH" \
      "labsteward-broker.service:$BROKER_SYSTEMD_UNIT_PATH"; do
      source_name="${item%%:*}"
      destination="${item#*:}"
      if [[ -e "${backup}/${source_name}" ]]; then
        cp -a "${backup}/${source_name}" "$destination"
      else
        rm -f "$destination"
      fi
    done
    if [[ -e "${backup}/labsteward.service" ]]; then
      cp -a "${backup}/labsteward.service" "$SYSTEMD_UNIT_PATH"
    else
      rm -f "$SYSTEMD_UNIT_PATH"
    fi
    "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true
    if ((service_was_active)); then
      "$SYSTEMCTL" restart labsteward.service >/dev/null 2>&1 || true
    fi
    if ((admin_service_was_active)); then
      "$SYSTEMCTL" restart labsteward-admin.service >/dev/null 2>&1 || true
    fi
    if ((broker_service_was_active)); then
      "$SYSTEMCTL" restart labsteward-broker.service >/dev/null 2>&1 || true
    fi
  fi
  if ((synology_bundle)); then
    for item in synology-plugin.py synology-manifest.json; do
      destination="${SYN_PLUGIN_DIR}/${item#synology-}"
      if [[ -e "${backup}/${item}" ]]; then
        cp -a "${backup}/${item}" "$destination"
      else
        rm -f "$destination"
      fi
    done
  fi
  if ((unifi_bundle)); then
    for item in unifi-plugin.py unifi-manifest.json; do
      destination="${UNIFI_PLUGIN_DIR}/${item#unifi-}"
      if [[ -e "${backup}/${item}" ]]; then
        cp -a "${backup}/${item}" "$destination"
      else
        rm -f "$destination"
      fi
    done
  fi
  if ((proxmox_bundle)); then
    for item in proxmox-plugin.py proxmox-manifest.json; do
      destination="${PROXMOX_PLUGIN_DIR}/${item#proxmox-}"
      if [[ -e "${backup}/${item}" ]]; then
        cp -a "${backup}/${item}" "$destination"
      else
        rm -f "$destination"
      fi
    done
  fi
  [[ ! -e "${backup}/plugins.json" ]] || cp -a "${backup}/plugins.json" "${BASE_DIR}/catalog/plugins.json"
  [[ ! -e "${backup}/config.schema.json" ]] || cp -a "${backup}/config.schema.json" "${BASE_DIR}/schemas/config.schema.json"
  [[ ! -e "${backup}/VERSION" ]] || cp -a "${backup}/VERSION" "$VERSION_FILE"
  [[ ! -e "${backup}/update.url" ]] || cp -a "${backup}/update.url" "$UPDATE_URL_FILE"
  rm -rf "$backup"
  backup=""
}

backup="$(mktemp -d "${BASE_DIR}/.rollback.XXXXXX")"
trap rollback ERR
install -d -m 0755 "$backup" "${BASE_DIR}/lib" "${BASE_DIR}/catalog" "${BASE_DIR}/schemas"
[[ ! -e "$MANAGER_PATH" ]] || cp -a "$MANAGER_PATH" "${backup}/manager"
[[ ! -e "${BASE_DIR}/lib/self-update.sh" ]] || cp -a "${BASE_DIR}/lib/self-update.sh" "${backup}/self-update.sh"
[[ ! -e "$SANITIZER_PATH" ]] || cp -a "$SANITIZER_PATH" "${backup}/labsteward_sanitize.py"
if ((log_bundle)); then
  [[ ! -e "$LOG_PATH" ]] || cp -a "$LOG_PATH" "${backup}/labsteward_log.py"
fi
if ((runtime_bundle)); then
  if "$SYSTEMCTL" is-active --quiet labsteward.service >/dev/null 2>&1; then
    service_was_active=1
  fi
  if "$SYSTEMCTL" is-active --quiet labsteward-admin.service >/dev/null 2>&1; then
    admin_service_was_active=1
  fi
  if "$SYSTEMCTL" is-active --quiet labsteward-broker.service >/dev/null 2>&1; then
  broker_service_was_active=1
  fi
  [[ ! -e "$CORE_PATH" ]] || cp -a "$CORE_PATH" "${backup}/labsteward_core.py"
  [[ ! -e "$MCP_PATH" ]] || cp -a "$MCP_PATH" "${backup}/labsteward_mcp.py"
  [[ ! -e "$SYSTEMD_UNIT_PATH" ]] || cp -a "$SYSTEMD_UNIT_PATH" "${backup}/labsteward.service"
  [[ ! -e "$ADMIN_PATH" ]] || cp -a "$ADMIN_PATH" "${backup}/labsteward_admin.py"
  [[ ! -e "$BROKER_PATH" ]] || cp -a "$BROKER_PATH" "${backup}/labsteward_broker.py"
  [[ ! -e "$ADMIN_SYSTEMD_UNIT_PATH" ]] || cp -a "$ADMIN_SYSTEMD_UNIT_PATH" "${backup}/labsteward-admin.service"
  [[ ! -e "$BROKER_SYSTEMD_UNIT_PATH" ]] || cp -a "$BROKER_SYSTEMD_UNIT_PATH" "${backup}/labsteward-broker.service"
fi
if ((synology_bundle)); then
  install -d -m 0755 "$SYN_PLUGIN_DIR"
  [[ ! -e "${SYN_PLUGIN_DIR}/plugin.py" ]] || cp -a "${SYN_PLUGIN_DIR}/plugin.py" "${backup}/synology-plugin.py"
  [[ ! -e "${SYN_PLUGIN_DIR}/manifest.json" ]] || cp -a "${SYN_PLUGIN_DIR}/manifest.json" "${backup}/synology-manifest.json"
fi
if ((unifi_bundle)); then
  install -d -m 0755 "$UNIFI_PLUGIN_DIR"
  [[ ! -e "${UNIFI_PLUGIN_DIR}/plugin.py" ]] || cp -a "${UNIFI_PLUGIN_DIR}/plugin.py" "${backup}/unifi-plugin.py"
  [[ ! -e "${UNIFI_PLUGIN_DIR}/manifest.json" ]] || cp -a "${UNIFI_PLUGIN_DIR}/manifest.json" "${backup}/unifi-manifest.json"
fi
if ((proxmox_bundle)); then
  install -d -m 0755 "$PROXMOX_PLUGIN_DIR"
  [[ ! -e "${PROXMOX_PLUGIN_DIR}/plugin.py" ]] || cp -a "${PROXMOX_PLUGIN_DIR}/plugin.py" "${backup}/proxmox-plugin.py"
  [[ ! -e "${PROXMOX_PLUGIN_DIR}/manifest.json" ]] || cp -a "${PROXMOX_PLUGIN_DIR}/manifest.json" "${backup}/proxmox-manifest.json"
fi
[[ ! -e "${BASE_DIR}/catalog/plugins.json" ]] || cp -a "${BASE_DIR}/catalog/plugins.json" "${backup}/plugins.json"
[[ ! -e "${BASE_DIR}/schemas/config.schema.json" ]] || cp -a "${BASE_DIR}/schemas/config.schema.json" "${backup}/config.schema.json"
[[ ! -e "$VERSION_FILE" ]] || cp -a "$VERSION_FILE" "${backup}/VERSION"
[[ ! -e "$UPDATE_URL_FILE" ]] || cp -a "$UPDATE_URL_FILE" "${backup}/update.url"
install -m 0755 "${stage}/stewctl" "$MANAGER_PATH"
ln -sfn "$MANAGER_PATH" "$MANAGER_ALIAS_PATH"
install -m 0755 "${stage}/self-update.sh" "${BASE_DIR}/lib/self-update.sh"
install -m 0644 "${stage}/labsteward-sanitize.py" "$SANITIZER_PATH"
if ((log_bundle)); then
  install -m 0644 "${stage}/labsteward-log.py" "$LOG_PATH"
fi
if ((runtime_bundle)); then
  if [[ $EUID -eq 0 ]]; then
    getent group labsteward-admin >/dev/null || groupadd --system labsteward-admin
    id labsteward-admin >/dev/null 2>&1 || useradd --system --gid labsteward-admin \
      --home-dir /var/lib/labsteward-admin --create-home --shell /usr/sbin/nologin labsteward-admin
    install -d -o labsteward-admin -g labsteward-admin -m 0700 /var/lib/labsteward-admin
    install -d -o root -g labsteward-admin -m 2750 /etc/labsteward-admin
  fi
  install -m 0644 "${stage}/labsteward-core.py" "$CORE_PATH"
  install -m 0644 "${stage}/labsteward-mcp.py" "$MCP_PATH"
  install -m 0644 "${stage}/labsteward-admin.py" "$ADMIN_PATH"
  install -m 0644 "${stage}/labsteward-broker.py" "$BROKER_PATH"
  install -D -m 0644 "${stage}/labsteward-core.service" "$SYSTEMD_UNIT_PATH"
  install -D -m 0644 "${stage}/labsteward-admin.service" "$ADMIN_SYSTEMD_UNIT_PATH"
  install -D -m 0644 "${stage}/labsteward-broker.service" "$BROKER_SYSTEMD_UNIT_PATH"
  "$SYSTEMCTL" daemon-reload
fi
if ((synology_bundle)); then
  install -m 0644 "${stage}/synology-plugin.py" "${SYN_PLUGIN_DIR}/plugin.py"
  install -m 0644 "${stage}/synology-manifest.json" "${SYN_PLUGIN_DIR}/manifest.json"
fi
if ((unifi_bundle)); then
  install -m 0644 "${stage}/unifi-plugin.py" "${UNIFI_PLUGIN_DIR}/plugin.py"
  install -m 0644 "${stage}/unifi-manifest.json" "${UNIFI_PLUGIN_DIR}/manifest.json"
fi
if ((proxmox_bundle)); then
  install -m 0644 "${stage}/proxmox-plugin.py" "${PROXMOX_PLUGIN_DIR}/plugin.py"
  install -m 0644 "${stage}/proxmox-manifest.json" "${PROXMOX_PLUGIN_DIR}/manifest.json"
fi
install -m 0644 "${stage}/plugins.json" "${BASE_DIR}/catalog/plugins.json"
install -m 0644 "${stage}/config.schema.json" "${BASE_DIR}/schemas/config.schema.json"
install -m 0644 "${stage}/VERSION" "$VERSION_FILE"
printf '%s\n' "$update_url" >"$UPDATE_URL_FILE"
chmod 0644 "$UPDATE_URL_FILE"
"$MANAGER_PATH" validate
if ((runtime_bundle && service_was_active)); then
  "$SYSTEMCTL" restart labsteward.service
fi
if ((runtime_bundle && admin_service_was_active)); then
  "$SYSTEMCTL" restart labsteward-admin.service
fi
if ((runtime_bundle && broker_service_was_active)); then
  "$SYSTEMCTL" restart labsteward-broker.service
fi
trap - ERR
rm -rf "$backup"
backup=""
echo "Updated LabSteward core to ${release_version}."
