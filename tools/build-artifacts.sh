#!/usr/bin/env bash
set -Eeuo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
template="${project_root}/src/labsteward-install.sh.in"
output="${project_root}/install/labsteward-install.sh"
check_only=0
[[ "${1:-}" == "--check" ]] && check_only=1
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT

while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    "# LABSTEWARD_INSTALL_MANAGER")
      printf "cat >/usr/local/bin/stewctl <<'EOF_LABSTEWARD_MANAGER'\n"
      cat "${project_root}/src/labsteward-manager.py"
      printf "EOF_LABSTEWARD_MANAGER\nchmod 0755 /usr/local/bin/stewctl\n"
      printf "ln -sfn /usr/local/bin/stewctl /usr/local/bin/labsteward\n"
      ;;
    "# LABSTEWARD_INSTALL_SELF_UPDATE")
      printf "cat >/opt/labsteward/lib/self-update.sh <<'EOF_LABSTEWARD_UPDATE'\n"
      cat "${project_root}/src/self-update.sh"
      printf "EOF_LABSTEWARD_UPDATE\nchmod 0755 /opt/labsteward/lib/self-update.sh\n"
      ;;
    "# LABSTEWARD_INSTALL_SANITIZER")
      printf "cat >/opt/labsteward/lib/labsteward_sanitize.py <<'EOF_LABSTEWARD_SANITIZER'\n"
      cat "${project_root}/src/labsteward_sanitize.py"
      printf "EOF_LABSTEWARD_SANITIZER\nchmod 0644 /opt/labsteward/lib/labsteward_sanitize.py\n"
      ;;
    "# LABSTEWARD_INSTALL_CORE")
      printf "cat >/opt/labsteward/lib/labsteward_core.py <<'EOF_LABSTEWARD_CORE'\n"
      cat "${project_root}/src/labsteward_core.py"
      printf "EOF_LABSTEWARD_CORE\nchmod 0644 /opt/labsteward/lib/labsteward_core.py\n"
      ;;
    "# LABSTEWARD_INSTALL_MCP")
      printf "cat >/opt/labsteward/lib/labsteward_mcp.py <<'EOF_LABSTEWARD_MCP'\n"
      cat "${project_root}/src/labsteward_mcp.py"
      printf "EOF_LABSTEWARD_MCP\nchmod 0644 /opt/labsteward/lib/labsteward_mcp.py\n"
      ;;
    "# LABSTEWARD_INSTALL_CATALOG")
      printf "cat >/opt/labsteward/catalog/plugins.json <<'EOF_LABSTEWARD_CATALOG'\n"
      cat "${project_root}/catalog/plugins.json"
      printf "EOF_LABSTEWARD_CATALOG\n"
      ;;
    "# LABSTEWARD_INSTALL_SCHEMA")
      printf "cat >/opt/labsteward/schemas/config.schema.json <<'EOF_LABSTEWARD_SCHEMA'\n"
      cat "${project_root}/schemas/config.schema.json"
      printf "EOF_LABSTEWARD_SCHEMA\n"
      ;;
    "# LABSTEWARD_INSTALL_SERVICE")
      printf "cat >/etc/systemd/system/labsteward.service <<'EOF_LABSTEWARD_SERVICE'\n"
      cat "${project_root}/src/labsteward.service"
      printf "EOF_LABSTEWARD_SERVICE\nchmod 0644 /etc/systemd/system/labsteward.service\n"
      ;;
    *) printf '%s\n' "$line" ;;
  esac
done <"$template" >"$temporary"

bash -n "$temporary"
if ((check_only)); then
  cmp -s "$temporary" "$output" || {
    echo "install/labsteward-install.sh is stale; run: bash tools/build-artifacts.sh" >&2
    exit 1
  }
  echo "Generated artifacts are current."
else
  install -m 0755 "$temporary" "$output"
  echo "Generated install/labsteward-install.sh"
fi
