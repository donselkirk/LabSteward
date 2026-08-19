#!/usr/bin/env bash
set -Eeuo pipefail

state_file="${LABSTEWARD_TEST_SYSTEMCTL_STATE:?missing test systemctl state}"
command_name="${1:-}"
case "$command_name" in
  daemon-reload)
    exit 0
    ;;
  is-active)
    if [[ -r "$state_file" && "$(<"$state_file")" == "active" ]]; then
      [[ "${2:-}" == "--quiet" ]] || printf 'active\n'
      exit 0
    fi
    [[ "${2:-}" == "--quiet" ]] || printf 'inactive\n'
    exit 3
    ;;
  enable|restart)
    printf 'active\n' >"$state_file"
    ;;
  disable)
    printf 'inactive\n' >"$state_file"
    ;;
  *)
    printf 'unsupported mock systemctl command: %s\n' "$command_name" >&2
    exit 2
    ;;
esac
