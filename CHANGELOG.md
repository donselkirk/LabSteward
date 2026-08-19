# Changelog

## Unreleased

- Add a shared, allowlisted action dispatcher with plugin-free `core.status`
  local execution and the remote `core_status` MCP tool.
- Add an authenticated TLS-only Streamable HTTP MCP service with per-client
  token and source-address checks, rate limiting, controlled audit events, Host
  validation, and browser-Origin rejection.
- Add private-CA certificate creation and explicit transport configure, enable,
  disable, restart, status, and local security-test commands.
- Add a locked-down systemd service running as the non-login `labsteward`
  account.
- Extend checksummed releases and rollback-safe self-updates to carry the MCP
  service, dispatcher, and systemd unit.
- Add end-to-end protocol and rejection tests without adding resource plugins.
