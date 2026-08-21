# Changelog

## Unreleased

- Add standards-based OAuth browser enrollment for MCP clients using dynamic
  client registration, authorization code with PKCE S256, protected-resource
  discovery, short-lived access tokens, rotating refresh tokens, and immediate
  revocation.
- Add console-only administrator bootstrap plus a source-restricted TLS web
  interface for client approval, client revocation/source controls, server
  registration, and server/client permission management.
- Add a separately sandboxed `labsteward-admin` account and a root-owned,
  AF_UNIX-only fixed-operation broker so the network service cannot edit
  deployed code or execute arbitrary commands.
- Preserve legacy bearer-token clients during migration while preventing old
  OAuth refresh tokens from becoming valid after client re-approval.
- Extend installation, self-update, rollback, generated-artifact, and
  end-to-end adversarial checks for the complete OAuth/admin runtime bundle.
- Add a separately checksummed v0.1.3 updater-bridge builder for appliances
  whose earlier updater cannot install the expanded v0.2.0 runtime atomically.
- Make pre-bridge updaters reject direct v0.2.0 attempts before changing files,
  and require empty release output directories to prevent stale asset uploads.
- Make Clients the main administration page and move Servers and Plugins to
  dedicated pages. Clients explicitly add unique servers, edit vertically arranged
  and described Off/Read/Write permissions in collapsed rows, and remove servers
  independently. Server removal cascades through all clients, while client
  revocation removes the visible record without allowing old refresh-token reuse.

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
