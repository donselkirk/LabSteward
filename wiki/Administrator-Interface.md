# Administrator interface

The LabSteward administrator interface is an optional, source-restricted web
application served over TLS on port 9444 by default. It is disabled until the
console administrator separately creates its TLS key, bootstraps the first
account, configures source networks, and enables both administrator services.

## Available controls

- Clients is the main page. It shows authentication type, source restrictions,
  and immediate revocation. Each client explicitly adds only the servers it needs;
  a server cannot be added twice. Assigned server rows are collapsed by default.
  Expanding a row shows vertically arranged plugin capabilities, descriptions and
  tooltips, and consistent Off, Read, and Write selectors. All-Off keeps the server
  assigned with no operational access. Source changes revoke active access tokens.
- Servers is a separate page for registration, plugin-specific write-only access
  configuration, and removal. Removing a server also removes it from every client.
- Plugins is a separate page showing the release catalogue, installed state,
  declared permission vocabulary, descriptions, and fixed install/remove actions.
  Synology, UniFi Network, and audit-only Proxmox VE are available. A plugin cannot be
  removed while a registered server uses it.
- Revoking a client immediately invalidates its tokens and removes it from the
  registry and client list. A hidden non-secret generation tombstone prevents an
  old refresh token from becoming valid if the same client name is later approved.
- The broker still rejects duplicate assignments, dangling grants, and cross-plugin
  permissions regardless of what a browser submits.

Credential forms are deliberately absent. For a Synology server, Configure
access displays the exact `stewctl server credentials set` command to run at the
appliance terminal. Synology prompts for DSM credentials; UniFi prompts for an
official Network API key and site UUID; Proxmox prompts for an audit-only token
ID, token secret, and API node name. No browser request or administrator
response accepts or retrieves a stored server credential.

## Authentication and recovery

There is no default administrator. Run `stewctl admin bootstrap --username
NAME` at the LXC console. The password is read without echo, confirmed, and
stored as a salted scrypt verifier. It is never accepted as a command-line
argument, environment variable, URL, or browser bootstrap value.

If access is lost, use the LXC console and repeat bootstrap with `--force --yes`.
This deliberate recovery path avoids remotely exploitable reset links. Passkeys
and TOTP are deferred until stable internal DNS and recovery behavior are
designed and tested.

## Browser protections

Administrator routes require an allowed socket source, an authenticated
source-bound session, exact Origin validation for changes, and a per-session
CSRF value. Cookies are Secure, HttpOnly, SameSite=Strict, and expire after
fifteen idle minutes. Responses disable framing, MIME sniffing, referrers,
sensitive browser permissions, caching, and all content sources except the
same-origin stylesheet and forms.

## Rollback

`stewctl admin disable` stops browser enrollment without stopping an already
configured MCP listener. Legacy bearer clients remain available during the
v0.2 migration. A release rollback restores the earlier immutable runtime
files and service units; administrator state and protected TLS material remain
for inspection rather than being silently deleted.

Appliances on v0.1.0-v0.1.2 must first apply the updater-only v0.1.3 bridge.
That bridge retains the previous runtime and installs only an updater that
understands the expanded v0.2.0 bundle. Skipping it causes the older updater to
reject the incomplete transition before changing files. Apply the pinned bridge
and then return to the normal release channel:

```bash
LABSTEWARD_UPDATE_BASE_URL=https://github.com/donselkirk/LabSteward/releases/download/v0.1.3 stewctl update apply
LABSTEWARD_UPDATE_BASE_URL=https://github.com/donselkirk/LabSteward/releases/latest/download stewctl update apply
```
