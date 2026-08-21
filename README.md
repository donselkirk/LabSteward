# LabSteward

LabSteward creates a dedicated, unprivileged Proxmox LXC for narrowly scoped
home-lab management integrations. The appliance is administered with one
`stewctl` command. Plugins, managed servers, credentials, and permission grants
are deliberately separate.

The core appliance includes a TLS-only Streamable HTTP MCP endpoint, browser
enrollment through OAuth authorization code with PKCE, an administrator
dashboard, and one built-in, read-only `core_status` tool. This proves that a
local AI client can authenticate to the gateway before any infrastructure
plugin is installed.
The dashboard opens on client management, with separate Servers and Plugins pages.
Each client explicitly adds only the servers it needs, then gives every plugin
capability an Off, Read, or Write level.
Proxmox, UniFi, and Synology remain planned catalog entries; their runtime
adapters and credential workflows are intentionally not included yet.

## Intended install

Run as `root` in a Proxmox VE host shell after the first reviewed release is
published:

```bash
bash -c "$(curl -fsSL https://github.com/donselkirk/LabSteward/releases/latest/download/labsteward.sh)"
```

The default LXC is Debian 13, unprivileged, with 1 CPU, 512 MiB RAM, 512 MiB
swap, and a 5 GiB disk. Nesting is enabled because the current Debian appliance
baseline has been validated with it; keyctl remains disabled.

## Management model

```text
stewctl configure
stewctl plugin list
stewctl plugin install proxmox
stewctl server add pve1 --plugin proxmox --endpoint https://pve1.example.test:8006
stewctl client add automation1 --source 192.0.2.40/32
stewctl client server add automation1 pve1
stewctl client permission set automation1 pve1 node.status=read lxc.power=write
stewctl client source set automation1 192.0.2.40/32
stewctl client rotate-token automation1
stewctl client revoke automation1 --yes
stewctl action run core.status
stewctl transport tls create --host 192.0.2.211 --host labsteward.example
stewctl transport configure --bind 192.0.2.211 --host labsteward.example
stewctl admin tls create --host 192.0.2.211 --host labsteward.example
stewctl admin bootstrap --username steward
stewctl admin configure --bind 192.0.2.211 --host labsteward.example --admin-source 192.0.2.0/24
stewctl transport enable
stewctl admin enable
stewctl transport test
stewctl status
stewctl validate
stewctl update check
stewctl update apply
```

`labsteward` is installed as a compatibility and discoverability alias for
`stewctl`.

## Plugin-free MCP validation

Remote access is opt-in. LabSteward creates no application listener until an
administrator creates TLS material, configures a specific bind address, and
enables the service. The following examples use documentation addresses; use
real gateway and client addresses only inside the appliance and local client.

```text
stewctl transport tls create --host 192.0.2.211 --host labsteward.example
stewctl transport configure --bind 192.0.2.211 --host labsteward.example
stewctl transport enable
stewctl admin tls create --host 192.0.2.211 --host labsteward.example
stewctl admin bootstrap --username steward
stewctl admin configure --bind 192.0.2.211 --host labsteward.example --admin-source 192.0.2.0/24
stewctl admin enable
stewctl transport test
```

Copy the displayed CA certificate through an authenticated channel, verify its
printed SHA-256 fingerprint separately, and add it to the client's trusted CA
store. The private CA remains the one unavoidable trust step unless the
administrator supplies a certificate already trusted by the client.

Codex Desktop, CLI, and the IDE extension can then use their shared MCP
configuration:

```toml
[mcp_servers.labsteward]
url = "https://labsteward.example:9443/mcp"
auth = "oauth"
required = true
default_tools_approval_mode = "prompt"
enabled_tools = ["core_status"]
```

Select **Authenticate** in the desktop or IDE MCP settings, or run `codex mcp
login labsteward`. LabSteward opens an administrator sign-in and consent page.
The approval page shows the client name, observed source, callback, and proposed
source restriction. A newly approved client receives no managed-server grants.

The client does not run another MCP server. LabSteward is the MCP server and the
local AI application is its MCP client. An approved client may call
`core_status` without a server grant because the action only reports an
allowlisted appliance summary and never contacts a managed server. Plugin tools
will additionally require per-server grants.

See [Remote access](wiki/Remote-Access.md) for prerequisites, validation,
security behavior, and rollback.

Plugin installation will only accept named entries from the checksummed release
catalog. It will never accept an arbitrary URL. Credential entry will be added
with each plugin and will read secrets from a terminal or standard input, never
from command-line arguments.

OAuth access tokens live for ten minutes and refresh tokens rotate on every use.
LabSteward persists only token hashes. Revocation removes active access tokens;
an authentication generation prevents refresh tokens from becoming valid again
if a device is later re-approved. The legacy `stewctl client add` bearer-token
flow remains available only for migration and non-OAuth clients.

`stewctl update check` reads only release version metadata and never creates a
rollback copy. `stewctl update apply` downloads and verifies all release assets
before creating a rollback copy or replacing core files. The `stewctl
self-update` command remains as a compatibility alias for applying an update.
Private GitHub releases are intentionally unsupported by the unauthenticated
updater; use reviewed manual upgrades until the repository becomes public.

Existing v0.1.0-v0.1.2 appliances require the updater-only v0.1.3 bridge before
v0.2.0 because their updater recognizes only the original runtime bundle. The
bridge changes the updater without enabling OAuth or the administrator listener;
the subsequent v0.2.0 update installs and validates the complete bundle. The
bridge is not a fresh-install release. The v0.2.0 core service asset also has a
new release-bundle name, which makes a pre-bridge updater reject a direct v0.2.0
attempt as incomplete before replacing any file.

Upgrade an existing v0.1.0-v0.1.2 appliance as root with the pinned bridge first,
then return it to the normal release channel:

```bash
LABSTEWARD_UPDATE_BASE_URL=https://github.com/donselkirk/LabSteward/releases/download/v0.1.3 stewctl update apply
LABSTEWARD_UPDATE_BASE_URL=https://github.com/donselkirk/LabSteward/releases/latest/download stewctl update apply
```

## Security boundaries

- Release and plugin code is installed under `/opt/labsteward`, owned by root, and
  not writable by the runtime service account.
- Non-secret configuration is stored in `/etc/labsteward/config.json`.
- Credential files live under `/etc/labsteward/secrets` and are excluded from
  releases, logs, exports, and command output.
- The runtime account has no interactive login and cannot install or update
  plugins.
- The browser-facing administrator runs as a separate non-login account and
  cannot edit the core registry or deployed code. It reaches a root-owned local
  broker over a Unix socket; the broker implements only fixed, schema-validated
  registry operations and has no arbitrary command primitive.
- Administrator configuration and TLS keys are isolated under
  `/etc/labsteward-admin`; OAuth state is mode-0600 under
  `/var/lib/labsteward-admin`.
- A server registration names one plugin and endpoint. Server access credentials
  are configured separately through the plugin's write-only schema.
- Remote clients require both a source IP/CIDR match and a unique cryptographic
  identity. Servers must be explicitly assigned to each client, cannot be assigned
  twice, and expose only capabilities declared by their plugin. Each assigned
  capability is Off, Read, or Write.
- Legacy permission lists are interpreted as Read during upgrades; they are never
  promoted to Write automatically. CLI entries without `=LEVEL` also mean Read.
- Removing a server removes its grants from every client. Revoking a client removes
  it from the registry and UI while retaining only a non-secret authentication-
  generation tombstone that prevents old refresh-token resurrection.
- No plugin may expose arbitrary shell execution, arbitrary requests, or raw
  secret/configuration reads.
- Plugins must construct responses from explicit output-field allowlists. The
  core then recursively redacts credential fields, authorization material,
  cookies, private keys, embedded URL credentials, and common inline tokens
  before a result can be logged or returned.
- Transport is configured separately and binds only to one literal address.
  The MCP endpoint requires TLS, a valid per-client bearer token, and a match
  between the socket peer address and the client's source allowlist. Forwarded
  address headers are never trusted.
- The service rejects browser origins, unexpected Host values, oversized or
  ambiguous requests, unknown tools, and arbitrary command-shaped inputs. It
  rate-limits each socket source and writes controlled audit events without
  tokens or action results.
- The appliance creates no application listener during initial bootstrap.
  `stewctl status` and local `stewctl action run core.status` require no plugins
  or registered servers.

## Development

```bash
bash tools/fetch-community-helpers.sh
bash tools/build-artifacts.sh
bash tests/static-checks.sh
bash tests/manager-behavior.sh
python3 tests/oauth-behavior.py
bash tests/self-update-behavior.sh
bash tests/updater-bridge-behavior.sh
```

Local checks do not replace installation testing on a disposable Proxmox node.
