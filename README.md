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
Synology, UniFi Network, and audit-only Proxmox VE are available as separately
installed plugins.

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
stewctl plugin install synology
stewctl server add nas1 --plugin synology --endpoint https://nas.example.test:5001
stewctl server credentials set nas1 --ca-file /path/to/dsm-ca.crt
stewctl client add automation1 --source 192.0.2.40/32
stewctl client server add automation1 nas1
stewctl client permission set automation1 nas1 system.read=read storage.read=read
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
stewctl update
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

Plugin installation accepts only named entries whose immutable package and
manifest match the checksummed release catalog. It never accepts an arbitrary
URL. Synology credentials are read without echo at the appliance terminal and
stored under `/etc/labsteward/secrets/servers`; they are never accepted as
command-line arguments or returned by the browser, CLI, MCP transport, or logs.

## Synology read-only plugin

Install the released plugin, register one HTTPS DSM origin, and store credentials
for a dedicated least-privilege DSM account:

```text
stewctl plugin install synology
stewctl server add nas1 --plugin synology --endpoint https://nas.example.test:5001
stewctl server credentials set nas1 --ca-file /path/to/dsm-ca.crt
```

Omit `--ca-file` only when DSM presents a certificate already trusted by Debian.
The plugin provides `system.read` for model, DSM version, health, uptime,
temperature, CPU, and memory summaries, and `storage.read` for pool/volume health,
capacity, and aggregate disk counts. These permissions map to the MCP tools
`synology_system_summary` and `synology_storage_summary`. It does not expose
shares, files, filenames, hostnames, serial numbers, raw DSM responses, arbitrary
DSM API names, or write actions.

The adapter uses DSM's API discovery and session authentication flow, then makes
only its fixed system/utilization or storage read calls. DSM API login/logout is
documented in Synology's [DSM Login Web API Guide](https://kb.synology.com/en-us/DG/DSM_Login_Web_API_Guide/2).

## UniFi Network plugin

The UniFi plugin uses the official local Network integration API. Register the
console as an HTTPS origin, then enter an API key and site UUID at the appliance
terminal:

```text
stewctl plugin install unifi
stewctl server add network1 --plugin unifi --endpoint https://unifi.example.test
stewctl server credentials set network1 --ca-file /path/to/unifi-ca.crt
```

Create the key and obtain the site ID through UniFi Network's Integrations page.
Ubiquiti recommends using the documentation served by the installed Network
application because available endpoints depend on its version. See Ubiquiti's
[official API setup guidance](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)
and [Network API reference](https://developer.ui.com/network/v10.3.58).

The initial plugin provides:

- `config.read`: network/VLAN and WiFi broadcast summaries without WiFi keys.
- `diagnostics.read`: device state, firmware, CPU, memory, uptime and bounded
  findings such as offline devices or high resource utilization.
- `clients.read`: a bounded connected-client list for ID discovery plus current
  connection and access context for one explicit client UUID. The official API
  does not provide historical per-client byte totals, so these tools do not claim
  to report historical bandwidth usage.
- `firewall.rules`: Read returns sanitized policy summaries. Write permits only
  enabling or disabling syslog logging for one explicit policy UUID through the
  official partial-update endpoint.

It does not expose WiFi passphrases, MAC addresses, raw filter bodies, arbitrary
API paths, firewall allow/block changes, policy creation/deletion, or rule
reordering. Full firewall policy replacement is intentionally deferred because
the official API requires a complete policy document and does not guarantee
idempotency for every mutation.

## Proxmox VE audit plugin

The initial Proxmox plugin deliberately uses a privilege-separated audit-only
API token. Register one Proxmox HTTPS origin and enter its token and API node
name at the appliance terminal:

```text
stewctl plugin install proxmox
stewctl server add pve1 --plugin proxmox --endpoint https://pve.example.test:8006
stewctl server credentials set pve1 --ca-file /path/to/proxmox-ca.crt
```

Its seven fixed tools report bounded node utilization, LXC and virtual-machine
inventory, individual guest summaries, storage capacity, recent task outcomes,
and node/guest diagnostic findings. Output excludes API identities, raw task
logs, UPIDs, storage paths, MAC addresses, network definitions, mount sources,
descriptions, and raw API responses. The Proxmox token should have only the
minimum audit roles needed for these reads; Proxmox documents privilege-separated
API tokens in its [administration guide](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf).

Container lifecycle, share configuration, and installer execution are not part
of this audit release. Community Scripts require root shell access on the host,
so a later write release will use a separate host-side executor with fixed
operations, checksum-pinned recipes, explicit confirmations, task tracking, and
a hard prohibition on mutating the node hosting LabSteward. It will not accept
arbitrary URLs, scripts, shell text, paths, or environment variables. See the
[write-executor design](wiki/Proxmox-Write-Executor.md).

OAuth access tokens live for ten minutes and refresh tokens rotate on every use.
LabSteward persists only token hashes. Revocation removes active access tokens;
an authentication generation prevents refresh tokens from becoming valid again
if a device is later re-approved. The legacy `stewctl client add` bearer-token
flow remains available only for migration and non-OAuth clients.

`stewctl update check` reads only release version metadata and never creates a
rollback copy. `stewctl update` downloads and verifies all release assets before
creating a rollback copy or replacing core files. `stewctl update apply` and
`stewctl self-update` remain compatibility aliases during migration.
Public GitHub releases are required so the unauthenticated updater can retrieve
assets without storing a GitHub credential in the appliance.

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
- A server registration names one plugin and endpoint. Plugin server access
  credentials are configured separately at the appliance terminal; the browser
  displays the command but never accepts or retrieves credential values.
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
