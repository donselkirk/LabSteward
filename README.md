# LabSteward

LabSteward creates a dedicated, unprivileged Proxmox LXC for narrowly scoped
home-lab management integrations. The appliance is administered with one
`stewctl` command. Plugins, managed servers, credentials, and permission grants
are deliberately separate.

The core appliance includes a TLS-only Streamable HTTP MCP endpoint and one
built-in, read-only `core_status` tool. This proves that a local AI client can
authenticate to the gateway before any infrastructure plugin is installed.
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
stewctl permission set pve1 audit.node audit.lxc audit.storage
stewctl client add automation1 --source 192.0.2.40/32
stewctl client permission set automation1 pve1 audit.node audit.lxc
stewctl client source set automation1 192.0.2.40/32
stewctl client rotate-token automation1
stewctl client revoke automation1 --yes
stewctl action run core.status
stewctl transport tls create --host 192.0.2.211 --host labsteward.example
stewctl transport configure --bind 192.0.2.211 --host labsteward.example
stewctl transport enable
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
stewctl client add desktop --source 192.0.2.40/32
stewctl transport enable
stewctl transport test
```

The client token is shown once. Store it in a protected client-side environment
variable, never in this repository or directly in Codex configuration. Copy the
displayed CA certificate through an authenticated channel, verify its printed
SHA-256 fingerprint separately, and add it to the client's trusted CA store.

Codex Desktop, CLI, and the IDE extension can then use their shared MCP
configuration:

```toml
[mcp_servers.labsteward]
url = "https://labsteward.example:9443/mcp"
bearer_token_env_var = "LABSTEWARD_TOKEN"
required = true
default_tools_approval_mode = "prompt"
enabled_tools = ["core_status"]
```

The client does not run another MCP server. LabSteward is the MCP server and the
local AI application is its MCP client. An enabled registered client may call
`core_status` without a server grant because the action only reports an
allowlisted appliance summary and never contacts a managed server. Plugin tools
will additionally require per-server grants.

See [Remote access](wiki/Remote-Access.md) for prerequisites, validation,
security behavior, and rollback.

Plugin installation will only accept named entries from the checksummed release
catalog. It will never accept an arbitrary URL. Credential entry will be added
with each plugin and will read secrets from a terminal or standard input, never
from command-line arguments.

Client creation generates a high-entropy token and displays it once to the local
administrator. Only its SHA-256 verifier is stored inside the LXC. A new client
has no server permissions until they are explicitly granted.

`stewctl update check` reads only release version metadata and never creates a
rollback copy. `stewctl update apply` downloads and verifies all release assets
before creating a rollback copy or replacing core files. The `stewctl
self-update` command remains as a compatibility alias for applying an update.
Private GitHub releases are intentionally unsupported by the unauthenticated
updater; use reviewed manual upgrades until the repository becomes public.

## Security boundaries

- Release and plugin code is installed under `/opt/labsteward`, owned by root, and
  not writable by the runtime service account.
- Non-secret configuration is stored in `/etc/labsteward/config.json`.
- Credential files live under `/etc/labsteward/secrets` and are excluded from
  releases, logs, exports, and command output.
- The runtime account has no interactive login and cannot install or update
  plugins.
- A server registration names one plugin and an explicit permission set.
- Remote clients require both a source IP/CIDR match and a unique token. Their
  permissions must be a subset of the permissions already granted to a server.
- Revoking a client disables its grants and removes its stored token verifier.
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
bash tests/self-update-behavior.sh
```

Local checks do not replace installation testing on a disposable Proxmox node.
