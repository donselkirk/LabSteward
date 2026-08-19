# LabSteward

LabSteward creates a dedicated, unprivileged Proxmox LXC for narrowly scoped
home-lab management integrations. The appliance is administered with one
`stewctl` command. Plugins, managed servers, credentials, and permission grants
are deliberately separate.

This repository is an early core-appliance scaffold. Proxmox, UniFi, and
Synology appear in the catalog as planned plugins; their runtime adapters and
credential workflows are intentionally not included yet.

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
stewctl status
stewctl validate
stewctl self-update
```

`labsteward` is installed as a compatibility and discoverability alias for
`stewctl`.

Plugin installation will only accept named entries from the checksummed release
catalog. It will never accept an arbitrary URL. Credential entry will be added
with each plugin and will read secrets from a terminal or standard input, never
from command-line arguments.

Client creation generates a high-entropy token and displays it once to the local
administrator. Only its SHA-256 verifier is stored inside the LXC. A new client
has no server permissions until they are explicitly granted.

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
- Transport is configured separately; the appliance creates no application
  listener during initial bootstrap. `stewctl status` validates the core without
  requiring any installed plugins or registered servers.

## Development

```bash
bash tools/fetch-community-helpers.sh
bash tools/build-artifacts.sh
bash tests/static-checks.sh
bash tests/manager-behavior.sh
bash tests/self-update-behavior.sh
```

Local checks do not replace installation testing on a disposable Proxmox node.
