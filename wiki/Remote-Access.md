# Remote access

LabSteward's first remote milestone deliberately provides only `core_status`.
It proves that an AI client can reach and authenticate to the appliance without
giving the appliance access to Proxmox, UniFi, Synology, or any other server.

## Impact and prerequisites

Enabling the transport opens a TLS listener on one explicitly configured LXC
address and port (9443 by default). LabSteward does not alter host, router,
Proxmox, or LXC firewall rules. Before enabling it:

- Reserve a stable gateway address and confirm routing from the intended client.
- Restrict any network firewall rule to the client's fixed address where
  practical.
- Run `stewctl validate` and `stewctl action run core.status` successfully.
- Decide whether clients will use the gateway IP or an internal DNS name, and
  include every chosen name when creating the certificate.
- Use one LabSteward client identity and token per physical or automation client.

## Appliance setup

Use real values only at the appliance console. These examples use IANA
documentation addresses and names.

```text
stewctl transport tls create --host 192.0.2.211 --host labsteward.example
stewctl transport configure --bind 192.0.2.211 --host labsteward.example --port 9443
stewctl client add desktop --source 192.0.2.40/32
stewctl transport enable
stewctl transport status
stewctl transport test
```

`transport test` proves that the local TLS listener is reachable and rejects an
unauthenticated request. It does not pretend to validate routing, client-side
trust, token delivery, or source-address handling from the desktop.

## Client setup

Transfer only `/etc/labsteward/secrets/tls/labsteward-ca.crt` to the client.
Never copy either private key. Verify the SHA-256 fingerprint printed during
certificate creation using a separate authenticated channel, then install the
CA certificate in the client's operating-system trust store.

Store the one-time client token in a protected environment variable available
to the local Codex process:

```text
LABSTEWARD_TOKEN=<token shown once by stewctl>
```

Configure a Streamable HTTP MCP server:

```toml
[mcp_servers.labsteward]
url = "https://labsteward.example:9443/mcp"
bearer_token_env_var = "LABSTEWARD_TOKEN"
required = true
default_tools_approval_mode = "prompt"
enabled_tools = ["core_status"]
```

Restart Codex after changing its MCP configuration. The connected tool list
must contain exactly `core_status` before plugins exist.

## End-to-end validation

Ask the local AI client to use LabSteward to report its core status. A valid
response contains only status and version, plugin/server/client counts, and
whether remote transport is configured.

Then rotate the client token and confirm the old token stops working. Do not put
either token in logs, shell history, screenshots, issues, or the repository.

Useful appliance checks are:

```text
stewctl transport status
stewctl validate
journalctl -u labsteward.service --no-pager
```

Audit events record the client ID and socket source but never tokens, request
authorization headers, tool arguments, action results, or protected files.

## Rollback and revocation

Stopping remote access is immediate and does not affect local administration:

```text
stewctl transport disable
stewctl client revoke desktop --yes
```

Remove the LabSteward CA certificate from the client trust store and remove its
local token variable. Network firewall rules created outside LabSteward must be
rolled back separately. The transport configuration and protected TLS files are
retained for inspection; deleting or replacing them is intentionally not part
of `transport disable`.
