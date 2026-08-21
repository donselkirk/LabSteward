# Remote access

LabSteward's first remote milestone deliberately provides only `core_status`.
It proves that an AI client can reach and authenticate to the appliance without
giving the appliance access to Proxmox, UniFi, Synology, or any other server.

## Impact and prerequisites

Enabling remote enrollment opens two TLS listeners on one explicitly configured
LXC address: MCP on port 9443 and the administrator/OAuth interface on port
9444 by default. LabSteward does not alter host, router,
Proxmox, or LXC firewall rules. Before enabling it:

- Reserve a stable gateway address and confirm routing from the intended client.
- Restrict any network firewall rule to the client's fixed address where
  practical.
- Run `stewctl validate` and `stewctl action run core.status` successfully.
- Decide whether clients will use the gateway IP or an internal DNS name, and
  include every chosen name when creating the certificate.
- Define narrow administrator and enrollment source networks.
- Use one LabSteward client identity per physical or automation client.

## Appliance setup

Use real values only at the appliance console. These examples use IANA
documentation addresses and names.

```text
stewctl transport tls create --host 192.0.2.211 --host labsteward.example
stewctl transport configure --bind 192.0.2.211 --host labsteward.example --port 9443
stewctl admin tls create --host 192.0.2.211 --host labsteward.example
stewctl admin bootstrap --username steward
stewctl admin configure --bind 192.0.2.211 --host labsteward.example \
  --admin-source 192.0.2.0/24 --enrollment-source 192.0.2.0/24
stewctl transport enable
stewctl admin enable
stewctl transport status
stewctl admin status
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

Configure a Streamable HTTP MCP server:

```toml
[mcp_servers.labsteward]
url = "https://labsteward.example:9443/mcp"
auth = "oauth"
required = true
default_tools_approval_mode = "prompt"
enabled_tools = ["core_status"]
```

Restart Codex after changing its MCP configuration, then select **Authenticate**
in desktop or IDE settings or run `codex mcp login labsteward`. Sign in to the
LabSteward administrator page and review the client name, observed source,
callback, and proposed `/32` or `/128` restriction before selecting **Trust
client**. The connected tool list must contain exactly `core_status` before
plugins exist.

## End-to-end validation

Ask the local AI client to use LabSteward to report its core status. A valid
response contains only status and version, plugin/server/client counts, and
whether remote transport is configured.

Revoke the client in the administrator interface and confirm the MCP call stops
working immediately. Re-approve it and confirm a fresh browser flow is needed.

Useful appliance checks are:

```text
stewctl transport status
stewctl validate
journalctl -u labsteward.service --no-pager
journalctl -u labsteward-admin.service --no-pager
journalctl -u labsteward-broker.service --no-pager
```

Audit events record the client ID and socket source but never tokens, request
authorization headers, tool arguments, action results, or protected files.

## Rollback and revocation

Stopping remote access is immediate and does not affect local administration:

```text
stewctl transport disable
stewctl admin disable
stewctl client revoke desktop --yes
```

Remove the LabSteward CA certificate and the stored MCP OAuth login from the
client. Network firewall rules created outside LabSteward must be
rolled back separately. The transport configuration and protected TLS files are
retained for inspection; deleting or replacing them is intentionally not part
of `transport disable`.
