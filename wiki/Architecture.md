# Architecture

LabSteward separates eight concerns:

1. The Community Scripts-style bootstrap creates an unprivileged Debian LXC.
2. The root-only `stewctl` manager installs verified core and plugin releases.
3. Plugin code under `/opt/labsteward/plugins` implements one resource family.
4. Non-secret server registrations bind aliases to one plugin and explicit
   permissions.
5. A shared dispatcher exposes only named actions with fixed input and output
   schemas.
6. The unprivileged runtime reads only the configuration and token verifiers it
   needs and exposes sanitized, allowlisted operations over TLS-only Streamable
   HTTP MCP.
7. A separate unprivileged administrator service handles browser sessions,
   OAuth enrollment, authorization codes, and rotating refresh tokens.
8. An AF_UNIX-only root broker accepts a closed set of validated registry
   operations from the administrator account. It cannot execute commands,
   retrieve arbitrary files, or fetch URLs.

Plugin installation does not grant access to a server. Registering a server
does not grant permissions. Granting permissions does not create credentials.
Each transition is explicit and independently auditable.

## Remote client boundary

Remote access is disabled until a transport is explicitly configured. Every
remote client has a unique cryptographic identity, one or more source IP/CIDR
restrictions, and per-server permission grants. Every capability has an Off,
Read, or Write level. A client sees only servers explicitly assigned to it, and
only capabilities declared by that server's plugin. New clients begin with no
managed servers.

The transport obtains the source address from the authenticated socket peer,
never an untrusted forwarding header, and requires TLS 1.2 or newer. It verifies
token hashes using constant-time comparison, rate-limits socket sources, audits
authentication failures without recording tokens, and passes accepted requests
through the same dispatcher used by local commands. It rejects browser Origin
headers and Host values outside the configured allowlist as DNS-rebinding
defenses. Revocation disables the client and removes its stored token verifier.
Mutual TLS may be added as an optional stronger client identity layer, but it
does not replace source restrictions or action grants.

The initial remote action is `core_status`. Every enabled client can call it
because it contacts no managed resource and returns only a fixed appliance
summary. It does not weaken the separate server and plugin permission model.
Future plugin actions must declare whether they read or mutate state and satisfy
the calling client's level for the assigned server. Removing a server cascades
through all client grants.

Administrative commands are:

```text
stewctl client add CLIENT --source IP_OR_CIDR
stewctl client list
stewctl client source set CLIENT IP_OR_CIDR ...
stewctl client permission set CLIENT SERVER PERMISSION ...
stewctl client rotate-token CLIENT
stewctl client revoke CLIENT --yes
```

OAuth is the preferred client identity. Access tokens expire after ten minutes;
refresh tokens last up to thirty days and rotate on every use. Authorization
codes are one-time, expire after two minutes, and require PKCE S256. Only token
hashes are persisted. A per-client authentication generation prevents refresh
tokens issued before revocation from becoming useful after later re-approval.
The original one-time bearer tokens remain temporarily supported for migration.

Transport administration is separately explicit:

```text
stewctl transport tls create --host IP_OR_DNS [--host IP_OR_DNS ...]
stewctl transport configure --bind IP [--host DNS_NAME] [--port 9443]
stewctl transport enable
stewctl transport status
stewctl transport test
stewctl transport restart
stewctl transport disable
```

Certificate creation produces a private CA, a leaf server certificate, and
protected private keys inside `/etc/labsteward/secrets/tls`. Only the CA
certificate is exported to clients. Replacing TLS material requires the
deliberate `--force --yes` combination and client trust must then be updated.

## Administrator boundary

The first administrator is created only from the LXC console with `stewctl
admin bootstrap`. There is no default account, remote bootstrap, email reset,
or recovery token. Recovery requires console access. Passwords are stored only
as salted scrypt verifiers.

The administrator listener is separately configured, source-restricted, and
disabled by default. It uses a distinct leaf key under
`/etc/labsteward-admin`, signed by the same private CA. Browser sessions are
source-bound, idle-expiring, Secure, HttpOnly, and SameSite=Strict. State-changing
forms require an unguessable CSRF value and an exact Origin match.

The `labsteward-admin` process cannot write `/etc/labsteward` or
`/opt/labsteward`. Registry mutations cross a group-restricted Unix socket to
the root broker. Peer credentials are checked with `SO_PEERCRED`, every request
uses a fixed operation name and bounded JSON schema, and no operation accepts a
command, filesystem path, or arbitrary fetch target.

## Core health check

`stewctl status` validates the configuration registries, plugin catalog,
dispatcher, MCP service code, service unit, sanitizer, client token metadata
protections, and cross-scope permission relationships. It requires no plugins,
servers, clients, credentials, or remote transport, so a fresh default
installation can verify its core independently. `stewctl action run core.status`
then validates the same dispatcher used by the MCP service.

## Core updates

`stewctl update check` downloads only version metadata and does not create a
rollback directory or modify installed files. Applying an update downloads and
checksum-verifies the complete core asset set before creating a rollback copy.
Failed validation restores the previous files, and every exit path removes its
temporary staging and rollback directories.

The updater is deliberately unauthenticated and does not accept repository
tokens through arguments or environment variables. Private GitHub releases
therefore produce a clear unavailable-source result and require a reviewed
manual upgrade. This avoids placing a repository credential in the appliance;
normal self-updates become available when the release source is public.

## Plugin package contract

Every plugin release contains a manifest declaring its ID, version, core API,
named capabilities with human-readable descriptions, action access levels, tool
names, and runtime entry point. The core installer rejects incompatible metadata,
catalogue mismatches, undeclared permissions, invalid entrypoints, and checksum
failures.

The initial Synology package implements this contract with two read-only
capabilities: `system.read` and `storage.read`. Its two tools accept only a
registered server alias. The core resolves that alias to the immutable endpoint,
checks the calling client's per-server grant, loads protected credentials, and
applies the shared sanitizer after the plugin's output allowlist. No caller can
supply an upstream URL, DSM API name, method, path, or arbitrary parameters.

The UniFi package follows the same model against the official local Network
integration API. Configuration, diagnostics, connected-client, and firewall
reads use fixed paths and bounded page sizes. `firewall.rules=read` exposes only
policy summaries; `firewall.rules=write` additionally permits one fixed PATCH
operation that changes only `loggingEnabled` on an explicit policy UUID. The
plugin cannot replace policy match criteria, actions, ordering, or identity, and
cannot create or delete a rule.

The Proxmox package is audit-only. It uses fixed GET endpoints for version, node
status, LXC and virtual-machine state/configuration summaries, storage status,
and recent tasks. It emits counts instead of mount and network definitions and
omits raw task logs, storage paths, worker identities, descriptions, and UPIDs.
Host mutations and third-party installer execution require a separate constrained
executor; installing the read plugin does not install or authorize that executor.

Plugins are code and therefore share the gateway's trust boundary. Process
isolation between plugins may be added later, but it must not be presented as
a security boundary until it is tested and enforced.

## Mandatory result-safety pipeline

Plugins may return only fields declared by the action's versioned output schema.
The core drops undeclared upstream fields, then recursively applies the shared
sanitizer before logging or transport serialization. The sanitizer redacts
secret-bearing field names, authorization values, cookies, private keys,
credentials embedded in URLs, and common inline token forms. It also bounds
result depth, collection size, and string length.

Raw upstream responses, response headers, configuration files, and exception
objects must never be returned directly. Sanitization is defense in depth; it
does not replace output allowlists, least-privilege upstream credentials, or
plugin-specific tests using representative sensitive fixtures.
