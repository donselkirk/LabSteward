# Architecture

LabSteward separates six concerns:

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

Plugin installation does not grant access to a server. Registering a server
does not grant permissions. Granting permissions does not create credentials.
Each transition is explicit and independently auditable.

## Remote client boundary

Remote access is disabled until a transport is explicitly configured. Every
remote client has a unique high-entropy token, one or more source IP/CIDR
restrictions, and per-server permission grants. Client grants must be a subset
of the server's plugin permissions. New clients begin with no server grants.

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
Future plugin actions must satisfy both the server permission set and the
calling client's subset grant.

Administrative commands are:

```text
stewctl client add CLIENT --source IP_OR_CIDR
stewctl client list
stewctl client source set CLIENT IP_OR_CIDR ...
stewctl client permission set CLIENT SERVER PERMISSION ...
stewctl client rotate-token CLIENT
stewctl client revoke CLIENT --yes
```

Tokens are shown once during local client creation or rotation. Plaintext tokens
are never stored by LabSteward; only a verifier readable by the unprivileged
runtime is retained inside the LXC.

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

## Planned plugin package contract

Every plugin release will contain a manifest declaring its ID, version, core
API range, server configuration schema, named permissions, tool names, and
runtime entry point. The core installer will reject unknown files, unsafe
paths, incompatible versions, undeclared permissions, and checksum failures.

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
