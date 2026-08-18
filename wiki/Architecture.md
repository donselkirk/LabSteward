# Architecture

LabSteward separates five concerns:

1. The Community Scripts-style bootstrap creates an unprivileged Debian LXC.
2. The root-only `labsteward` manager installs verified core and plugin releases.
3. Plugin code under `/opt/labsteward/plugins` implements one resource family.
4. Non-secret server registrations bind aliases to one plugin and explicit
   permissions.
5. The unprivileged runtime reads only the configuration and credential files
   it needs and exposes sanitized, allowlisted operations over a separately
   hardened transport.

Plugin installation does not grant access to a server. Registering a server
does not grant permissions. Granting permissions does not create credentials.
Each transition is explicit and independently auditable.

## Planned plugin package contract

Every plugin release will contain a manifest declaring its ID, version, core
API range, server configuration schema, named permissions, tool names, and
runtime entry point. The core installer will reject unknown files, unsafe
paths, incompatible versions, undeclared permissions, and checksum failures.

Plugins are code and therefore share the gateway's trust boundary. Process
isolation between plugins may be added later, but it must not be presented as
a security boundary until it is tested and enforced.
