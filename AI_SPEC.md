# LABSteward application specification

This document is the implementation contract for LABSteward. It describes the
application as if it were being built from scratch, including its purpose,
security boundaries, interfaces, tests, operational behavior, and roadmap.

## 1. Product definition

LABSteward is a security boundary for AI clients and automation scripts that
need narrowly scoped, sanitized access to home-lab resources. It runs inside a
dedicated Proxmox LXC and mediates access through fixed, reviewed plugin
actions. It is not a general shell, proxy, credential store, host-management
backdoor, or arbitrary URL fetcher.

The product name is **LABSteward**. Technical identifiers remain lowercase
`labsteward` for compatibility. The operator command is `stewctl`.

Goals:

- provide safe, predefined resource actions to AI/MCP clients;
- keep credentials inside the appliance;
- enforce client source restrictions and explicit server grants;
- sanitize every returned and logged result;
- make releases reproducible, checksummed, rollback-safe, and self-updatable.

Non-goals:

- arbitrary commands or scripts;
- unrestricted SSH, HTTP proxying, or URL retrieval;
- storing credentials in source, releases, prompts, or browser responses;
- allowing LABSteward to modify the host node that runs it;
- silently changing infrastructure without explicit permission.

## 2. Security invariants

These invariants are release-blocking requirements:

1. Credentials remain under `/etc/labsteward/secrets` inside the LXC.
2. Deployed code and plugin packages are root-owned and immutable to service
   accounts.
3. The core and MCP services run as the non-login `labsteward` account.
4. The administrator runs as the separate non-login `labsteward-admin` account.
5. Registry mutations cross only the group-restricted local broker socket.
6. Client access requires a registered identity and an allowed source address.
7. OAuth is the supported client model; legacy bearer clients are migration-only.
8. Browser mutations require HTTPS, an allowed admin source, a source-bound
   session, CSRF protection, and browser-origin checks where applicable.
9. Every plugin action is fixed, bounded, permission-checked, and sanitized.
10. No action may mutate the LABSteward host node.
11. Logs and errors never contain secrets or unapproved infrastructure details.
12. Updates verify assets before replacement and automatically roll back after
    failed validation.

## 3. Architecture

The appliance contains these components:

- **Core**: fixed registry and action dispatcher.
- **MCP transport**: TLS listener, client authentication, source checks, and
  sanitized MCP responses.
- **Administrator**: TLS browser UI, login, OAuth enrollment, and presentation.
- **Broker**: root-owned local service that performs the fixed registry writes
  requested by the administrator.
- **Plugins**: immutable reviewed adapters for a resource family.
- **Catalog**: approved plugin metadata, permissions, descriptions, and versions.
- **Updater**: checksum-verified release replacement and rollback helper.
- **Logger**: structured sanitized runtime/audit event writer and reader.

Protected locations:

- `/opt/labsteward`: immutable runtime, catalog, schemas, and plugins;
- `/etc/labsteward/config.json`: non-secret registry configuration;
- `/etc/labsteward/secrets`: server credentials, client verifiers, TLS material;
- `/var/lib/labsteward`: runtime state;
- `/var/log/labsteward`: current and archived sanitized logs;
- `/etc/labsteward-admin`: admin configuration and credential verifier;
- `/var/lib/labsteward-admin`: OAuth state.

## 4. Data contracts

The configuration schema is version 1 in `schemas/config.schema.json`.

Top-level registries are `plugins`, `servers`, and `clients`.

- Plugin IDs match `^[a-z][a-z0-9-]{0,31}$`.
- Server aliases match `^[a-z][a-z0-9._-]{0,63}$`.
- Client IDs match `^[a-z][a-z0-9-]{0,31}$`.
- Server endpoints are HTTPS origins without credentials, paths, queries, or
  fragments.
- Client sources are one or more bounded IP/CIDR restrictions.
- Grants map a registered server to declared permission levels: `read` or
  `write`; an absent permission is `off`.

Plugin manifests declare the plugin ID, version, core API, entrypoint,
permissions, and fixed actions. The catalog and manifest must agree exactly.

## 5. CLI contract

The manager requires root and returns exit code 0 on success and 2 for safe
user/configuration errors.

Primary commands include:

```text
stewctl version
stewctl status
stewctl validate
stewctl configure
stewctl update
stewctl update check
stewctl update apply          # compatibility alias
stewctl self-update           # deprecated compatibility alias
stewctl plugin list|install|remove
stewctl server list|add|remove|credentials set|credentials remove
stewctl client list|revoke|source set|permission set|server add|server remove
stewctl action run <fixed-action> [scoped arguments]
stewctl transport status|enable|disable|restart|test|configure|tls create
stewctl admin status|enable|disable|bootstrap|configure|tls create
stewctl logs [--archive YYYY-MM-DD]
```

`stewctl update` applies the latest public release. `stewctl update check` is
non-mutating. Updates preserve configuration, credentials, TLS material,
grants, and logs.

## 6. MCP and OAuth

The MCP listener is TLS-only and exposes only catalogued fixed actions. Every
request is checked against the client identity, source restriction, server
grant, plugin permission, action argument allowlist, and output sanitizer.

OAuth uses authorization code with PKCE S256, loopback redirect URIs, short
authorization-code lifetime, rotating refresh tokens, bounded access-token
lifetime, source-bound approval, and revocation generations.

Required OAuth endpoints are:

```text
/.well-known/oauth-authorization-server
/oauth/register
/authorize
/oauth/token
/oauth/revoke
```

No endpoint accepts or returns server credentials.

## 7. Administrator UI

The UI is served over configured HTTPS on port 9444 and is disabled until the
administrator is bootstrapped and enabled.

Pages:

- **Clients**: OAuth enrollment, source restrictions, revoke/remove, server
  assignments, and collapsed permission rows.
- **Servers**: add/remove servers, plugin selection, and terminal-only access
  setup guidance.
- **Plugins**: catalog status, install/remove, declared capabilities, and
  package integrity state.
- **Logs**: current-runtime events and bounded archived-log browsing.

All lists use consistent top alignment and right-aligned Save/action controls.
Permission controls are vertical, tooltip-described, and expose Off/Read/Write.

## 8. Logging contract

Events are JSONL records containing UTC time, type, severity, component, runtime
ID, sanitized message, and bounded safe fields.

- `current.jsonl` contains events from the current appliance runtime.
- `archive/YYYY-MM-DD.jsonl` contains closed daily events.
- Previous current logs are archived at startup.
- Rotation occurs after a calendar-day transition.
- Archives older than 30 days are pruned.
- File size, event count, and read result limits are enforced.

Events cover authentication, authorization, registry changes, plugin outcomes,
service failures, update lifecycle, rollback, rotation, and pruning.

Raw journals, payloads, tokens, credentials, private keys, cookies, CSRF data,
credential-bearing URLs, raw plugin results, and unapproved network details are
never logged or displayed.

## 9. Update and release contract

GitHub Actions validates pull requests and main. A manual release workflow
builds a semantic-versioned bundle from the exact commit, publishes checksummed
assets, and independently downloads and verifies them after publication.

The LXC updater:

1. downloads public release metadata and checksums;
2. validates version, compatibility, completeness, and checksums;
3. creates a rollback snapshot;
4. replaces immutable runtime files only;
5. reloads systemd and restarts previously active affected services;
6. validates registry, transport, services, plugins, and packages;
7. restores the prior runtime and service state on failure;
8. logs the result without exposing protected data.

GitHub Actions never connects to the live LXC. Manual SSH deployment is not a
supported release path.

## 10. Testing contract

Every release must pass mocked tests for CLI behavior, installation, services,
admin/OAuth, broker operations, MCP authentication, plugin actions, sanitizing,
logs, updater success/failure/rollback, release bundles, and UI states.

Fixtures use synthetic addresses, names, credentials, responses, and secrets.
Tests assert that forbidden values never appear in returned data, HTML, errors,
logs, release assets, or documentation.

Acceptance requires a disposable appliance update and rollback smoke test in CI.

## 11. Feature status and roadmap

Implemented: core health, TLS MCP transport, administrator UI, OAuth enrollment,
client/server/plugin registry controls, Synology read-only actions, UniFi
scoped actions, Proxmox audit-only actions, sanitization, checksummed releases,
rollback scaffolding, and structured logging foundations.

Expected next: complete admin/broker lifecycle coverage, full Logs page,
automatic service validation after updates, public release workflow, and exact
AI-spec consistency checks.

Planned separately: Proxmox write executor, trusted community-script recipes,
container lifecycle actions, share mapping, and additional authentication factors.
Each planned feature requires a rationale, prerequisites, security impact,
permission model, tests, and acceptance criteria before implementation.

## 12. AI operating rules

An AI working on LABSteward must inspect `AGENTS.md`, this specification, the
schemas, catalog, manifests, tests, and release metadata before changing code.
It must distinguish read-only diagnostics from mutations, request authorization
for live changes, preserve credential and host-node boundaries, sanitize all
results, use mocked tests, and document rollback impact.

It must never invent permissions, accept arbitrary commands/URLs, expose secrets,
use live infrastructure as an unmocked test fixture, or treat an undocumented
feature as implemented.

## 13. Specification validation

CI must fail on both inconsistency and coverage gaps. It must compare this file
with the config schema, plugin catalog/manifests, CLI parser, MCP action catalog,
service units, updater asset lists, log constants, tests, and workflows.

CI must also require documentation for every command, route, action, permission,
schema field, service, log event, and workflow. Implemented features cannot be
marked planned; planned features require rationale, prerequisites, security
impact, tests, and acceptance criteria; and all user-facing branding must use
**LABSteward**.

