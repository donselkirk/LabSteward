# Proxmox write-executor design

The Proxmox API plugin is intentionally audit-only. Lifecycle changes, storage
configuration, mount mappings, and Community Scripts need a separate host-side
security boundary because the latter require a root shell on a Proxmox host.

## Proposed permissions

- `guests.lifecycle`: start, clean shutdown, reboot, and stop one explicit guest.
- `guests.configure`: change a small allowlist of CPU, memory, on-boot, and
  protection settings. It does not expose the complete guest configuration.
- `shares.map`: attach or detach a named, administrator-defined share from one
  explicit LXC mount slot. Callers cannot supply host paths or mount options.
- `installers.run`: execute one enabled recipe ID at one reviewed commit and
  SHA-256 digest. It cannot accept a URL or script body from a caller.

Destruction, restore, snapshot deletion, arbitrary guest execution, host package
changes, and raw shell access remain separate and out of scope.

## Trust model

Each managed host would run a minimal root-owned executor with a forced-command
transport. LabSteward sends a small versioned JSON request containing only an
operation, target guest, recipe/share ID, parameters from that recipe's schema,
an expiry, and a unique request ID. The executor independently verifies:

1. LabSteward's dedicated key and source address.
2. Request schema, size, expiry, and replay protection.
3. That its host is not the host running LabSteward.
4. That the operation, guest, share, and recipe are locally enabled.
5. That downloaded recipe bytes match an administrator-approved digest.
6. That a conflicting Proxmox task is not active.

Results contain only a task ID, bounded state, timestamps, and sanitized error
category. Installer stdout/stderr and secrets are never returned to an AI client.

## Trusted installer registry

Community Scripts and custom projects use the same recipe format. A recipe pins
the repository, commit, script path, SHA-256 digest, supported Proxmox versions,
parameter schema, expected guest type, and rollback guidance. Adding or updating
a recipe is an administrator action at the LabSteward console; clients can only
select already enabled recipe IDs. Floating branches, `curl | shell`, redirects,
and caller-provided environment variables are rejected.

The first implementation should support a disposable test host only. Validation
must cover failed downloads, checksum mismatch, timeout, replay, partial install,
conflicting IDs, rollback, and the self-host mutation prohibition before any
production host enables write permissions.
