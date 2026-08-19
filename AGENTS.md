# LabSteward Development Guidance

LabSteward is a security boundary for home-lab management. Changes must preserve
least privilege, explicit target allowlists, immutable deployed code, protected
credentials, and sanitized results.

- Never add arbitrary shell, URL, file, or HTTP-proxy capabilities.
- Plugin packages are trusted code and must be release-pinned and checksum
  verified before installation.
- Keep plugin installation, server registration, and permission grants as
  separate administrator actions.
- The runtime account must not update its own code or read the source checkout.
- Credentials must be entered inside the LXC and stored outside release files.
- Every action result must use an explicit output allowlist and pass through the
  core sanitizer before it is logged or returned.
- Remote callers must satisfy both source-network and cryptographic identity
  checks, and their grants must remain subsets of server permissions.
- A gateway hosted by a managed system must never receive mutation privileges
  for that host.
- Every release must pass generated-artifact, syntax, behavior, checksum, and
  downgrade-protection checks.
