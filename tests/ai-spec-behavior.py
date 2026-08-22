#!/usr/bin/env python3
"""Coverage checks for the canonical AI specification."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = (ROOT / "AI_SPEC.md").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


required_sections = [
    "## 1. Product definition",
    "## 2. Security invariants",
    "## 3. Architecture",
    "## 4. Data contracts",
    "## 5. CLI contract",
    "## 6. MCP and OAuth",
    "## 7. Administrator UI",
    "## 8. Logging contract",
    "## 9. Update and release contract",
    "## 10. Testing contract",
    "## 11. Feature status and roadmap",
    "## 12. AI operating rules",
    "## 13. Specification validation",
]
for section in required_sections:
    require(section in SPEC, f"AI_SPEC missing section: {section}")
require("LABSteward" in SPEC and "stewctl update" in SPEC, "AI_SPEC branding/update contract missing")
catalog = json.loads((ROOT / "catalog/plugins.json").read_text(encoding="utf-8"))
for plugin in catalog["plugins"]:
    require(plugin["id"] in SPEC, f"AI_SPEC missing plugin {plugin['id']}")
    for permission in plugin.get("permissions", {}):
        require(permission in SPEC, f"AI_SPEC missing permission {permission}")
for command in ("stewctl version", "stewctl validate", "stewctl update check", "stewctl logs"):
    require(command in SPEC, f"AI_SPEC missing command {command}")
require(re.search(r"30 days", SPEC) is not None, "AI_SPEC missing log retention")
print("AI specification coverage checks passed.")
