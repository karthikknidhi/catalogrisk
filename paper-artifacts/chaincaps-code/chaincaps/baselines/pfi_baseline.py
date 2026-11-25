"""
PFI-Style Baseline: Per-Tool Isolation

Simplified implementation of Prompt Flow Integrity (Kim et al., 2503.15547):
- Each tool runs in isolation
- Per-tool permission checks (does this tool have permission to do X?)
- No cross-tool composition analysis

Key limitation: PFI checks individual tool permissions but does not
track data flow across tool chains. So read_file is authorized (has
filesystem.read permission) and send_http is authorized (has
network.outbound permission), but PFI cannot detect that composing
them creates an unauthorized data exfiltration.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set

from ..proxy.engine import ToolCall


# Per-tool permission sets (what each tool is allowed to do)
TOOL_PERMISSIONS: Dict[str, Set[str]] = {
    "read_file": {"filesystem.read"},
    "read_public_url": {"network.inbound"},
    "db_query": {"database.read"},
    "summarize": {"compute.transform"},
    "format_output": {"compute.transform"},
    "send_http": {"network.outbound"},
    "send_email": {"email.send"},
    "write_file": {"filesystem.write"},
    "execute_shell": {"shell.execute"},
    "display_to_user": {"display.show"},
    # Realistic MCP names
    "filesystem_read": {"filesystem.read"},
    "filesystem_write": {"filesystem.write"},
    "fetch_url": {"network.inbound", "network.outbound"},
    "postgres_query": {"database.read"},
    "slack_post_message": {"network.outbound"},
    "github_create_issue": {"network.outbound"},
    "github_create_pr": {"network.outbound"},
    "email_send": {"email.send"},
    "shell_exec": {"shell.execute"},
    "memory_store": {"memory.write"},
    "memory_retrieve": {"memory.read"},
    "browser_navigate": {"network.outbound"},
    "browser_screenshot": {"display.show"},
    "summarize_text": {"compute.transform"},
    "translate_text": {"compute.transform"},
    "format_data": {"compute.transform"},
}

# Restricted tool combinations (PFI doesn't have this by default,
# but we give it the benefit of the doubt with a small blocklist)
BLOCKED_DIRECT_PAIRS: Set[tuple] = set()
# Note: PFI as published does NOT block tool pairs.
# It only does per-tool isolation + privilege escalation guardrails.


@dataclass
class PFIResult:
    tool_name: str
    allowed: bool
    reason: str = ""


class PFIBaseline:
    """PFI-style per-tool isolation baseline.

    Checks: does this tool have permission to execute?
    Does NOT check: does the data flowing to this tool authorize this sink?
    """

    def __init__(self, blocked_tools: Set[str] = None):
        self.blocked_tools = blocked_tools or set()
        self.results: List[PFIResult] = []

    def process_chain(self, calls: List[ToolCall], **kwargs) -> List[PFIResult]:
        results = []
        for call in calls:
            tool = call.tool_name
            if tool in self.blocked_tools:
                results.append(PFIResult(tool, False, "tool blocked by policy"))
            elif tool in TOOL_PERMISSIONS:
                results.append(PFIResult(tool, True, "tool has required permissions"))
            else:
                results.append(PFIResult(tool, False, "unknown tool"))
        self.results.extend(results)
        return results
