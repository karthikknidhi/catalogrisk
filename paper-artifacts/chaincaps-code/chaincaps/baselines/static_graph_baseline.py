"""
SCG Baseline: Static Composition Graph

Pre-defines a blocklist of known-bad tool compositions as pairs and
triples. Blocks a chain if the observed tool sequence contains any
blocklisted subsequence.

This is analogous to signature-based IDS approaches applied to tool
composition: effective against known patterns, blind to novel ones.

Key limitation demonstrated by our paper:
- Only catches compositions that are explicitly enumerated
- Novel or indirect compositions (e.g., read_file -> summarize ->
  format -> send_http) bypass the blocklist unless the full
  subsequence is listed
- Cannot adapt to new tools without updating the blocklist
- No data-level tracking: blocks based on tool names only
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from ..proxy.engine import ToolCall


# Known-bad pairs: (source_tool, sink_tool)
BLOCKED_PAIRS: Set[Tuple[str, str]] = {
    ("read_file", "send_http"),
    ("read_file", "execute_shell"),
    ("db_query", "send_http"),
    ("db_query", "send_email"),
    ("db_query", "execute_shell"),
    ("read_file", "send_email"),
    # Realistic MCP names
    ("filesystem_read", "fetch_url"),
    ("filesystem_read", "slack_post_message"),
    ("filesystem_read", "github_create_issue"),
    ("filesystem_read", "email_send"),
    ("filesystem_read", "shell_exec"),
    ("filesystem_read", "browser_navigate"),
    ("postgres_query", "fetch_url"),
    ("postgres_query", "slack_post_message"),
    ("postgres_query", "email_send"),
    ("postgres_query", "github_create_issue"),
    ("postgres_query", "shell_exec"),
    ("memory_retrieve", "fetch_url"),
    ("memory_retrieve", "slack_post_message"),
    ("browser_screenshot", "email_send"),
    ("browser_screenshot", "fetch_url"),
}

# Known-bad triples: (tool1, tool2, tool3)
BLOCKED_TRIPLES: Set[Tuple[str, str, str]] = {
    ("read_file", "summarize", "send_http"),
    ("read_file", "format_output", "send_http"),
    ("db_query", "summarize", "send_email"),
    ("db_query", "format_output", "send_http"),
    ("read_file", "summarize", "send_email"),
    ("read_file", "format_output", "execute_shell"),
    # Realistic MCP names
    ("filesystem_read", "summarize_text", "fetch_url"),
    ("filesystem_read", "format_data", "fetch_url"),
    ("filesystem_read", "summarize_text", "slack_post_message"),
    ("filesystem_read", "format_data", "email_send"),
    ("postgres_query", "format_data", "slack_post_message"),
    ("postgres_query", "summarize_text", "email_send"),
    ("postgres_query", "format_data", "email_send"),
    ("postgres_query", "format_data", "fetch_url"),
    ("filesystem_read", "format_data", "github_create_issue"),
    ("filesystem_read", "summarize_text", "email_send"),
}

# Tools that are always safe (display to user, transforms)
ALWAYS_SAFE_SINKS: Set[str] = {"display_to_user"}


@dataclass
class SCGResult:
    """Result from the SCG baseline check."""
    tool_name: str
    allowed: bool
    matched_pattern: Optional[Tuple] = None
    reason: str = ""


class StaticGraphBaseline:
    """Static Composition Graph (SCG) baseline.

    Maintains a blocklist of known-bad (tool1, tool2) pairs and
    (tool1, tool2, tool3) triples. For each tool call, checks
    whether the observed tool sequence so far contains any
    blocklisted subsequence.

    Key limitations:
    - Cannot detect compositions not in the blocklist
    - No data-level reasoning (tool A -> B is blocked regardless
      of what data actually flows)
    - Quadratic/cubic scan of the tool history per call
    - Adding new tools requires manual blocklist updates
    """

    def __init__(self,
                 extra_pairs: Optional[Set[Tuple[str, str]]] = None,
                 extra_triples: Optional[Set[Tuple[str, str, str]]] = None):
        self.blocked_pairs = set(BLOCKED_PAIRS)
        self.blocked_triples = set(BLOCKED_TRIPLES)
        if extra_pairs:
            self.blocked_pairs.update(extra_pairs)
        if extra_triples:
            self.blocked_triples.update(extra_triples)
        self.results: List[SCGResult] = []

    def process_chain(self, calls: List[ToolCall],
                      source_budgets: Optional[Dict] = None,
                      **kwargs) -> List[SCGResult]:
        """Process a chain of tool calls with static composition blocklist.

        For each call at index i, checks:
        1. Whether (calls[j].tool_name, calls[i].tool_name) is a blocked
           pair for any j < i.
        2. Whether (calls[j].tool_name, calls[k].tool_name, calls[i].tool_name)
           is a blocked triple for any j < k < i.

        Args:
            calls: Sequence of tool calls in the chain.
            source_budgets: Ignored (SCG does not use budgets),
                accepted for interface compatibility.

        Returns:
            List of SCGResult, one per tool call.
        """
        results = []
        tool_history: List[str] = []

        for i, call in enumerate(calls):
            tool = call.tool_name
            blocked = False
            matched = None

            # Skip checking always-safe sinks
            if tool not in ALWAYS_SAFE_SINKS:
                # Check pairs: any earlier tool + current tool
                for j in range(len(tool_history)):
                    pair = (tool_history[j], tool)
                    if pair in self.blocked_pairs:
                        blocked = True
                        matched = pair
                        break

                # Check triples: any two earlier tools + current tool
                if not blocked:
                    for j in range(len(tool_history)):
                        for k in range(j + 1, len(tool_history)):
                            triple = (tool_history[j], tool_history[k], tool)
                            if triple in self.blocked_triples:
                                blocked = True
                                matched = triple
                                break
                        if blocked:
                            break

            if blocked:
                results.append(SCGResult(
                    tool, False, matched,
                    reason=f"blocked by pattern {matched}"
                ))
            else:
                results.append(SCGResult(
                    tool, True,
                    reason="no matching blocked pattern"
                ))

            tool_history.append(tool)

        self.results.extend(results)
        return results
