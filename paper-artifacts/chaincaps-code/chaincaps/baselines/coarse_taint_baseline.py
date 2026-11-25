"""
CPT Baseline: Coarse Provenance Taint

Tracks coarse taint levels through tool chains using a 3-level lattice:
  SENSITIVE > INTERNAL > PUBLIC

Join = max(level): mixing sensitive + public data yields sensitive taint.

Blocking policy:
  SENSITIVE -> block all external sinks (HTTP, external email, execute)
  INTERNAL  -> block HTTP, allow corporate email
  PUBLIC    -> allow all

This is a simplified Fides without the confidentiality/integrity split.
Similar spirit to DroidSafe or TaintDroid coarse taint tracking.

Key limitation demonstrated by our paper:
- Only 3 taint levels, so two INTERNAL sources with different authorized
  sinks cannot be distinguished.
- No per-resource scope: INTERNAL allows email to ANY address (no
  @corp.com restriction), unlike ChainCaps which tracks exact scopes.
- Cannot express "this datum may go to HTTP but not email" -- the
  lattice only orders by overall sensitivity.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, List, Optional

from ..proxy.engine import ToolCall


class TaintLevel(IntEnum):
    """3-level taint lattice. Higher = more sensitive."""
    PUBLIC = 0
    INTERNAL = 1
    SENSITIVE = 2


# Map tool names to taint levels they produce
SOURCE_TAINT: Dict[str, TaintLevel] = {
    "read_file": TaintLevel.INTERNAL,
    "read_public_url": TaintLevel.PUBLIC,
    "db_query": TaintLevel.INTERNAL,
    # Realistic MCP names
    "filesystem_read": TaintLevel.INTERNAL,
    "fetch_url": TaintLevel.PUBLIC,
    "postgres_query": TaintLevel.INTERNAL,
    "memory_retrieve": TaintLevel.INTERNAL,
    "browser_screenshot": TaintLevel.INTERNAL,
}

# Resource patterns that escalate to SENSITIVE
SENSITIVE_PATTERNS: List[str] = [
    ".env", "shadow", "secret", "credential", "api_key",
    "patient", "salary", "salaries", "password", "ssh",
    "id_rsa", "private", "hipaa", "records",
]

# Sink blocking rules
_NEVER_BLOCKED = 3

SINK_BLOCK_THRESHOLD: Dict[str, int] = {
    "send_http": TaintLevel.INTERNAL,
    "send_email": TaintLevel.SENSITIVE,
    "write_file": TaintLevel.SENSITIVE,
    "execute_shell": TaintLevel.INTERNAL,
    "display_to_user": _NEVER_BLOCKED,
    # Realistic MCP names
    "fetch_url": TaintLevel.INTERNAL,
    "slack_post_message": TaintLevel.INTERNAL,
    "github_create_issue": TaintLevel.INTERNAL,
    "github_create_pr": TaintLevel.SENSITIVE,
    "email_send": TaintLevel.SENSITIVE,
    "shell_exec": TaintLevel.INTERNAL,
    "filesystem_write": TaintLevel.SENSITIVE,
    "browser_navigate": TaintLevel.INTERNAL,
    "memory_store": _NEVER_BLOCKED,
}


@dataclass
class CPTResult:
    """Result from the CPT baseline check."""
    tool_name: str
    allowed: bool
    taint_level: Optional[TaintLevel] = None
    reason: str = ""


class CoarseTaintBaseline:
    """Coarse Provenance Taint (CPT) baseline.

    Propagates a single taint level through the tool chain using
    join = max. Blocks sinks when the accumulated taint exceeds
    the sink's threshold.

    Key limitations:
    - 3 levels cannot represent per-source sink subsets
    - No scope narrowing (email to anyone vs. email to @corp.com)
    - Treats all INTERNAL sources identically
    - Mixing any sensitive source taints the entire chain
    """

    def __init__(self,
                 source_overrides: Optional[Dict[str, TaintLevel]] = None,
                 sensitive_patterns: Optional[List[str]] = None):
        self.source_overrides = source_overrides or {}
        self.sensitive_patterns = sensitive_patterns or list(SENSITIVE_PATTERNS)
        self.results: List[CPTResult] = []

    def process_chain(self, calls: List[ToolCall],
                      source_budgets: Optional[Dict] = None,
                      **kwargs) -> List[CPTResult]:
        """Process a chain of tool calls with coarse taint tracking.

        Args:
            calls: Sequence of tool calls in the chain.
            source_budgets: ChainCaps budgets, used to infer the BEST
                possible taint level (generous to CPT). Accepted for
                interface compatibility.

        Returns:
            List of CPTResult, one per tool call.
        """
        results = []
        current_taint: Optional[TaintLevel] = None

        # If source_budgets provided, build best-effort taint overrides
        inferred_overrides = dict(self.source_overrides)
        if source_budgets:
            from ..core.budget import SinkType
            for resource, budget in source_budgets.items():
                has_http = any(
                    p.operation == SinkType.SEND_HTTP
                    for p in budget.privileges
                )
                has_email = any(
                    p.operation == SinkType.SEND_EMAIL
                    for p in budget.privileges
                )
                if has_http:
                    inferred_overrides[resource] = TaintLevel.PUBLIC
                elif has_email:
                    inferred_overrides[resource] = TaintLevel.INTERNAL
                else:
                    inferred_overrides[resource] = TaintLevel.SENSITIVE

        for call in calls:
            tool = call.tool_name

            if tool in SOURCE_TAINT:
                # Source: determine taint level
                taint = self._classify_source(call, inferred_overrides)
                # Join with existing taint: max
                if current_taint is None:
                    current_taint = taint
                else:
                    current_taint = TaintLevel(max(current_taint, taint))
                results.append(CPTResult(
                    tool, True, current_taint,
                    reason=f"source taint={taint.name}, chain taint={current_taint.name}"
                ))

            elif tool in SINK_BLOCK_THRESHOLD:
                # Sink: check taint against threshold
                threshold = SINK_BLOCK_THRESHOLD[tool]
                threshold_label = (
                    threshold.name if isinstance(threshold, TaintLevel)
                    else "NEVER"
                )
                if current_taint is None:
                    # No source tracked: allow
                    results.append(CPTResult(
                        tool, True, reason="no tracked taint, default allow"
                    ))
                elif current_taint >= threshold:
                    results.append(CPTResult(
                        tool, False, current_taint,
                        reason=(
                            f"taint {current_taint.name} >= "
                            f"threshold {threshold_label} for {tool}"
                        )
                    ))
                else:
                    results.append(CPTResult(
                        tool, True, current_taint,
                        reason=(
                            f"taint {current_taint.name} < "
                            f"threshold {threshold_label} for {tool}"
                        )
                    ))
            else:
                # Transform: propagate taint unchanged
                results.append(CPTResult(
                    tool, True, current_taint,
                    reason="transform passthrough"
                ))

        self.results.extend(results)
        return results

    def _classify_source(self, call: ToolCall,
                         overrides: Dict[str, TaintLevel]) -> TaintLevel:
        """Classify a source tool call into a taint level."""
        resource = self._extract_resource(call)

        # Check explicit overrides first
        if resource and resource in overrides:
            return overrides[resource]

        # Default by tool type
        default = SOURCE_TAINT.get(call.tool_name, TaintLevel.INTERNAL)
        if default == TaintLevel.PUBLIC:
            return TaintLevel.PUBLIC

        # Check resource key against sensitive patterns
        if resource:
            resource_lower = resource.lower()
            for pattern in self.sensitive_patterns:
                if pattern in resource_lower:
                    return TaintLevel.SENSITIVE

        return default

    def _extract_resource(self, call: ToolCall) -> Optional[str]:
        """Extract resource identifier from call arguments."""
        for key in ("path", "file", "url", "query"):
            if key in call.arguments:
                return str(call.arguments[key])
        return None
