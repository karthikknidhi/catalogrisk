"""
STSA Baseline: Source-to-Sink Allowlist

Maintains a static policy matrix mapping (source_type, sink_type) -> allow/deny.
No per-datum budget tracking -- only coarse source categories.

Source types: SENSITIVE, INTERNAL, PUBLIC
Sink types: DISPLAY, HTTP, EMAIL, FILE_WRITE, EXECUTE

Default policy:
  SENSITIVE -> only DISPLAY
  INTERNAL  -> DISPLAY + EMAIL(@corp.com)
  PUBLIC    -> all sinks

Key limitation demonstrated by our paper:
- Allowlists cannot distinguish between two INTERNAL sources with
  different authorized sinks (e.g., internal report -> corp email OK,
  but internal report -> external email should be blocked).
- No per-resource scope narrowing: email is either allowed or not,
  regardless of recipient domain.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple

from ..proxy.engine import ToolCall


class SourceType(Enum):
    """Coarse source classification."""
    SENSITIVE = auto()
    INTERNAL = auto()
    PUBLIC = auto()


class SinkCategory(Enum):
    """Coarse sink classification."""
    DISPLAY = auto()
    HTTP = auto()
    EMAIL = auto()
    FILE_WRITE = auto()
    EXECUTE = auto()


# Map tool names to source types
TOOL_TO_SOURCE: Dict[str, SourceType] = {
    "read_file": SourceType.INTERNAL,
    "read_public_url": SourceType.PUBLIC,
    "db_query": SourceType.INTERNAL,
    # Realistic MCP names
    "filesystem_read": SourceType.INTERNAL,
    "fetch_url": SourceType.PUBLIC,
    "postgres_query": SourceType.INTERNAL,
    "memory_retrieve": SourceType.INTERNAL,
    "browser_screenshot": SourceType.INTERNAL,
}

# Sensitive resource patterns -- if resource key matches, override to SENSITIVE
SENSITIVE_PATTERNS: List[str] = [
    ".env", "shadow", "secret", "credential", "api_key",
    "patient", "salary", "salaries", "password", "ssh",
    "id_rsa", "private", "hipaa", "records",
]

# Map tool names to sink categories
TOOL_TO_SINK: Dict[str, SinkCategory] = {
    "send_http": SinkCategory.HTTP,
    "send_email": SinkCategory.EMAIL,
    "write_file": SinkCategory.FILE_WRITE,
    "execute_shell": SinkCategory.EXECUTE,
    "display_to_user": SinkCategory.DISPLAY,
    # Realistic MCP names
    "fetch_url": SinkCategory.HTTP,  # when used as POST
    "slack_post_message": SinkCategory.HTTP,
    "github_create_issue": SinkCategory.HTTP,
    "github_create_pr": SinkCategory.HTTP,
    "email_send": SinkCategory.EMAIL,
    "shell_exec": SinkCategory.EXECUTE,
    "filesystem_write": SinkCategory.FILE_WRITE,
    "browser_navigate": SinkCategory.HTTP,
    "memory_store": SinkCategory.FILE_WRITE,
}

# The allowlist policy matrix: (SourceType, SinkCategory) -> allowed
DEFAULT_POLICY: Dict[Tuple[SourceType, SinkCategory], bool] = {
    # SENSITIVE: only display
    (SourceType.SENSITIVE, SinkCategory.DISPLAY): True,
    (SourceType.SENSITIVE, SinkCategory.HTTP): False,
    (SourceType.SENSITIVE, SinkCategory.EMAIL): False,
    (SourceType.SENSITIVE, SinkCategory.FILE_WRITE): False,
    (SourceType.SENSITIVE, SinkCategory.EXECUTE): False,
    # INTERNAL: display + email (no scope check -- this is the weakness)
    (SourceType.INTERNAL, SinkCategory.DISPLAY): True,
    (SourceType.INTERNAL, SinkCategory.HTTP): False,
    (SourceType.INTERNAL, SinkCategory.EMAIL): True,
    (SourceType.INTERNAL, SinkCategory.FILE_WRITE): False,
    (SourceType.INTERNAL, SinkCategory.EXECUTE): False,
    # PUBLIC: all sinks
    (SourceType.PUBLIC, SinkCategory.DISPLAY): True,
    (SourceType.PUBLIC, SinkCategory.HTTP): True,
    (SourceType.PUBLIC, SinkCategory.EMAIL): True,
    (SourceType.PUBLIC, SinkCategory.FILE_WRITE): True,
    (SourceType.PUBLIC, SinkCategory.EXECUTE): True,
}


@dataclass
class STSAResult:
    """Result from the STSA baseline check."""
    tool_name: str
    allowed: bool
    source_type: Optional[SourceType] = None
    sink_category: Optional[SinkCategory] = None
    reason: str = ""


class AllowlistBaseline:
    """Source-to-Sink Allowlist (STSA) baseline.

    Classifies each source into one of three coarse categories and
    checks whether the current source type is allowed to flow to
    the target sink category.

    Key limitations:
    - No per-resource scope (email to anyone vs. email to @corp.com)
    - No budget attenuation across transforms
    - Mixed sources default to the most restrictive classification
    - Cannot distinguish sub-categories within the same source type
    """

    def __init__(self,
                 policy_overrides: Optional[Dict[Tuple[SourceType, SinkCategory], bool]] = None,
                 sensitive_patterns: Optional[List[str]] = None):
        self.policy = dict(DEFAULT_POLICY)
        if policy_overrides:
            self.policy.update(policy_overrides)
        self.sensitive_patterns = sensitive_patterns or list(SENSITIVE_PATTERNS)
        self.results: List[STSAResult] = []

    def process_chain(self, calls: List[ToolCall],
                      source_budgets: Optional[Dict] = None,
                      **kwargs) -> List[STSAResult]:
        """Process a chain of tool calls with STSA allowlist checking.

        Args:
            calls: Sequence of tool calls in the chain.
            source_budgets: Ignored (STSA does not use per-datum budgets),
                accepted for interface compatibility.

        Returns:
            List of STSAResult, one per tool call.
        """
        results = []
        current_source: Optional[SourceType] = None

        for call in calls:
            tool = call.tool_name

            if tool in TOOL_TO_SOURCE:
                # Source tool: classify source type
                source_type = self._classify_source(call)
                # If mixing sources, take the most restrictive
                if current_source is None:
                    current_source = source_type
                else:
                    current_source = self._meet_sources(current_source, source_type)
                results.append(STSAResult(
                    tool, True, source_type=current_source,
                    reason="source classified"
                ))

            elif tool in TOOL_TO_SINK:
                # Sink tool: check the policy matrix
                sink_cat = TOOL_TO_SINK[tool]
                if current_source is None:
                    # No tracked source; allow (conservative: assume public)
                    results.append(STSAResult(
                        tool, True, sink_category=sink_cat,
                        reason="no tracked source, default allow"
                    ))
                else:
                    allowed = self.policy.get(
                        (current_source, sink_cat), False
                    )
                    results.append(STSAResult(
                        tool, allowed, current_source, sink_cat,
                        reason=(
                            f"policy({current_source.name}, {sink_cat.name})"
                            f" = {'ALLOW' if allowed else 'DENY'}"
                        )
                    ))
            else:
                # Transform: propagate source classification unchanged
                results.append(STSAResult(
                    tool, True, source_type=current_source,
                    reason="transform passthrough"
                ))

        self.results.extend(results)
        return results

    def _classify_source(self, call: ToolCall) -> SourceType:
        """Classify a source tool call into a coarse source type."""
        # Check if the tool is already known as public
        default_type = TOOL_TO_SOURCE.get(call.tool_name, SourceType.INTERNAL)
        if default_type == SourceType.PUBLIC:
            return SourceType.PUBLIC

        # Check resource key against sensitive patterns
        resource = self._extract_resource(call)
        if resource:
            resource_lower = resource.lower()
            for pattern in self.sensitive_patterns:
                if pattern in resource_lower:
                    return SourceType.SENSITIVE

        return default_type

    def _meet_sources(self, a: SourceType, b: SourceType) -> SourceType:
        """Meet of two source types: most restrictive wins.

        SENSITIVE < INTERNAL < PUBLIC (lower = more restrictive).
        """
        order = {SourceType.SENSITIVE: 0, SourceType.INTERNAL: 1, SourceType.PUBLIC: 2}
        if order[a] <= order[b]:
            return a
        return b

    def _extract_resource(self, call: ToolCall) -> Optional[str]:
        """Extract resource identifier from call arguments."""
        for key in ("path", "file", "url", "query"):
            if key in call.arguments:
                return str(call.arguments[key])
        return None
