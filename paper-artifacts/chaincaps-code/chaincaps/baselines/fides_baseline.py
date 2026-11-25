"""
Fides-Style Baseline: Standard C/I Label IFC

Implements a simplified version of Fides (Costa et al., 2505.23643):
- Confidentiality labels: {PUBLIC, INTERNAL, SECRET}
- Integrity labels: {TRUSTED, UNTRUSTED}
- Policy: UNTRUSTED data cannot flow to TRUSTED sinks;
          SECRET data cannot flow to PUBLIC sinks

This baseline demonstrates the representational limitation:
sources with identical C/I labels but different authorized sinks
cannot be distinguished.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

from ..proxy.engine import ToolCall


class Confidentiality(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2


class Integrity(IntEnum):
    UNTRUSTED = 0
    TRUSTED = 1


@dataclass(frozen=True)
class CILabel:
    """Confidentiality/Integrity label pair."""
    conf: Confidentiality
    integ: Integrity

    def can_flow_to(self, sink_label: CILabel) -> bool:
        """Standard IFC check: data can flow to sink if
        data.conf <= sink.conf and data.integ >= sink.integ
        (no read-up, no write-down for confidentiality;
         no read-down, no write-up for integrity)
        """
        return (self.conf <= sink_label.conf and
                self.integ >= sink_label.integ)

    def meet(self, other: CILabel) -> CILabel:
        """Meet: highest confidentiality, lowest integrity."""
        return CILabel(
            conf=max(self.conf, other.conf),
            integ=min(self.integ, other.integ),
        )


# Default labels for tools (original + realistic MCP names)
TOOL_SOURCE_LABELS: Dict[str, CILabel] = {
    "read_file": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
    "read_public_url": CILabel(Confidentiality.PUBLIC, Integrity.UNTRUSTED),
    "db_query": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
    # Realistic MCP names
    "filesystem_read": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
    "fetch_url": CILabel(Confidentiality.PUBLIC, Integrity.UNTRUSTED),
    "postgres_query": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
    "memory_retrieve": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
    "browser_screenshot": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
}

# Sink labels determine what data can flow to them
TOOL_SINK_LABELS: Dict[str, CILabel] = {
    "send_http": CILabel(Confidentiality.PUBLIC, Integrity.TRUSTED),
    "send_email": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
    "write_file": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
    "execute_shell": CILabel(Confidentiality.PUBLIC, Integrity.TRUSTED),
    "display_to_user": CILabel(Confidentiality.SECRET, Integrity.UNTRUSTED),
    # Realistic MCP names
    "fetch_url": CILabel(Confidentiality.PUBLIC, Integrity.TRUSTED),  # POST
    "slack_post_message": CILabel(Confidentiality.PUBLIC, Integrity.TRUSTED),
    "github_create_issue": CILabel(Confidentiality.PUBLIC, Integrity.TRUSTED),
    "github_create_pr": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
    "email_send": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
    "shell_exec": CILabel(Confidentiality.PUBLIC, Integrity.TRUSTED),
    "filesystem_write": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
    "browser_navigate": CILabel(Confidentiality.PUBLIC, Integrity.TRUSTED),
    "memory_store": CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED),
}


@dataclass
class FidesResult:
    """Result from the Fides baseline check."""
    tool_name: str
    allowed: bool
    data_label: Optional[CILabel] = None
    sink_label: Optional[CILabel] = None
    reason: Optional[str] = None


class FidesBaseline:
    """Fides-style C/I label tracking baseline.

    Key limitation demonstrated by our paper:
    - Two internal trusted sources (e.g., bug report vs status note)
      both get label (INTERNAL, TRUSTED)
    - But one should only go to email, the other only to HTTP
    - C/I labels cannot represent this distinction without
      exponential label refinement
    """

    def __init__(self, source_label_overrides: Optional[Dict[str, CILabel]] = None):
        self.source_overrides = source_label_overrides or {}
        self._current_label: Optional[CILabel] = None
        self.results: List[FidesResult] = []

    def process_chain(self, calls: List[ToolCall],
                      source_budgets: Optional[Dict] = None
                      ) -> List[FidesResult]:
        """Process a chain of tool calls with Fides-style IFC.

        Note: source_budgets (ChainCaps budgets) are used to infer the
        BEST POSSIBLE Fides label for each source. This is generous to
        Fides -- it gets oracle-level label assignment. The point is
        to show that even with perfect label assignment, C/I labels
        have representational limitations for sink-authority subsets.
        """
        results = []
        current_label = None

        # Map ChainCaps budgets to best Fides labels (generous to Fides)
        source_ci_labels = dict(self.source_overrides)
        if source_budgets:
            from ..core.budget import SinkType
            for resource, budget in source_budgets.items():
                # Infer the best C/I label from the budget
                has_network = any(
                    p.operation in (SinkType.SEND_HTTP, SinkType.SEND_EMAIL)
                    for p in budget.privileges
                )
                if has_network:
                    source_ci_labels[resource] = CILabel(
                        Confidentiality.PUBLIC, Integrity.TRUSTED
                    )
                else:
                    source_ci_labels[resource] = CILabel(
                        Confidentiality.INTERNAL, Integrity.TRUSTED
                    )

        for call in calls:
            tool = call.tool_name

            if tool in TOOL_SOURCE_LABELS or tool in source_ci_labels:
                # Source: assign label
                resource = self._extract_resource(call)
                if resource and resource in source_ci_labels:
                    current_label = source_ci_labels[resource]
                elif tool in source_ci_labels:
                    current_label = source_ci_labels[tool]
                else:
                    current_label = TOOL_SOURCE_LABELS.get(
                        tool, CILabel(Confidentiality.INTERNAL, Integrity.TRUSTED)
                    )
                results.append(FidesResult(tool, True, data_label=current_label))

            elif tool in TOOL_SINK_LABELS:
                # Sink: check flow
                sink_label = TOOL_SINK_LABELS[tool]
                if current_label is None:
                    results.append(FidesResult(tool, True, sink_label=sink_label))
                elif current_label.can_flow_to(sink_label):
                    results.append(FidesResult(
                        tool, True, current_label, sink_label
                    ))
                else:
                    results.append(FidesResult(
                        tool, False, current_label, sink_label,
                        reason=f"C/I violation: {current_label} -> {sink_label}"
                    ))
            else:
                # Transform: propagate label
                results.append(FidesResult(tool, True, data_label=current_label))

        self.results.extend(results)
        return results

    def _extract_resource(self, call: ToolCall) -> Optional[str]:
        for key in ("path", "file", "url", "query"):
            if key in call.arguments:
                return str(call.arguments[key])
        return None
