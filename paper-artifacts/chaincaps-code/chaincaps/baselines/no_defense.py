"""
No-Defense Baseline

Simply allows all tool calls. Used as the lower bound for security
and upper bound for utility.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..proxy.engine import ToolCall


@dataclass
class NoDefenseResult:
    tool_name: str
    allowed: bool = True
    reason: str = "no defense"


class NoDefenseBaseline:
    """Allows all tool calls unconditionally."""

    def __init__(self):
        self.results: List[NoDefenseResult] = []

    def process_chain(self, calls: List[ToolCall], **kwargs) -> List[NoDefenseResult]:
        results = [NoDefenseResult(c.tool_name) for c in calls]
        self.results.extend(results)
        return results
