"""
ChainCaps Proxy: Runtime Enforcement Engine

The core enforcement layer that intercepts tool calls, maintains the
dataflow DAG, and enforces monotonic capability attenuation.

Sits between the LLM planner and tool execution, acting as an MCP proxy.
"""

from __future__ import annotations
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..core.budget import Budget, SinkPrivilege, SinkType
from ..core.dag import DataflowDAG, SinkEvent
from ..core.manifest import ToolManifest, get_manifest


@dataclass
class ToolCall:
    """A tool call intercepted by the proxy."""
    tool_name: str
    arguments: Dict[str, Any]
    # IDs of data nodes that flow into this call's arguments
    data_dependencies: List[str] = field(default_factory=list)


@dataclass
class ToolResult:
    """Result of a tool call after proxy enforcement."""
    tool_call: ToolCall
    allowed: bool
    output: Optional[Any] = None
    output_node_id: Optional[str] = None
    sink_event: Optional[SinkEvent] = None
    block_reason: Optional[str] = None
    latency_ms: float = 0.0


@dataclass
class EnforcementStats:
    """Aggregate statistics for evaluation."""
    total_calls: int = 0
    allowed_calls: int = 0
    blocked_calls: int = 0
    declassified_calls: int = 0
    source_reads: int = 0
    transforms: int = 0
    sink_attempts: int = 0
    total_latency_ms: float = 0.0
    dag_nodes: int = 0

    @property
    def block_rate(self) -> float:
        return self.blocked_calls / max(self.total_calls, 1)

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / max(self.total_calls, 1)


class ChainCapsEngine:
    """The ChainCaps runtime enforcement engine.

    Enforces monotonic capability attenuation across tool chains.
    """

    def __init__(self,
                 manifests: Optional[Dict[str, ToolManifest]] = None,
                 source_budget_overrides: Optional[Dict[str, Budget]] = None,
                 session_isolation: bool = False):
        """Initialize the engine.

        Args:
            manifests: Custom tool manifests (overrides defaults)
            source_budget_overrides: Per-source budget overrides
                (e.g., {"secret.txt": budget_display_only()})
            session_isolation: If True, reset context budget after each
                display_to_user sink (task boundary). This eliminates
                context-budget FPs where an early sensitive read
                poisons later unrelated operations.
        """
        self.dag = DataflowDAG()
        self.manifests = manifests or {}
        self.source_budget_overrides = source_budget_overrides or {}
        self.stats = EnforcementStats()
        self._active_declassification_tokens: Dict[str, str] = {}
        self._session_isolation = session_isolation
        self._session_boundary_node_ids: set = set()  # nodes before boundary

    def get_manifest(self, tool_name: str) -> ToolManifest:
        """Get manifest for a tool, checking custom manifests first."""
        if tool_name in self.manifests:
            return self.manifests[tool_name]
        return get_manifest(tool_name)

    def process_tool_call(self, call: ToolCall,
                          tool_executor: Optional[Callable] = None,
                          declassification_token: Optional[str] = None,
                          ) -> ToolResult:
        """Process a tool call through the ChainCaps enforcement pipeline.

        1. Look up the tool's manifest
        2. If source: create source node with Init budget
        3. If transform: create transform node with propagated budget
        4. If sink: check authorization against propagated budget
        5. Execute if authorized; block otherwise

        Args:
            call: The intercepted tool call
            tool_executor: Optional function to actually execute the tool
            declassification_token: Optional declassification for this call

        Returns:
            ToolResult with authorization decision and metadata
        """
        start_time = time.time()
        self.stats.total_calls += 1

        manifest = self.get_manifest(call.tool_name)
        result = ToolResult(tool_call=call, allowed=False)

        if manifest.is_source and manifest.is_sink:
            # Dual-role tool (e.g., fetch_url can GET or POST)
            # If it has data dependencies, treat as sink (it's sending data)
            # If no data dependencies, treat as source (it's reading data)
            has_data_deps = bool(call.data_dependencies) or bool(self.dag.nodes)
            if has_data_deps and manifest.exec_privileges:
                result = self._handle_sink(
                    call, manifest, declassification_token
                )
            else:
                result = self._handle_source(call, manifest)
        elif manifest.is_source:
            result = self._handle_source(call, manifest)
        elif manifest.is_sink:
            result = self._handle_sink(
                call, manifest, declassification_token
            )
        else:
            result = self._handle_transform(call, manifest)

        # Session isolation: reset context budget after display_to_user
        # and mark all current nodes as "before boundary" so they are not
        # used as implicit dependencies for subsequent calls.
        if (self._session_isolation and result.allowed
                and manifest.is_sink
                and any(p.operation == SinkType.DISPLAY
                        for p in manifest.exec_privileges)):
            self.dag._context_budget = Budget.top()
            self._session_boundary_node_ids = set(self.dag.nodes.keys())

        # Execute if allowed and executor provided
        if result.allowed and tool_executor:
            try:
                result.output = tool_executor(call.tool_name, call.arguments)
            except Exception as e:
                result.output = f"EXECUTION_ERROR: {e}"

        result.latency_ms = (time.time() - start_time) * 1000
        self.stats.total_latency_ms += result.latency_ms
        self.stats.dag_nodes = len(self.dag.nodes)

        return result

    def _handle_source(self, call: ToolCall,
                       manifest: ToolManifest) -> ToolResult:
        """Handle a source tool call (data ingestion)."""
        self.stats.source_reads += 1

        # Determine budget: check overrides, then manifest default
        resource_key = self._extract_resource_key(call)
        if resource_key and resource_key in self.source_budget_overrides:
            budget = self.source_budget_overrides[resource_key]
        elif manifest.default_source_budget:
            budget = manifest.default_source_budget
        else:
            budget = Budget.from_sinks(SinkPrivilege(SinkType.DISPLAY))

        # Create source node in DAG
        label = f"{call.tool_name}({resource_key or '?'})"
        node_id = self.dag.add_source(label, budget, call.tool_name)

        self.stats.allowed_calls += 1
        return ToolResult(
            tool_call=call,
            allowed=True,
            output_node_id=node_id,
        )

    def _filter_post_boundary(self, node_ids: list) -> list:
        """Filter node IDs to only include post-boundary nodes (session isolation)."""
        if not self._session_isolation or not self._session_boundary_node_ids:
            return node_ids
        filtered = [nid for nid in node_ids
                    if nid not in self._session_boundary_node_ids]
        return filtered if filtered else node_ids  # fallback to all if none remain

    def _handle_transform(self, call: ToolCall,
                          manifest: ToolManifest) -> ToolResult:
        """Handle a transform tool call (data processing, no side effects)."""
        self.stats.transforms += 1

        # If no explicit data dependencies, use all recent source nodes
        input_ids = call.data_dependencies
        if not input_ids:
            # Conservative: depend on all existing nodes
            input_ids = self._filter_post_boundary(list(self.dag.nodes.keys()))

        if not input_ids:
            # No data in the DAG yet; create with top budget
            node_id = self.dag.add_source(
                f"{call.tool_name}(no_deps)",
                Budget.top(),
                call.tool_name,
            )
            self.stats.allowed_calls += 1
            return ToolResult(
                tool_call=call, allowed=True, output_node_id=node_id
            )

        # Create transform node with propagated budget
        label = f"{call.tool_name}({json.dumps(call.arguments, default=str)[:50]})"
        node_id = self.dag.add_transform(
            label, input_ids, call.tool_name, manifest.pass_through
        )

        self.stats.allowed_calls += 1
        return ToolResult(
            tool_call=call, allowed=True, output_node_id=node_id
        )

    def _handle_sink(self, call: ToolCall, manifest: ToolManifest,
                     declassification_token: Optional[str]) -> ToolResult:
        """Handle a sink tool call (side effects).

        This is where the core enforcement happens.
        """
        self.stats.sink_attempts += 1

        # Determine the requested sink privilege
        requested = self._infer_sink_privilege(call, manifest)
        if not requested:
            self.stats.blocked_calls += 1
            return ToolResult(
                tool_call=call,
                allowed=False,
                block_reason="Cannot determine requested sink privilege",
            )

        # Check authorization via DAG
        data_deps = call.data_dependencies
        if not data_deps:
            data_deps = self._filter_post_boundary(list(self.dag.nodes.keys()))

        event = self.dag.check_sink(
            call.tool_name, requested, data_deps, declassification_token
        )

        if event.authorized:
            if declassification_token:
                self.stats.declassified_calls += 1
            self.stats.allowed_calls += 1
        else:
            self.stats.blocked_calls += 1

        return ToolResult(
            tool_call=call,
            allowed=event.authorized,
            sink_event=event,
            block_reason=event.block_reason,
        )

    def _extract_resource_key(self, call: ToolCall) -> Optional[str]:
        """Extract the resource key from a tool call for budget lookup."""
        args = call.arguments
        for key in ("path", "file", "filename", "url", "query", "table"):
            if key in args:
                return str(args[key])
        # Fallback: first string argument
        for v in args.values():
            if isinstance(v, str):
                return v
        return None

    def _infer_sink_privilege(self, call: ToolCall,
                              manifest: ToolManifest
                              ) -> Optional[SinkPrivilege]:
        """Infer the specific sink privilege from the call arguments."""
        if not manifest.exec_privileges:
            return None

        # Use the first exec privilege as the base
        base = manifest.exec_privileges[0]

        # Try to narrow scope from arguments; fall back to manifest scope
        args = call.arguments
        if base.operation == SinkType.SEND_HTTP:
            url = args.get("url", args.get("endpoint", base.scope))
            return SinkPrivilege(SinkType.SEND_HTTP, str(url))
        elif base.operation == SinkType.SEND_EMAIL:
            to = args.get("to", args.get("recipient", "*"))
            return SinkPrivilege(SinkType.SEND_EMAIL, str(to))
        elif base.operation == SinkType.WRITE_FILE:
            path = args.get("path", args.get("file", "*"))
            return SinkPrivilege(SinkType.WRITE_FILE, str(path))
        elif base.operation == SinkType.EXECUTE:
            cmd = args.get("command", args.get("cmd", "*"))
            return SinkPrivilege(SinkType.EXECUTE, str(cmd))

        return base

    def get_report(self) -> Dict:
        """Generate an enforcement report for evaluation."""
        return {
            "stats": {
                "total_calls": self.stats.total_calls,
                "allowed": self.stats.allowed_calls,
                "blocked": self.stats.blocked_calls,
                "declassified": self.stats.declassified_calls,
                "block_rate": self.stats.block_rate,
                "avg_latency_ms": self.stats.avg_latency_ms,
            },
            "dag": self.dag.stats,
            "sink_events": [
                {
                    "tool": e.tool_name,
                    "privilege": str(e.requested_privilege),
                    "authorized": e.authorized,
                    "reason": e.block_reason,
                    "declassified": e.declassification_token is not None,
                }
                for e in self.dag.sink_events
            ],
        }
