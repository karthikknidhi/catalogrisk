"""
ChainCaps Core: Online Dataflow DAG

Maintains the runtime dataflow graph tracking how data flows between
tools via the LLM's context window. Each node is a data item (tool output,
source read, user input) with an attached budget. Edges represent data
dependencies.

Implements:
- Budget Preservation Lemma: beta(x) <= meet(Init(o) for o in Src(x))
- Online DAG construction during tool execution
- Provenance tracking for audit
"""

from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .budget import Budget, SinkPrivilege, SinkType


@dataclass
class DataNode:
    """A node in the dataflow DAG representing a data item."""
    node_id: str
    label: str  # Human-readable label (e.g., "read_file(.env)")
    budget: Budget
    source_ids: List[str] = field(default_factory=list)  # Parent node IDs
    tool_name: Optional[str] = None  # Tool that produced this data
    timestamp: float = field(default_factory=time.time)
    is_source: bool = False  # True for original data sources (no parents)

    @property
    def source_ancestors(self) -> Set[str]:
        """Computed by the DAG, not stored here."""
        return set()  # Placeholder; DAG computes this


@dataclass
class SinkEvent:
    """A record of an attempted or executed sink operation."""
    event_id: str
    tool_name: str
    requested_privilege: SinkPrivilege
    data_node_ids: List[str]  # Data items flowing to this sink
    propagated_budget: Budget  # Meet of all input budgets
    authorized: bool
    declassification_token: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    block_reason: Optional[str] = None


class DataflowDAG:
    """Online dataflow DAG with budget propagation.

    Invariant (Budget Preservation Lemma):
    For every derived value x:
        beta(x) <= meet(Init(o) for o in Src(x))

    This is maintained by construction: each new node's budget is
    the meet of its parents' budgets intersected with the tool's
    pass-through set.
    """

    def __init__(self, signing_key: Optional[bytes] = None):
        self.nodes: Dict[str, DataNode] = {}
        self.sink_events: List[SinkEvent] = []
        # Context budget: conservative bound when data enters free-form context
        self._context_budget: Budget = Budget.top()
        # Spent declassification tokens (replay prevention)
        self._spent_tokens: Set[str] = set()
        # HMAC signing key for declassification tokens (held by trusted issuer only)
        import os as _os
        self._signing_key = signing_key or _os.urandom(32)

    def add_source(self, label: str, init_budget: Budget,
                   tool_name: Optional[str] = None) -> str:
        """Add a source data node (e.g., file read, DB query result).

        Args:
            label: Human-readable description
            init_budget: Initial authorized-sink budget (from source policy)
            tool_name: Tool that produced this source data

        Returns:
            node_id for the new source node
        """
        node_id = f"src_{uuid.uuid4().hex[:8]}"
        node = DataNode(
            node_id=node_id,
            label=label,
            budget=init_budget,
            tool_name=tool_name,
            is_source=True,
        )
        self.nodes[node_id] = node
        # Update context budget conservatively
        self._context_budget = self._context_budget.meet(init_budget)
        return node_id

    def add_transform(self, label: str, input_node_ids: List[str],
                      tool_name: str,
                      pass_through: Optional[Budget] = None) -> str:
        """Add a transform node: output of a non-sink tool.

        Budget propagation:
            beta(output) = Pass_t ∩ meet(beta(x) for x in inputs)

        Args:
            label: Description of the transform
            input_node_ids: IDs of input data nodes
            tool_name: Tool performing the transform
            pass_through: Tool's pass-through budget (default: top = no restriction)

        Returns:
            node_id for the new transform output
        """
        if not input_node_ids:
            raise ValueError("Transform must have at least one input")

        # Compute meet of all input budgets
        input_budgets = []
        for nid in input_node_ids:
            if nid not in self.nodes:
                raise KeyError(f"Unknown input node: {nid}")
            input_budgets.append(self.nodes[nid].budget)

        meet_budget = input_budgets[0]
        for b in input_budgets[1:]:
            meet_budget = meet_budget.meet(b)

        # Apply tool's pass-through constraint
        if pass_through is not None:
            meet_budget = meet_budget.meet(pass_through)

        node_id = f"xfm_{uuid.uuid4().hex[:8]}"
        node = DataNode(
            node_id=node_id,
            label=label,
            budget=meet_budget,
            source_ids=list(input_node_ids),
            tool_name=tool_name,
        )
        self.nodes[node_id] = node
        # Update context budget
        self._context_budget = self._context_budget.meet(meet_budget)
        return node_id

    def check_sink(self, tool_name: str,
                   requested_privilege: SinkPrivilege,
                   data_node_ids: List[str],
                   declassification_token: Optional[str] = None) -> SinkEvent:
        """Check if a sink operation is authorized by data budgets.

        Sink Soundness Theorem:
            Allow iff requested_privilege ∈ meet(beta(x) for x in data_deps)

        Args:
            tool_name: Sink tool name
            requested_privilege: The specific sink privilege requested
            data_node_ids: IDs of data items flowing to this sink
            declassification_token: Optional token for authorized escalation

        Returns:
            SinkEvent recording the authorization decision
        """
        # Compute propagated budget from all data dependencies
        # Per Algorithm 1: β_agg = (∩_{x∈D} β(x)) ∩ β_ctx
        if data_node_ids:
            budgets = []
            for nid in data_node_ids:
                if nid not in self.nodes:
                    raise KeyError(f"Unknown data node: {nid}")
                budgets.append(self.nodes[nid].budget)

            propagated = budgets[0]
            for b in budgets[1:]:
                propagated = propagated.meet(b)
            # Always intersect with context budget (paper Algorithm 1, line 2)
            propagated = propagated.meet(self._context_budget)
        else:
            # No explicit data deps: use conservative context budget alone
            propagated = self._context_budget

        # Check authorization
        authorized = propagated.authorizes(requested_privilege)
        block_reason = None

        if not authorized and declassification_token:
            # Declassification: validate token structure and scope
            authorized = self._validate_declassification(
                declassification_token, requested_privilege, data_node_ids
            )
            if authorized:
                block_reason = None
            else:
                block_reason = (
                    f"Sink {requested_privilege} not authorized; "
                    f"declassification token invalid or scope mismatch"
                )
        elif not authorized:
            block_reason = (
                f"Sink {requested_privilege} not authorized by "
                f"propagated budget {propagated}"
            )

        event = SinkEvent(
            event_id=f"sink_{uuid.uuid4().hex[:8]}",
            tool_name=tool_name,
            requested_privilege=requested_privilege,
            data_node_ids=list(data_node_ids),
            propagated_budget=propagated,
            authorized=authorized,
            declassification_token=declassification_token,
            block_reason=block_reason,
        )
        self.sink_events.append(event)
        return event

    def _validate_declassification(self, token: str,
                                       privilege: SinkPrivilege,
                                       data_node_ids: List[str]) -> bool:
        """Validate a cryptographically signed declassification token.

        A valid token must be a JSON string containing:
        - "payload": JSON with sink, lineage, user_approval, scope, token_id
        - "hmac": HMAC-SHA256 of the payload using the signing key

        The signing key is held ONLY by the trusted issuer (the system/user),
        NOT by the LLM. This prevents the LLM from forging tokens.

        Security properties:
        1. Authenticity: HMAC verification (LLM cannot forge)
        2. Sink-specific: payload.sink must match requested privilege
        3. Lineage-bound: payload.lineage must cover data dependencies
        4. User-approved: payload.user_approval must be true
        5. Replay-resistant: token_id tracked in spent set
        6. One-shot: payload.scope must be "one-shot"
        """
        import json as _json
        import hashlib
        import hmac as _hmac

        try:
            tok = _json.loads(token)
        except (TypeError, _json.JSONDecodeError):
            return False

        if not isinstance(tok, dict):
            return False

        # Must have payload and HMAC
        payload_str = tok.get("payload", "")
        provided_hmac = tok.get("hmac", "")
        if not payload_str or not provided_hmac:
            return False

        # Verify HMAC (authenticity check)
        expected_hmac = _hmac.new(
            self._signing_key, payload_str.encode(), hashlib.sha256
        ).hexdigest()
        if not _hmac.compare_digest(provided_hmac, expected_hmac):
            return False

        # Parse payload
        try:
            payload = _json.loads(payload_str)
        except (TypeError, _json.JSONDecodeError):
            return False

        # Validate payload fields
        if not payload.get("user_approval"):
            return False
        if payload.get("scope") != "one-shot":
            return False

        # Sink must match
        if payload.get("sink", "") != str(privilege):
            return False

        # Lineage must cover all data dependencies
        tok_lineage = set(payload.get("lineage", []))
        if data_node_ids and not set(data_node_ids).issubset(tok_lineage):
            return False

        # Replay prevention
        token_id = payload.get("token_id", "")
        if not token_id or token_id in self._spent_tokens:
            return False

        self._spent_tokens.add(token_id)
        return True

    def get_source_ancestors(self, node_id: str) -> Set[str]:
        """Get all source ancestor IDs for a node (for theorem verification)."""
        visited = set()
        sources = set()

        def _dfs(nid: str):
            if nid in visited:
                return
            visited.add(nid)
            node = self.nodes[nid]
            if node.is_source:
                sources.add(nid)
            for parent_id in node.source_ids:
                _dfs(parent_id)

        _dfs(node_id)
        return sources

    def verify_budget_preservation(self, node_id: str) -> bool:
        """Verify the Budget Preservation Lemma for a node.

        beta(x) <= meet(Init(o) for o in Src(x))
        """
        node = self.nodes[node_id]
        source_ids = self.get_source_ancestors(node_id)

        if not source_ids:
            return True  # No sources = trivially true

        source_budgets = [self.nodes[sid].budget for sid in source_ids]
        ancestor_meet = source_budgets[0]
        for b in source_budgets[1:]:
            ancestor_meet = ancestor_meet.meet(b)

        return node.budget.is_subset_of(ancestor_meet)

    @property
    def stats(self) -> Dict:
        """DAG statistics for evaluation."""
        total_sinks = len(self.sink_events)
        blocked = sum(1 for e in self.sink_events if not e.authorized)
        declassified = sum(
            1 for e in self.sink_events
            if e.authorized and e.declassification_token
        )
        return {
            "total_nodes": len(self.nodes),
            "source_nodes": sum(1 for n in self.nodes.values() if n.is_source),
            "transform_nodes": sum(
                1 for n in self.nodes.values() if not n.is_source
            ),
            "total_sink_events": total_sinks,
            "authorized": total_sinks - blocked,
            "blocked": blocked,
            "declassified": declassified,
        }
