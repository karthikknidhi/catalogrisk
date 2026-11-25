"""
ChainCaps Core: Sink-Authority Budget Algebra

Implements the formal capability algebra from the paper:
- Atomic sink privileges with partial ordering
- Budgets as downward-closed subsets (ideals)
- Monotonic meet-propagation across tool chains
- Non-amplification invariant enforcement
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import FrozenSet, Optional, Set
from urllib.parse import unquote


class SinkType(Enum):
    """Atomic sink operation types."""
    DISPLAY = auto()
    SEND_HTTP = auto()
    SEND_EMAIL = auto()
    WRITE_FILE = auto()
    EXECUTE = auto()
    DB_WRITE = auto()
    MEMORY_WRITE = auto()


@dataclass(frozen=True)
class SinkPrivilege:
    """An atomic sink privilege: (operation, resource_scope).

    Examples:
        SinkPrivilege(SEND_HTTP, "api.example.com")
        SinkPrivilege(WRITE_FILE, "/tmp/*")
        SinkPrivilege(DISPLAY, "*")  # unrestricted display
    """
    operation: SinkType
    scope: str = "*"  # "*" means unrestricted within this operation

    @staticmethod
    def _canonicalize_scope(scope: str) -> str:
        """Canonicalize a scope string to prevent path-traversal bypasses.

        Decodes URL-encoded characters (e.g. %2e%2e -> ..) and then
        normalizes filesystem paths with os.path.normpath to collapse
        any '..' or '.' components.
        """
        # Step 1: decode any URL-encoded characters (%2f, %2e, etc.)
        decoded = unquote(scope)
        # Step 2: normalize filesystem paths (starts with /)
        if decoded.startswith("/"):
            decoded = os.path.normpath(decoded)
        return decoded

    def subsumes(self, other: SinkPrivilege) -> bool:
        """Check if this privilege subsumes (is more general than) another.

        send_http(*) subsumes send_http(api.example.com)
        write_file(/tmp/*) subsumes write_file(/tmp/x.txt)

        Path traversal protection: both scopes are canonicalized via
        URL-decoding and os.path.normpath before comparison, so
        /tmp/../var/www/ will NOT match /tmp/*.
        """
        if self.operation != other.operation:
            return False
        if self.scope == "*":
            return True

        canon_self = self._canonicalize_scope(self.scope)
        canon_other = self._canonicalize_scope(other.scope)

        # For HTTP operations, strip protocol prefix for domain matching
        if self.operation in (SinkType.SEND_HTTP,):
            canon_self = self._strip_protocol(canon_self)
            canon_other = self._strip_protocol(canon_other)

        if canon_self == canon_other:
            return True
        # Glob-style: /tmp/* subsumes /tmp/x.txt
        # Also: domain.com/* subsumes domain.com/path/to/resource
        if canon_self.endswith("*"):
            prefix = canon_self[:-1]
            return canon_other.startswith(prefix)
        # Domain-style: @corp.com subsumes boss@corp.com
        if canon_self.startswith("@") and canon_other.endswith(canon_self):
            return True
        return False

    @staticmethod
    def _strip_protocol(scope: str) -> str:
        """Strip http:// or https:// prefix for domain comparison."""
        for prefix in ("https://", "http://"):
            if scope.startswith(prefix):
                return scope[len(prefix):]
        return scope

    def __repr__(self) -> str:
        return f"{self.operation.name.lower()}({self.scope})"


@dataclass(frozen=True)
class Budget:
    """A sink-authority budget: downward-closed set of authorized sink privileges.

    The budget represents what future sinks data derived from this source
    may authorize. Budgets form a lattice under subset ordering with
    meet = intersection.
    """
    privileges: FrozenSet[SinkPrivilege]

    @staticmethod
    def top(sink_types: Optional[Set[SinkType]] = None) -> Budget:
        """Unrestricted budget (all sinks allowed)."""
        if sink_types is None:
            sink_types = set(SinkType)
        return Budget(frozenset(
            SinkPrivilege(op, "*") for op in sink_types
        ))

    @staticmethod
    def bottom() -> Budget:
        """Empty budget (no sinks allowed)."""
        return Budget(frozenset())

    @staticmethod
    def from_sinks(*privs: SinkPrivilege) -> Budget:
        """Create budget from explicit sink privileges."""
        return Budget(frozenset(privs))

    def meet(self, other: Budget) -> Budget:
        """Lattice meet: intersection of authorized sinks.

        This is the core attenuation operation. The result authorizes
        only sinks that BOTH budgets authorize.
        """
        # For each privilege in self, keep it only if other has a
        # privilege that subsumes it (or equals it)
        result = set()
        for p in self.privileges:
            for q in other.privileges:
                if q.subsumes(p):
                    result.add(p)
                    break
        # Symmetric: also check other's privileges against self
        for p in other.privileges:
            for q in self.privileges:
                if q.subsumes(p):
                    result.add(p)
                    break
        return Budget(frozenset(result))

    def authorizes(self, priv: SinkPrivilege) -> bool:
        """Check if this budget authorizes a specific sink privilege."""
        for p in self.privileges:
            if p.subsumes(priv):
                return True
        return False

    def is_subset_of(self, other: Budget) -> bool:
        """Check if this budget is a subset of (attenuated from) another."""
        for p in self.privileges:
            if not other.authorizes(p):
                return False
        return True

    def __le__(self, other: Budget) -> bool:
        return self.is_subset_of(other)

    def __repr__(self) -> str:
        if not self.privileges:
            return "Budget(EMPTY)"
        privs = sorted(str(p) for p in self.privileges)
        return f"Budget({', '.join(privs)})"


# --- Common budget factories ---

def budget_display_only() -> Budget:
    """Data can only be displayed to user."""
    return Budget.from_sinks(SinkPrivilege(SinkType.DISPLAY))


def budget_internal_email(scope: str = "@corp.com") -> Budget:
    """Data can be displayed or emailed internally."""
    return Budget.from_sinks(
        SinkPrivilege(SinkType.DISPLAY),
        SinkPrivilege(SinkType.SEND_EMAIL, scope),
    )


def budget_public() -> Budget:
    """Data can go anywhere (public information)."""
    return Budget.top()


def budget_sensitive_file() -> Budget:
    """Sensitive file data: display only, no network/exec."""
    return Budget.from_sinks(
        SinkPrivilege(SinkType.DISPLAY),
        SinkPrivilege(SinkType.WRITE_FILE, "/tmp/*"),
    )
