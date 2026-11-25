"""
Synthetic MCP tool-catalog generator for the manifest-scaling study.

We build catalogs of controllable size N whose *gold* (correct) manifests are
known by construction. Roles and gold budgets:

  sensitive_source : reads confidential data. Gold budget = display only.
                     Correct policy forbids exfiltration to any network sink.
  public_source    : reads public data. Gold budget = top (may go anywhere).
  transform        : pure data processing, no side effect. pass_through = top.
  http_sink        : can SEND_HTTP to a destination taken from call args.
  file_sink        : can WRITE_FILE to a path taken from call args.
  email_sink       : can SEND_EMAIL to a recipient taken from call args.

Authorization in ChainCaps is gated by the *propagated data budget*, not by the
sink manifest's own scope, so an exfiltration succeeds only if some source on
the chain was authored with an over-permissive budget. That is the single
failure channel we vary.

The role mix is held fixed as N scales so that "bigger catalog" means "more
tools of the same kinds", isolating scale from composition.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List

# Make the cloned ChainCaps artifact importable without installing it.
_CHAINCAPS = Path(__file__).resolve().parents[2] / "chaincaps-code"
if str(_CHAINCAPS) not in sys.path:
    sys.path.insert(0, str(_CHAINCAPS))

from chaincaps.core.budget import Budget, SinkPrivilege, SinkType  # noqa: E402
from chaincaps.core.manifest import ToolManifest  # noqa: E402


class Role(str, Enum):
    SENSITIVE_SOURCE = "sensitive_source"
    PUBLIC_SOURCE = "public_source"
    TRANSFORM = "transform"
    HTTP_SINK = "http_sink"
    FILE_SINK = "file_sink"
    EMAIL_SINK = "email_sink"


# Fixed role proportions (sum to 1.0). Sensitive sources and network sinks are
# the security-relevant endpoints; the mix is deliberately sink-rich to reflect
# real deployments where agents can reach many external services.
ROLE_MIX: Dict[Role, float] = {
    Role.SENSITIVE_SOURCE: 0.30,
    Role.PUBLIC_SOURCE: 0.15,
    Role.TRANSFORM: 0.25,
    Role.HTTP_SINK: 0.15,
    Role.FILE_SINK: 0.08,
    Role.EMAIL_SINK: 0.07,
}


@dataclass(frozen=True)
class ToolSpec:
    """Ground-truth description of a catalog tool (independent of any manifest)."""
    name: str
    role: Role


def _display_only() -> Budget:
    return Budget.from_sinks(SinkPrivilege(SinkType.DISPLAY))


def gold_manifest(spec: ToolSpec) -> ToolManifest:
    """The correct manifest for a tool, by construction."""
    r = spec.role
    if r is Role.SENSITIVE_SOURCE:
        return ToolManifest(
            name=spec.name, is_source=True,
            default_source_budget=_display_only(),
            description="Reads confidential records.",
        )
    if r is Role.PUBLIC_SOURCE:
        return ToolManifest(
            name=spec.name, is_source=True,
            default_source_budget=Budget.top(),
            description="Reads public data.",
        )
    if r is Role.TRANSFORM:
        return ToolManifest(
            name=spec.name, is_source=False, is_sink=False,
            pass_through=None,  # None == transparent (top) pass-through
            description="Pure data transform.",
        )
    if r is Role.HTTP_SINK:
        return ToolManifest(
            name=spec.name, is_sink=True,
            exec_privileges=[SinkPrivilege(SinkType.SEND_HTTP, "*")],
            description="Sends an HTTP request to a destination.",
        )
    if r is Role.FILE_SINK:
        return ToolManifest(
            name=spec.name, is_sink=True,
            exec_privileges=[SinkPrivilege(SinkType.WRITE_FILE, "*")],
            description="Writes a file.",
        )
    if r is Role.EMAIL_SINK:
        return ToolManifest(
            name=spec.name, is_sink=True,
            exec_privileges=[SinkPrivilege(SinkType.SEND_EMAIL, "*")],
            description="Sends an email.",
        )
    raise ValueError(r)


def _counts_for_size(n: int) -> Dict[Role, int]:
    """Largest-remainder apportionment so counts sum exactly to n."""
    raw = {r: ROLE_MIX[r] * n for r in ROLE_MIX}
    floor = {r: int(v) for r, v in raw.items()}
    remainder = n - sum(floor.values())
    # distribute leftover to the largest fractional parts
    frac_order = sorted(ROLE_MIX, key=lambda r: raw[r] - floor[r], reverse=True)
    for i in range(remainder):
        floor[frac_order[i % len(frac_order)]] += 1
    # guarantee at least one sensitive source and one http sink so an attack
    # is always expressible; borrow from the largest bucket if needed.
    for needed in (Role.SENSITIVE_SOURCE, Role.HTTP_SINK):
        if floor[needed] == 0:
            donor = max(floor, key=lambda r: floor[r])
            floor[donor] -= 1
            floor[needed] += 1
    return floor


def build_catalog(n: int) -> List[ToolSpec]:
    """Return n tool specs with the fixed role mix. Deterministic in n."""
    counts = _counts_for_size(n)
    specs: List[ToolSpec] = []
    for role, k in counts.items():
        for i in range(k):
            specs.append(ToolSpec(name=f"{role.value}_{i:03d}", role=role))
    return specs


def gold_manifests(specs: List[ToolSpec]) -> Dict[str, ToolManifest]:
    return {s.name: gold_manifest(s) for s in specs}
