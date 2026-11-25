"""
Manifest authoring models.

We do NOT ask a language model to author policies here; that would confound
"authoring is hard" with "this particular model is weak". Instead we inject
authoring errors at controlled per-tool rates whose *shape* is calibrated to
the naive-authoring error profile reported by ChainCaps (their Table: naive
classification 0.95, exec-scope 0.75, source-budget 0.55). A separate,
optional experiment checks that real LLM authoring produces the same error
shape (scaling/llm_calibration.py).

The only failure that defeats ChainCaps' monotonic enforcement is an
over-permissive (or mis-classified) *source* budget, because budgets can only
attenuate downstream. We therefore track, as ground truth, exactly which
sensitive sources were authored with an exfiltration-enabling budget.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Set

from chaincaps.core.budget import Budget, SinkPrivilege, SinkType
from chaincaps.core.manifest import ToolManifest

from scaling.catalog import Role, ToolSpec, gold_manifest


@dataclass
class AuthoringRates:
    """Per-tool probabilities of each authoring error, by authoring strategy."""
    # exfiltration-enabling errors on sensitive sources
    sens_overperm: float = 0.0   # add SEND_HTTP(*) to a sensitive source budget
    sens_misclass: float = 0.0   # author a sensitive source as public (top budget)
    label: str = "gold"


# The high-error regime is deliberately calibrated to the 27.3% attack-block
# anchor reported by ChainCaps: an effective source-error rate of 0.75 implies
# a population block rate of 0.25. It is not an independent reproduction of
# their benchmark. The low-error regime is a transparent sensitivity point,
# not an observed or named ChainCaps authoring strategy.
NAIVE_CALIBRATED = AuthoringRates(
    sens_overperm=0.55,
    sens_misclass=0.20,
    label="naive_calibrated",
)
LOW_ERROR = AuthoringRates(
    sens_overperm=0.06,
    sens_misclass=0.02,
    label="low_error",
)
GOLD = AuthoringRates(label="gold")


@dataclass
class AuthoredCatalog:
    manifests: Dict[str, ToolManifest]
    # ground-truth: sensitive sources whose authored budget permits SEND_HTTP,
    # i.e. the exploitable holes actually planted by the authoring process.
    exfiltratable_sources: Set[str] = field(default_factory=set)
    n_sensitive: int = 0


def _overpermissive_sensitive() -> Budget:
    """A sensitive source mistakenly granted network reach."""
    return Budget.from_sinks(
        SinkPrivilege(SinkType.DISPLAY),
        SinkPrivilege(SinkType.SEND_HTTP, "*"),
    )


def author(specs: List[ToolSpec], rates: AuthoringRates,
           rng: random.Random) -> AuthoredCatalog:
    """Author a manifest for every tool under the given error rates."""
    manifests: Dict[str, ToolManifest] = {}
    holes: Set[str] = set()
    n_sensitive = 0

    for spec in specs:
        m = gold_manifest(spec)  # start from correct, then possibly corrupt
        if spec.role is Role.SENSITIVE_SOURCE:
            n_sensitive += 1
            r = rng.random()
            if r < rates.sens_misclass:
                # authored as public: budget = top (exfiltration allowed)
                m = ToolManifest(name=spec.name, is_source=True,
                                 default_source_budget=Budget.top(),
                                 description=m.description)
                holes.add(spec.name)
            elif r < rates.sens_misclass + rates.sens_overperm:
                # over-permissive budget: display + SEND_HTTP(*)
                m = ToolManifest(name=spec.name, is_source=True,
                                 default_source_budget=_overpermissive_sensitive(),
                                 description=m.description)
                holes.add(spec.name)
        manifests[spec.name] = m

    return AuthoredCatalog(manifests=manifests, exfiltratable_sources=holes,
                           n_sensitive=n_sensitive)
