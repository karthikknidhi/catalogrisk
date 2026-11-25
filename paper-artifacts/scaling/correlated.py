"""
Correlated (author-effect) manifest authoring.

The main sweep draws one authoring error independently for each sensitive
source. Reviewers asked what happens under the dependence the local-model pilot
actually shows. We model it with the standard over-dispersed binomial: each
catalog has one author whose error propensity pi is drawn from a Beta
distribution with mean p and intra-class correlation rho,

    pi ~ Beta(a, b),  a = p (1/rho - 1),  b = (1-p) (1/rho - 1),

and, given pi, each sensitive source is over-permissioned independently with
probability pi. rho = 0 recovers the independent sweep; rho -> 1 recovers one
shared decision for the whole catalog. The marginal per-source error rate is p
for every rho, so per-attack blocking stays at 1 - p.

Under this model the catalog-vulnerable probability for S sensitive sources is

    1 - E[(1-pi)^S] = 1 - B(a, b + S) / B(a, b),

and the effective number of independent decisions is the M that gives the same
catalog risk under independence: M_eff = ln(1 - risk) / ln(1 - p).
"""
from __future__ import annotations

import math
import random
from typing import Dict, List, Tuple

from chaincaps.core.manifest import ToolManifest

from scaling.authoring import AuthoredCatalog, _overpermissive_sensitive
from scaling.catalog import Role, ToolSpec, gold_manifest


def beta_params(p: float, rho: float) -> Tuple[float, float]:
    if not 0.0 < rho < 1.0:
        raise ValueError("rho must lie strictly between 0 and 1")
    k = 1.0 / rho - 1.0
    return p * k, (1.0 - p) * k


def _log_beta(a: float, b: float) -> float:
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)


def catalog_risk(n_sensitive: int, p: float, rho: float) -> float:
    """Exact P(at least one over-permissioned source) under the beta-binomial."""
    if rho <= 0.0:
        return 1.0 - (1.0 - p) ** n_sensitive
    if rho >= 1.0:
        return p
    a, b = beta_params(p, rho)
    return 1.0 - math.exp(_log_beta(a, b + n_sensitive) - _log_beta(a, b))


def effective_decisions(risk: float, p: float) -> float:
    """Independent decisions that would give the same catalog risk."""
    if risk <= 0.0:
        return 0.0
    if risk >= 1.0:
        return float("inf")
    return math.log(1.0 - risk) / math.log(1.0 - p)


def author_correlated(specs: List[ToolSpec], p: float, rho: float,
                      rng: random.Random) -> AuthoredCatalog:
    """Author one catalog under the author-effect model (HTTP over-permission)."""
    if rho <= 0.0:
        pi = p
    else:
        a, b = beta_params(p, rho)
        pi = rng.betavariate(a, b)
    manifests: Dict[str, ToolManifest] = {}
    holes = set()
    n_sensitive = 0
    for spec in specs:
        m = gold_manifest(spec)
        if spec.role is Role.SENSITIVE_SOURCE:
            n_sensitive += 1
            if rng.random() < pi:
                m = ToolManifest(name=spec.name, is_source=True,
                                 default_source_budget=_overpermissive_sensitive(),
                                 description=m.description)
                holes.add(spec.name)
        manifests[spec.name] = m
    return AuthoredCatalog(manifests=manifests, exfiltratable_sources=holes,
                           n_sensitive=n_sensitive)
