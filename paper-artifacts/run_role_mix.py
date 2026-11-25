"""
Role-mix robustness. Deterministic, offline, no network, no API keys.

Reviewer KQSD noted that the synthetic catalogs use one fixed role mix (30%
sensitive sources). Because every sensitive source is tested once, the
catalog-vulnerable rate should depend on the mix only through the number of
sensitive sources S. We check this in the real ChainCaps engine by rerunning
the low-error regime (p = 0.08) with 10%, 30%, and 50% sensitive sources (the
public-source and sink shares fixed, transforms absorbing the difference) and
comparing each cell with 1 - (1 - p)^S.

Produces:
    results/role_mix.json

Run:
    PYTHONPATH=. python run_role_mix.py
"""
from __future__ import annotations

import json
import random
import statistics as stats
from pathlib import Path
from typing import Dict, List

import scaling.catalog as catalog
from scaling.authoring import LOW_ERROR, author
from scaling.catalog import Role, build_catalog
from scaling.workflows import evaluate_catalog

OUT = Path(__file__).resolve().parent / "results" / "role_mix.json"
SIZES = [50, 100, 200]
SEEDS = list(range(2000))
P = LOW_ERROR.sens_overperm + LOW_ERROR.sens_misclass  # 0.08
SENSITIVE_FRACS = [0.10, 0.30, 0.50]
BASE = dict(catalog.ROLE_MIX)


def _mix(frac: float) -> Dict[Role, float]:
    m = dict(BASE)
    m[Role.SENSITIVE_SOURCE] = frac
    m[Role.TRANSFORM] = BASE[Role.TRANSFORM] + (BASE[Role.SENSITIVE_SOURCE] - frac)
    assert abs(sum(m.values()) - 1.0) < 1e-9 and m[Role.TRANSFORM] > 0
    return m


def _wilson95(successes: int, total: int) -> List[float]:
    z = 1.96
    p = successes / total
    denom = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / denom
    half = z * ((p * (1.0 - p) / total + z * z / (4.0 * total * total)) ** 0.5) / denom
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


def main():
    out: Dict = {"p": P, "n_seeds": len(SEEDS), "sizes": SIZES, "by_frac": {}}
    try:
        for frac in SENSITIVE_FRACS:
            catalog.ROLE_MIX.clear()
            catalog.ROLE_MIX.update(_mix(frac))
            out["by_frac"][str(frac)] = {}
            for n in SIZES:
                specs = build_catalog(n)
                s = sum(1 for x in specs if x.role is Role.SENSITIVE_SOURCE)
                vuln, block = [], []
                for seed in SEEDS:
                    ac = author(specs, LOW_ERROR, random.Random(1000 * seed + n))
                    r = evaluate_catalog(specs, ac.manifests,
                                         len(ac.exfiltratable_sources),
                                         ac.n_sensitive, f"frac={frac}", seed,
                                         random.Random(9000 * seed + n))
                    vuln.append(r.catalog_vulnerable)
                    block.append(r.attack_block_rate)
                k = len(SEEDS)
                ci = _wilson95(sum(vuln), k)
                analytic = 1.0 - (1.0 - P) ** s
                out["by_frac"][str(frac)][n] = {
                    "n_sensitive": s,
                    "attack_block_rate_mean": round(stats.mean(block), 4),
                    "catalog_vulnerable_rate": round(sum(vuln) / k, 4),
                    "catalog_vulnerable_ci95": ci,
                    "analytic": round(analytic, 4),
                    "analytic_inside_ci": ci[0] <= analytic <= ci[1],
                }
                print(f"frac={frac:.2f} N={n:3d} S={s:3d} block={stats.mean(block):.3f} "
                      f"vuln={sum(vuln)/k:.3f} analytic={analytic:.3f} ci={ci}")
    finally:
        catalog.ROLE_MIX.clear()
        catalog.ROLE_MIX.update(BASE)
    OUT.write_text(json.dumps(out, indent=2) + "\n")
    print(f"saved {OUT.name}")


if __name__ == "__main__":
    main()
