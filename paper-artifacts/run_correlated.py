"""
Engine sweep under the pilot-fitted author effect. Deterministic, offline.

For each pilot condition we take the moment-matched intra-class correlation
rho (analyze_effective_m.py), author 2,000 catalogs per size under the
beta-binomial author model at marginal rate p = 0.08, and run every sensitive
source through one HTTP path in the real ChainCaps engine, exactly as in the
main sweep. This checks that the engine follows the correlated closed form as
it follows the independent one, and gives the curve at the pilot's effective M
beside the independent (g = 1) and one-decision (g = S) references.

Produces:
    results/correlated.json

Run:
    PYTHONPATH=. python run_correlated.py
"""
from __future__ import annotations

import json
import random
import statistics as stats
from pathlib import Path
from typing import Dict, List

from scaling.catalog import build_catalog, Role
from scaling.correlated import author_correlated, catalog_risk, effective_decisions
from scaling.workflows import evaluate_catalog

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results" / "correlated.json"
EFF = ROOT / "results" / "effective_m.json"

SIZES = [10, 25, 50, 100, 200, 400]
SEEDS = list(range(2000))
P = 0.08


def _wilson95(successes: int, total: int) -> List[float]:
    if total == 0:
        return [0.0, 0.0]
    z = 1.96
    p = successes / total
    denom = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / denom
    half = z * ((p * (1.0 - p) / total + z * z / (4.0 * total * total)) ** 0.5) / denom
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


def main():
    eff = json.loads(EFF.read_text())
    rhos = {cond: eff["conditions"][cond]["rho_homogeneous"]
            for cond in ("description_only", "policy_conditioned")}
    out: Dict = {"p": P, "n_seeds": len(SEEDS), "sizes": SIZES,
                 "rho": rhos, "by_condition": {}}
    for cond, rho in rhos.items():
        out["by_condition"][cond] = {}
        for n in SIZES:
            specs = build_catalog(n)
            s = sum(1 for x in specs if x.role is Role.SENSITIVE_SOURCE)
            vuln, block = [], []
            for seed in SEEDS:
                ac = author_correlated(specs, P, rho,
                                       random.Random(1000 * seed + n))
                res = evaluate_catalog(
                    specs, ac.manifests, len(ac.exfiltratable_sources),
                    ac.n_sensitive, f"rho={rho}", seed,
                    random.Random(9000 * seed + n))
                vuln.append(res.catalog_vulnerable)
                block.append(res.attack_block_rate)
            k = len(SEEDS)
            rate = sum(vuln) / k
            analytic = catalog_risk(s, P, rho)
            out["by_condition"][cond][n] = {
                "n_sensitive": s,
                "attack_block_rate_mean": round(stats.mean(block), 4),
                "catalog_vulnerable_rate": round(rate, 4),
                "catalog_vulnerable_ci95": _wilson95(sum(vuln), k),
                "catalog_vulnerable_analytic": round(analytic, 4),
                "effective_decisions_analytic": round(
                    effective_decisions(analytic, P), 2),
            }
            print(f"{cond:20s} rho={rho:.4f} N={n:3d} S={s:3d} "
                  f"block={stats.mean(block):.3f} vuln={rate:.3f} "
                  f"analytic={analytic:.3f} ci={_wilson95(sum(vuln), k)}")
    OUT.write_text(json.dumps(out, indent=2) + "\n")
    print(f"saved {OUT.name}")


if __name__ == "__main__":
    main()
