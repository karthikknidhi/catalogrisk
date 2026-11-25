"""
Coverage sweep over the HTTP share of excess channels. Deterministic, offline.

Reviewer request: the HTTP-only vs all-sink contrast in Table 4 draws each
over-permissioned source's excess channel from the pilot's 63-decision channel
counts. The claim that an HTTP-only test cannot see non-HTTP errors does not
depend on that mix, so we sweep the HTTP fraction h of the excess channel from
0 to 1 (the remainder split evenly between email and file) and evaluate the
same authored catalogs under HTTP-only and all-sink coverage in the real
ChainCaps engine. Under independent errors the closed forms are

    all sinks : 1 - (1 - p)^S
    HTTP only : 1 - (1 - p h)^S

so an HTTP-only test under-reports for every h < 1, independently of the pilot.

Produces:
    results/coverage_fraction.json

Run:
    PYTHONPATH=. python run_coverage_fraction.py
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict, List

from scaling.catalog import build_catalog, Role
from scaling.sink_coverage import author_channel, evaluate_coverage

OUT = Path(__file__).resolve().parent / "results" / "coverage_fraction.json"

SIZES = [50, 100, 200, 400]
SEEDS = list(range(2000))
P = 0.08
H_GRID = [0.0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1.0]


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
    out: Dict = {"p": P, "n_seeds": len(SEEDS), "sizes": SIZES,
                 "h_grid": H_GRID, "by_h": {}}
    for h in H_GRID:
        mix = {"http": h, "email": (1.0 - h) / 2.0, "file": (1.0 - h) / 2.0}
        out["by_h"][str(h)] = {}
        for n in SIZES:
            specs = build_catalog(n)
            s = sum(1 for x in specs if x.role is Role.SENSITIVE_SOURCE)
            http_hits = all_hits = 0
            for seed in SEEDS:
                mans, _ = author_channel(specs, P, mix,
                                         random.Random(1000 * seed + n))
                r = evaluate_coverage(specs, mans, f"h={h}", seed,
                                      random.Random(9000 * seed + n))
                http_hits += r.http_only_vulnerable
                all_hits += r.all_sink_vulnerable
            k = len(SEEDS)
            out["by_h"][str(h)][n] = {
                "n_sensitive": s,
                "http_only_vulnerable_rate": round(http_hits / k, 4),
                "http_only_vulnerable_ci95": _wilson95(http_hits, k),
                "all_sink_vulnerable_rate": round(all_hits / k, 4),
                "all_sink_vulnerable_ci95": _wilson95(all_hits, k),
                "http_only_analytic": round(1.0 - (1.0 - P * h) ** s, 4),
                "all_sink_analytic": round(1.0 - (1.0 - P) ** s, 4),
            }
            print(f"h={h:<5} N={n:3d} S={s:3d} http_only={http_hits/k:.3f} "
                  f"(analytic {1-(1-P*h)**s:.3f})  all={all_hits/k:.3f}")
    OUT.write_text(json.dumps(out, indent=2) + "\n")
    print(f"saved {OUT.name}")


if __name__ == "__main__":
    main()
