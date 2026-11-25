"""
Sink-class coverage sweep. Deterministic, offline, no network, no API keys.

Converts the coverage caveat into a measurement: when source-budget errors are
distributed across outbound channels in the proportions observed in the
authoring pilot, how much of the catalog vulnerability does an HTTP-only test
set see, versus a test set that also exercises email and file sinks?

Produces:
    results/sink_coverage.json

Run:
    PYTHONPATH=. python run_sink_coverage.py
"""
from __future__ import annotations

import json
import random
import statistics as stats
from pathlib import Path
from typing import Dict, List

from scaling.catalog import build_catalog, Role
from scaling.sink_coverage import (
    PILOT_MIXES,
    author_channel,
    evaluate_coverage,
    mix_weights,
)

OUT = Path(__file__).resolve().parent / "results"
OUT.mkdir(exist_ok=True)

SIZES = [10, 25, 50, 100, 200, 400]
SEEDS = list(range(2000))
P = 0.08  # per-sensitive-source over-permission rate (matches the low-error anchor)


def _wilson95(successes: int, total: int) -> List[float]:
    if total == 0:
        return [0.0, 0.0]
    z = 1.96
    p = successes / total
    denom = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / denom
    half = z * ((p * (1.0 - p) / total + z * z / (4.0 * total * total)) ** 0.5) / denom
    return [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]


def _sensitive_count(n: int) -> int:
    return sum(1 for s in build_catalog(n) if s.role is Role.SENSITIVE_SOURCE)


def main():
    summary: Dict = {
        "p": P, "n_seeds": len(SEEDS), "sizes": SIZES,
        "pilot_channel_mix": PILOT_MIXES,
        "mixes": {},
    }
    for mix_name, counts in PILOT_MIXES.items():
        chans, probs = mix_weights(counts)
        p_http = dict(zip(chans, probs))["http"]
        summary["mixes"][mix_name] = {"channel_weights": dict(zip(chans, probs)),
                                      "by_size": {}}
        for n in SIZES:
            specs = build_catalog(n)
            s = _sensitive_count(n)
            http_hits = 0
            all_hits = 0
            for seed in SEEDS:
                mans, _ = author_channel(specs, P, counts,
                                         random.Random(1000 * seed + n))
                r = evaluate_coverage(specs, mans, mix_name, seed,
                                      random.Random(9000 * seed + n))
                http_hits += r.http_only_vulnerable
                all_hits += r.all_sink_vulnerable
            k = len(SEEDS)
            summary["mixes"][mix_name]["by_size"][n] = {
                "n_sensitive": s,
                "http_only_vulnerable_rate": round(http_hits / k, 4),
                "http_only_vulnerable_ci95": _wilson95(http_hits, k),
                "all_sink_vulnerable_rate": round(all_hits / k, 4),
                "all_sink_vulnerable_ci95": _wilson95(all_hits, k),
                # analytic weakest-link expectations
                "all_sink_analytic": round(1.0 - (1.0 - P) ** s, 4),
                "http_only_analytic": round(1.0 - (1.0 - P * p_http) ** s, 4),
            }
            print(f"{mix_name:20s} N={n:3d} S={s:3d}  "
                  f"http_only={http_hits/k:.3f}  all_sink={all_hits/k:.3f}")

    with open(OUT / "sink_coverage.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("\nSaved: results/sink_coverage.json")


if __name__ == "__main__":
    main()
