"""
Main scaling sweep. Deterministic, offline, no network, no API keys.

Produces:
    results/strategies.csv  -- {gold, low_error, naive_calibrated} x N x seed
  results/reliability.csv -- per-source error rate p x N x seed
    results/summary.json    -- aggregates and tolerable-rate p_max(N)

Run:
  PYTHONPATH=. python run_scaling.py
"""
from __future__ import annotations

import csv
import json
import random
import statistics as stats
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List

from scaling.catalog import build_catalog, Role
from scaling.authoring import (
    author,
    AuthoringRates,
    GOLD,
    LOW_ERROR,
    NAIVE_CALIBRATED,
)
from scaling.workflows import evaluate_catalog

OUT = Path(__file__).resolve().parent / "results"
OUT.mkdir(exist_ok=True)

SIZES = [10, 25, 50, 100, 200, 400]
SEEDS = list(range(2000))
# per-sensitive-source exfiltration-enabling error rate grid (fine at low end so
# the tolerable rate resolves even for large catalogs)
P_GRID = [0.0, 0.0001, 0.0002, 0.0003, 0.0005, 0.001, 0.002, 0.005,
          0.01, 0.02, 0.05, 0.10, 0.20]
TARGET_RISK = 0.05  # tolerated probability that a sampled catalog has >=1 hole
SENSITIVE_FRAC = 0.30  # matches catalog.ROLE_MIX[SENSITIVE_SOURCE]


def _ci95(xs: List[float]) -> float:
    if len(xs) < 2:
        return 0.0
    return 1.96 * stats.pstdev(xs) / (len(xs) ** 0.5)


def _wilson95(successes: int, total: int) -> List[float]:
    """Wilson score interval for a binomial proportion."""
    if total == 0:
        return [0.0, 0.0]
    z = 1.96
    p = successes / total
    denom = 1.0 + z * z / total
    center = (p + z * z / (2.0 * total)) / denom
    half = z * ((p * (1.0 - p) / total + z * z / (4.0 * total * total)) ** 0.5) / denom
    return [round(max(0.0, center - half), 4),
            round(min(1.0, center + half), 4)]


def run_strategies() -> List[dict]:
    rows = []
    for strat, rates in (
        ("gold", GOLD),
        ("low_error", LOW_ERROR),
        ("naive_calibrated", NAIVE_CALIBRATED),
    ):
        for n in SIZES:
            specs = build_catalog(n)
            for seed in SEEDS:
                ac = author(specs, rates, random.Random(1000 * seed + n))
                res = evaluate_catalog(
                    specs, ac.manifests, len(ac.exfiltratable_sources),
                    ac.n_sensitive, strat, seed,
                    random.Random(9000 * seed + n))
                rows.append(asdict(res))
    return rows


def run_reliability() -> List[dict]:
    rows = []
    for p in P_GRID:
        rates = AuthoringRates(sens_overperm=p, sens_misclass=0.0,
                               label=f"p={p}")
        for n in SIZES:
            specs = build_catalog(n)
            for seed in SEEDS:
                ac = author(specs, rates, random.Random(1000 * seed + n))
                res = evaluate_catalog(
                    specs, ac.manifests, len(ac.exfiltratable_sources),
                    ac.n_sensitive, f"p={p}", seed,
                    random.Random(9000 * seed + n))
                d = asdict(res)
                d["p"] = p
                rows.append(d)
    return rows


def summarize(strategy_rows, reliability_rows) -> dict:
    summary: Dict = {"target_risk": TARGET_RISK, "sizes": SIZES,
                     "n_seeds": len(SEEDS), "strategies": {}, "reliability": {},
                     "reliability_ci95": {}, "tolerable_rate": {}}

    # --- strategies: block rate, benign, catalog-vulnerable by (strategy, N) ---
    for strat in ("gold", "low_error", "naive_calibrated"):
        summary["strategies"][strat] = {}
        for n in SIZES:
            sub = [r for r in strategy_rows if r["strategy"] == strat and r["n_tools"] == n]
            br = [r["attack_block_rate"] for r in sub]
            be = [r["benign_completion_rate"] for r in sub]
            cv = [r["catalog_vulnerable"] for r in sub]
            summary["strategies"][strat][n] = {
                "attack_block_rate_mean": round(stats.mean(br), 4),
                "attack_block_rate_ci95": round(_ci95(br), 4),
                "benign_completion_mean": round(stats.mean(be), 4),
                "catalog_vulnerable_rate": round(stats.mean(cv), 4),
                "catalog_vulnerable_ci95": _wilson95(sum(cv), len(cv)),
            }

    # --- reliability grid: catalog-vulnerable rate by (p, N) ---
    for p in P_GRID:
        summary["reliability"][p] = {}
        summary["reliability_ci95"][p] = {}
        for n in SIZES:
            sub = [r for r in reliability_rows if r["p"] == p and r["n_tools"] == n]
            cv = [r["catalog_vulnerable"] for r in sub]
            summary["reliability"][p][n] = round(stats.mean(cv), 4)
            summary["reliability_ci95"][p][n] = _wilson95(sum(cv), len(cv))

    # --- tolerable per-tool rate p_max(N): largest p with insecure-rate <= target ---
    # empirical (grid) and closed-form weakest-link p_max = 1-(1-eps)^(1/S),
    # S = expected sensitive sources = SENSITIVE_FRAC * N.
    summary["tolerable_rate_analytic"] = {}
    for n in SIZES:
        ok = [p for p in P_GRID
              if summary["reliability"][p][n] <= TARGET_RISK]
        summary["tolerable_rate"][n] = max(ok) if ok else 0.0
        s_sources = max(
            sum(1 for spec in build_catalog(n)
                if spec.role is Role.SENSITIVE_SOURCE),
            1,
        )
        summary["tolerable_rate_analytic"][n] = round(
            1.0 - (1.0 - TARGET_RISK) ** (1.0 / s_sources), 5)
    # Log-log slopes for the grid estimate and the exact finite-N expression.
    import math
    ns = [math.log(n) for n in SIZES]
    def slope(xs: List[float], ys: List[float]) -> float:
        xbar, ybar = sum(xs) / len(xs), sum(ys) / len(ys)
        cov = sum((a - xbar) * (b - ybar) for a, b in zip(xs, ys))
        var = sum((a - xbar) ** 2 for a in xs)
        return cov / var

    analytic_ps = [math.log(summary["tolerable_rate_analytic"][n]) for n in SIZES]
    empirical_ps = [math.log(summary["tolerable_rate"][n]) for n in SIZES]
    summary["analytic_loglog_slope"] = round(slope(ns, analytic_ps), 3)
    summary["empirical_grid_loglog_slope"] = round(slope(ns, empirical_ps), 3)

    return summary


def main():
    strat_rows = run_strategies()
    rel_rows = run_reliability()

    with open(OUT / "strategies.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(strat_rows[0].keys()))
        w.writeheader(); w.writerows(strat_rows)
    with open(OUT / "reliability.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rel_rows[0].keys()))
        w.writeheader(); w.writerows(rel_rows)

    summary = summarize(strat_rows, rel_rows)
    with open(OUT / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # console digest
    print("=== attack block rate (mean) by strategy x N ===")
    for strat in ("gold", "low_error", "naive_calibrated"):
        line = "  ".join(
            f"N={n}:{summary['strategies'][strat][n]['attack_block_rate_mean']:.3f}"
            for n in SIZES)
        print(f"{strat:8s} {line}")
    print("\n=== catalog-vulnerable rate (>=1 tested exfil path) by strategy x N ===")
    for strat in ("gold", "low_error", "naive_calibrated"):
        line = "  ".join(
            f"N={n}:{summary['strategies'][strat][n]['catalog_vulnerable_rate']:.2f}"
            for n in SIZES)
        print(f"{strat:8s} {line}")
    print(f"\n=== tolerable per-tool error rate p_max(N) at risk<= {TARGET_RISK} ===")
    print("empirical " + "  ".join(f"N={n}:{summary['tolerable_rate'][n]}" for n in SIZES))
    print("analytic  " + "  ".join(f"N={n}:{summary['tolerable_rate_analytic'][n]}" for n in SIZES))
    print(f"empirical-grid log-log slope: {summary['empirical_grid_loglog_slope']}")
    print(f"analytic log-log slope: {summary['analytic_loglog_slope']}")
    print("\nSaved: results/strategies.csv, reliability.csv, summary.json")


if __name__ == "__main__":
    main()
