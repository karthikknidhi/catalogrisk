"""
Second-engine sweep: the same catalogs and test paths in ChainCaps and APPA.

For each regime, catalog size, and seed we author one catalog exactly as the
main sweep does (same seeds), draw the source-complete attack paths with the
same random choices, and evaluate every path in both engines: the ChainCaps
proxy engine and OpenAPPA's `appa replay` (APPA_BIN). We record per-path
agreement and each engine's catalog-vulnerable rate. A gold control also runs
the benign paths. Deterministic given the seeds; no network, no model calls.

APPA replay cost grows with catalog size, so this paired sweep uses 1,000
seeds per size up to N=200 and 300 at N=400 (the main sweep uses 2,000).

Produces:
    results/appa.json

Run:
    APPA_BIN=/path/to/appa PYTHONPATH=. python run_appa.py
"""
from __future__ import annotations

import json
import os
import random
import sys
from multiprocessing import Pool
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results" / "appa.json"

SIZES = [10, 25, 50, 100, 200, 400]
SEEDS_BY_SIZE = {10: 1000, 25: 1000, 50: 1000, 100: 1000, 200: 1000, 400: 300}
GOLD_SEEDS = 100
REGIMES = ["gold", "low_error", "naive_calibrated", "correlated_policy_fit"]


def _wilson95(k: int, n: int) -> List[float]:
    z = 1.96
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def one(args):
    regime, n, seed, rho = args
    from scaling.authoring import GOLD, LOW_ERROR, NAIVE_CALIBRATED, author
    from scaling.appa_engine import policy_toml, replay, source_label, trace
    from scaling.catalog import Role, build_catalog
    from scaling.correlated import author_correlated
    from scaling.workflows import ATTACKER_URL, LEGIT_URL, _by_role, _run_chain

    specs = build_catalog(n)
    arng = random.Random(1000 * seed + n)
    if regime == "correlated_policy_fit":
        ac = author_correlated(specs, 0.08, rho, arng)
    else:
        rates = {"gold": GOLD, "low_error": LOW_ERROR, "naive_calibrated": NAIVE_CALIBRATED}[regime]
        ac = author(specs, rates, arng)
    roles = _by_role(specs)
    http = [s.name for s in roles[Role.HTTP_SINK]]
    xf = [s.name for s in roles[Role.TRANSFORM]]
    rng = random.Random(9000 * seed + n)
    paths = []
    for s in roles[Role.SENSITIVE_SOURCE]:
        sink = rng.choice(http)
        k = rng.randint(0, min(2, len(xf)))
        chain = rng.sample(xf, k) if k and xf else []
        paths.append(("attack", s.name, chain, sink, ATTACKER_URL))
    if regime == "gold":
        for s in roles[Role.PUBLIC_SOURCE]:
            sink = rng.choice(http)
            k = rng.randint(0, min(2, len(xf)))
            chain = rng.sample(xf, k) if k and xf else []
            paths.append(("benign", s.name, chain, sink, LEGIT_URL))
    labels = {s.name: source_label(ac.manifests[s.name]) for s in roles[Role.SENSITIVE_SOURCE]}
    traces = {f"{kind}_{i:04d}": trace(src, chain, sink, "url", url)
              for i, (kind, src, chain, sink, url) in enumerate(paths)}
    appa = replay(policy_toml(specs, labels), traces)
    cc = {f"{kind}_{i:04d}": _run_chain(ac.manifests, src, chain, sink, {"url": url})
          for i, (kind, src, chain, sink, url) in enumerate(paths)}
    att = [k for k in traces if k.startswith("attack")]
    ben = [k for k in traces if k.startswith("benign")]
    return {
        "regime": regime, "n": n, "seed": seed, "S": len(att),
        "agree": sum(appa[k] == cc[k] for k in traces), "paths": len(traces),
        "appa_vuln": int(any(appa[k] for k in att)), "cc_vuln": int(any(cc[k] for k in att)),
        "appa_blocked": sum(not appa[k] for k in att),
        "benign_ok_appa": sum(appa[k] for k in ben), "benign_ok_cc": sum(cc[k] for k in ben),
        "n_benign": len(ben),
    }


def main():
    if not os.environ.get("APPA_BIN"):
        sys.exit("set APPA_BIN to the appa binary")
    rho = json.loads((ROOT / "results" / "effective_m.json").read_text()
                     )["conditions"]["policy_conditioned"]["rho_homogeneous"]
    rho = float(os.environ.get("APPA_RHO", rho))
    regimes = os.environ.get("APPA_REGIMES", ",".join(REGIMES)).split(",")
    jobs = []
    for regime in regimes:
        for n in SIZES:
            k = GOLD_SEEDS if regime == "gold" else SEEDS_BY_SIZE[n]
            jobs += [(regime, n, seed, rho) for seed in range(k)]
    with Pool(int(os.environ.get("WORKERS", "2"))) as pool:
        rows = []
        for i, r in enumerate(pool.imap_unordered(one, jobs, chunksize=4)):
            rows.append(r)
            if (i + 1) % 500 == 0:
                print(f"{i + 1}/{len(jobs)}", flush=True)
    out: Dict = {"rho_policy_fit": rho, "seeds_by_size": SEEDS_BY_SIZE,
                 "gold_seeds": GOLD_SEEDS, "by_regime": {}}
    if set(regimes) != set(REGIMES) and OUT.exists():
        # Partial rerun (e.g. a new rho): keep the other regimes' rows.
        prev = json.loads(OUT.read_text())
        out["by_regime"] = {r: v for r, v in prev["by_regime"].items() if r not in regimes}
    from scaling.appa_engine import check_mixed_label_refused
    refused, msg = check_mixed_label_refused()
    out["mixed_label_refused"] = refused
    out["mixed_label_message"] = msg
    for regime in regimes:
        out["by_regime"][regime] = {}
        for n in SIZES:
            sub = [r for r in rows if r["regime"] == regime and r["n"] == n]
            k = len(sub)
            va = sum(r["appa_vuln"] for r in sub)
            vc = sum(r["cc_vuln"] for r in sub)
            paths = sum(r["paths"] for r in sub)
            agree = sum(r["agree"] for r in sub)
            out["by_regime"][regime][n] = {
                "catalogs": k, "S": sub[0]["S"],
                "appa_catalog_vulnerable": round(va / k, 4),
                "appa_catalog_vulnerable_ci95": _wilson95(va, k),
                "chaincaps_catalog_vulnerable": round(vc / k, 4),
                "appa_attack_block_rate": round(sum(r["appa_blocked"] for r in sub)
                                                / sum(r["S"] for r in sub), 4),
                "paths": paths, "paths_agree": agree,
                "benign_completion_appa": (round(sum(r["benign_ok_appa"] for r in sub)
                                                 / sum(r["n_benign"] for r in sub), 4)
                                           if regime == "gold" else None),
            }
            print(regime, n, out["by_regime"][regime][n], flush=True)
    out["by_regime"] = {r: out["by_regime"][r] for r in REGIMES if r in out["by_regime"]}
    out["total_paths"] = total_paths = sum(c["paths"] for row in out["by_regime"].values()
                                           for c in row.values())
    out["total_paths_agree"] = total_agree = sum(c["paths_agree"] for row in out["by_regime"].values()
                                                 for c in row.values())
    OUT.write_text(json.dumps(out, indent=2) + "\n")
    print(f"agreement {total_agree}/{total_paths}; saved {OUT.name}")


if __name__ == "__main__":
    main()
