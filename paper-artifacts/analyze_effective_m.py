"""
Effective number of independent policy decisions, estimated from the pilot.

Reviewer request: Section 4.4 names M (independent source-policy decisions) as
the scaling variable but never estimates it. The pilot carries the needed
ingredient: every model authors the same sensitive sources, and the per-model
over-permission count is over-dispersed relative to independent per-source
errors. The camera-ready uses the expanded pilot (15 models: 12 local and 3
hosted frontier models; 19 sensitive sources; results/llm_calibration_v2.json)
and also reports the submitted pilot (7 models, 9 sources), local-only and
frontier-only fits, subsets, and leave-one-author-out estimates. We moment-match that dispersion to a beta-binomial author
effect (scaling/correlated.py) and report what it implies at the paper's
operating point (p = 0.08) for every catalog size.

Estimator (per condition). Let K_m be model m's over-permission count over the S
sensitive sources, p_bar the pooled rate, and D = Var(K) / [S p_bar (1-p_bar)] the
dispersion ratio (population variance, as in analyze_pilot_dependence.py).
Under the beta-binomial, D = 1 + (S-1) rho, so rho_hat = (D-1)/(S-1), clipped
to [0, 1). A second, heterogeneity-adjusted estimate replaces the binomial
variance with sum_i p_i (1-p_i), which allows per-source difficulty to differ;
it is reported as a sensitivity check. Uncertainty comes from resampling the
models with replacement (10,000 resamples, fixed seed).

Transfer assumption: rho is estimated where the pilot's marginal rate is
0.43-0.68 and applied at p = 0.08. That is an assumption, stated in the paper.

    PYTHONPATH=. python analyze_effective_m.py
"""
from __future__ import annotations

import json
import random
import statistics as st
from pathlib import Path

from scaling.catalog import Role, build_catalog
from scaling.correlated import catalog_risk, effective_decisions
from scaling.pilot_data import ORIGINAL_MODELS, ORIGINAL_SOURCES, load_pilot, restrict

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results" / "effective_m.json"

P = 0.08
SIZES = [10, 25, 50, 100, 200, 400]
N_BOOT = 10_000
BOOT_SEED = 20261103


def _matrix(models, cond):
    rows = [m for m in models if m["condition"] == cond]
    sources = [d["tool"] for d in rows[0]["details"]
               if d["over_permission"] is not None]
    # mat[m][i] = 1 if model m over-permissions source i
    mat = []
    for m in rows:
        by_tool = {d["tool"]: d for d in m["details"]}
        mat.append([1 if by_tool[s]["over_permission"] else 0 for s in sources])
    return [m["model"] for m in rows], sources, mat


def _rho_homogeneous(mat) -> float:
    s = len(mat[0])
    counts = [sum(r) for r in mat]
    p_bar = sum(counts) / (len(mat) * s)
    var_bin = s * p_bar * (1 - p_bar)
    if var_bin == 0:
        return 0.0
    d = st.pvariance(counts) / var_bin
    return min(max((d - 1) / (s - 1), 0.0), 0.999)


def _rho_heterogeneous(mat) -> float:
    s = len(mat[0])
    n = len(mat)
    counts = [sum(r) for r in mat]
    p_i = [sum(r[i] for r in mat) / n for i in range(s)]
    var_ind = sum(q * (1 - q) for q in p_i)
    if var_ind == 0:
        return 0.0
    d = st.pvariance(counts) / var_ind
    return min(max((d - 1) / (s - 1), 0.0), 0.999)


def _pct(xs, q):
    xs = sorted(xs)
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def _curve(rho):
    out = {}
    for n in SIZES:
        s = sum(1 for x in build_catalog(n) if x.role is Role.SENSITIVE_SOURCE)
        risk = catalog_risk(s, P, rho)
        out[n] = {"n_sensitive": s, "catalog_vulnerable": round(risk, 4),
                  "effective_decisions": round(effective_decisions(risk, P), 2)}
    return out


def _fit(models, rng, s200):
    """Point estimates, curves and author bootstrap for both conditions."""
    res = {}
    for cond in ("description_only", "policy_conditioned"):
        names, sources, mat = _matrix(models, cond)
        counts = [sum(r) for r in mat]
        rho_h = _rho_homogeneous(mat)
        rho_x = _rho_heterogeneous(mat)
        p_bar = sum(counts) / (len(mat) * len(sources))
        boots_rho, boots_risk, boots_m = [], [], []
        for _ in range(N_BOOT):
            sample = [mat[rng.randrange(len(mat))] for _ in mat]
            r = _rho_homogeneous(sample)
            risk = catalog_risk(s200, P, r)
            boots_rho.append(r)
            boots_risk.append(risk)
            boots_m.append(effective_decisions(risk, P))
        res[cond] = {
            "models": names,
            "per_model_overperm_count": dict(zip(names, counts)),
            "n_sensitive_pilot": len(sources),
            "marginal_overperm_rate": round(p_bar, 4),
            "dispersion_ratio": round(st.pvariance(counts)
                                      / (len(sources) * p_bar * (1 - p_bar)), 2),
            "rho_homogeneous": round(rho_h, 4),
            "rho_heterogeneity_adjusted": round(rho_x, 4),
            "curve_rho_homogeneous": _curve(rho_h),
            "curve_rho_heterogeneity_adjusted": _curve(rho_x),
            "bootstrap_N200": {
                "rho_median": round(_pct(boots_rho, 0.5), 4),
                "rho_95": [round(_pct(boots_rho, 0.025), 4),
                           round(_pct(boots_rho, 0.975), 4)],
                "catalog_vulnerable_median": round(_pct(boots_risk, 0.5), 4),
                "catalog_vulnerable_95": [round(_pct(boots_risk, 0.025), 4),
                                          round(_pct(boots_risk, 0.975), 4)],
                "effective_decisions_median": round(_pct(boots_m, 0.5), 2),
                "effective_decisions_95": [round(_pct(boots_m, 0.025), 2),
                                           round(_pct(boots_m, 0.975), 2)],
            },
        }
    return res


def _point(models, cond, s200):
    _, sources, mat = _matrix(models, cond)
    rho = _rho_homogeneous(mat)
    risk = catalog_risk(s200, P, rho)
    return {"authors": len(mat), "sources": len(sources), "rho_homogeneous": round(rho, 4),
            "catalog_vulnerable_N200": round(risk, 4),
            "effective_decisions_N200": round(effective_decisions(risk, P), 2)}


def _tolerable(rho, eps=0.05):
    """p_max(N): the error rate giving catalog risk eps at fixed rho (bisection)."""
    import math
    res = {}
    for n in SIZES:
        s = sum(1 for x in build_catalog(n) if x.role is Role.SENSITIVE_SOURCE)
        lo, hi = 1e-9, eps
        for _ in range(200):
            mid = (lo + hi) / 2
            if catalog_risk(s, mid, rho) < eps:
                lo = mid
            else:
                hi = mid
        res[n] = round(lo, 7)
    xs = [math.log(n) for n in SIZES]
    ys = [math.log(res[n]) for n in SIZES]
    xb, yb = sum(xs) / len(xs), sum(ys) / len(ys)
    slope = (sum((a - xb) * (b - yb) for a, b in zip(xs, ys))
             / sum((a - xb) ** 2 for a in xs))
    return {"p_max": res, "loglog_slope": round(slope, 3)}


def main():
    s200 = sum(1 for x in build_catalog(200) if x.role is Role.SENSITIVE_SOURCE)
    expanded = load_pilot("expanded")
    submitted = load_pilot("submitted")
    out = {"p": P, "n_boot": N_BOOT, "boot_seed": BOOT_SEED,
           "sizes": SIZES, "pilot": "expanded (15 models: 12 local, 3 frontier; 19 sensitive sources)",
           "reference": {"independent": _curve(0.0),
                         "one_shared_decision": _curve(1.0)}}
    # Main estimate: the expanded pilot. Same seed and draw order as the
    # submission (description-only first), so each block is reproducible alone.
    out["conditions"] = _fit(expanded, random.Random(BOOT_SEED), s200)
    out["submitted_pilot"] = _fit(submitted, random.Random(BOOT_SEED), s200)
    names = sorted({m["model"] for m in expanded})
    frontier = [n for n in names if n.startswith("claude")]
    local = [n for n in names if n not in frontier]
    new_sources = [d["tool"] for d in expanded[0]["details"]
                   if d["over_permission"] is not None and d["tool"] not in ORIGINAL_SOURCES]
    sens = {}
    for cond in ("description_only", "policy_conditioned"):
        sens[cond] = {
            "local_models_only": _point(restrict(expanded, local), cond, s200),
            "frontier_models_only": _point(restrict(expanded, frontier), cond, s200),
            "original_7_models_19_sources": _point(restrict(expanded, ORIGINAL_MODELS), cond, s200),
            "all_models_original_9_sources": _point(restrict(expanded, None, ORIGINAL_SOURCES), cond, s200),
            "all_models_10_new_sources": _point(restrict(expanded, None, new_sources), cond, s200),
            "leave_one_author_out": {n: _point(restrict(expanded, [x for x in names if x != n]),
                                               cond, s200) for n in names},
        }
    out["sensitivity"] = sens
    out["tolerable_rate_eps05"] = {
        cond: _tolerable(out["conditions"][cond]["rho_homogeneous"])
        for cond in ("description_only", "policy_conditioned")}
    out["tolerable_rate_eps05"]["submitted_policy_conditioned"] = _tolerable(
        out["submitted_pilot"]["policy_conditioned"]["rho_homogeneous"])
    OUT.write_text(json.dumps(out, indent=2) + "\n")
    for cond, r in out["conditions"].items():
        c = r["curve_rho_homogeneous"][200]
        b = r["bootstrap_N200"]
        print(f"{cond}: rho={r['rho_homogeneous']} (het-adj {r['rho_heterogeneity_adjusted']})"
              f"  N=200 risk={c['catalog_vulnerable']} M_eff={c['effective_decisions']}"
              f"  boot risk 95%={b['catalog_vulnerable_95']} M_eff 95%={b['effective_decisions_95']}")
        for n in SIZES:
            h = r["curve_rho_homogeneous"][n]; x = r["curve_rho_heterogeneity_adjusted"][n]
            print(f"   N={n:3d} S={h['n_sensitive']:3d} risk={h['catalog_vulnerable']:.3f} M={h['effective_decisions']:5.1f}"
                  f" | het-adj risk={x['catalog_vulnerable']:.3f} M={x['effective_decisions']:5.1f}")
    for cond, r in out["sensitivity"].items():
        loo = [v["effective_decisions_N200"] for v in r["leave_one_author_out"].values()]
        print(f"{cond}: leave-one-out M_eff {min(loo)}-{max(loo)}; "
              f"7x19 {r['original_7_models_19_sources']['effective_decisions_N200']}; "
              f"12x9 {r['all_models_original_9_sources']['effective_decisions_N200']}")
    print("independent N=200:", out["reference"]["independent"][200])
    print(f"saved {OUT.name}")


if __name__ == "__main__":
    main()
