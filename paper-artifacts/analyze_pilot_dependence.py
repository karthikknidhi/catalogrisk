"""
Dependence structure of pilot authoring errors.

Section 4.4 treats correlated source errors hypothetically. The pilot models
authoring the same sensitive sources (12 models x 19 sources in the expanded
camera-ready pilot; 7 x 9 in the submitted pilot, reported under "submitted")
are replicate independent authors, so their agreement measures whether over-permission is independent
across sources or clustered. We report two robust statistics per condition:

  * source concentration: how many sources every model over-permissions, and
    the full per-source over-permission count vector;
  * author over-dispersion: the variance of the per-model over-permission count
    against the binomial variance expected under independent per-source errors.

We also report the mean pairwise correlation of over-permission across the
sources that at least one model authored differently. Analysis only; no runs.

    python analyze_pilot_dependence.py
"""
from __future__ import annotations

import itertools
import json
import statistics as st
from pathlib import Path

from scaling.pilot_data import load_pilot

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results" / "pilot_dependence.json"


def _corr(a, b):
    n = len(a)
    ma, mb = sum(a) / n, sum(b) / n
    num = sum((x - ma) * (y - mb) for x, y in zip(a, b))
    da = sum((x - ma) ** 2 for x in a) ** 0.5
    db = sum((y - mb) ** 2 for y in b) ** 0.5
    return num / (da * db) if da > 0 and db > 0 else None


def stats(models):
    out = {}
    for cond in ("description_only", "policy_conditioned"):
        rows = [m for m in models if m["condition"] == cond]
        src = [det["tool"] for det in rows[0]["details"]
               if det["over_permission"] is not None]
        mat = {s: [] for s in src}
        for m in rows:
            for det in m["details"]:
                if det["over_permission"] is not None:
                    mat[det["tool"]].append(1 if det["over_permission"] else 0)
        n_models = len(rows)
        per_source = {s: sum(v) for s, v in mat.items()}
        per_model = [sum(1 for det in m["details"]
                         if det["over_permission"] is True) for m in rows]
        p_bar = sum(per_source.values()) / (len(src) * n_models)
        var_obs = st.pvariance(per_model)
        var_bin = len(src) * p_bar * (1 - p_bar)
        pairs = [_corr(mat[i], mat[j]) for i, j in itertools.combinations(src, 2)]
        pairs = [c for c in pairs if c is not None]
        out[cond] = {
            "n_models": n_models,
            "n_sensitive": len(src),
            "marginal_overperm_rate": round(p_bar, 4),
            "per_source_overperm_count": dict(
                sorted(per_source.items(), key=lambda x: -x[1])),
            "unanimous_overperm_sources": sum(1 for c in per_source.values()
                                              if c == n_models),
            "never_overperm_sources": sum(1 for c in per_source.values()
                                          if c == 0),
            "per_model_count_variance_obs": round(var_obs, 3),
            "per_model_count_variance_binomial": round(var_bin, 3),
            "overdispersion_ratio": round(var_obs / var_bin, 2) if var_bin else None,
            "mean_pairwise_source_corr": round(st.mean(pairs), 3),
            "n_defined_pairs": len(pairs),
        }
    return out


def main():
    out = stats(load_pilot("expanded"))
    out["submitted"] = stats(load_pilot("submitted"))
    OUT.write_text(json.dumps(out, indent=2))
    for cond, r in out.items():
        if cond == "submitted":
            continue
        print(f"{cond}: unanimous={r['unanimous_overperm_sources']}/"
              f"{r['n_sensitive']}  overdispersion={r['overdispersion_ratio']}x  "
              f"mean_pair_corr={r['mean_pairwise_source_corr']}")
    print(f"saved {OUT.name}")


if __name__ == "__main__":
    main()
