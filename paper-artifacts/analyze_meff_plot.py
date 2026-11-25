"""Figure: catalog vulnerability at the pilot's effective M beside g=1 and g=S.

Reviewer xgoo asked for the curve at the moment-matched effective M plotted
beside the independent (g = 1) case. Lines are the closed forms; markers are
engine measurements (results/summary.json for g = 1, results/correlated.json
for the pilot fits); the shaded band is the 95% bootstrap range of the
policy-conditioned fit, resampling the seven pilot models (same seed as
analyze_effective_m.py). Type-42 fonts.

    PYTHONPATH=. python analyze_meff_plot.py
"""
from __future__ import annotations

import json
import random
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
matplotlib.rcParams["font.size"] = 9  # drawn near final size
import matplotlib.pyplot as plt  # noqa: E402

from analyze_effective_m import BOOT_SEED, N_BOOT, P, _matrix, _pct, _rho_homogeneous
from scaling.pilot_data import load_pilot
from scaling.catalog import Role, build_catalog
from scaling.correlated import catalog_risk

ROOT = Path(__file__).resolve().parent
FIG = ROOT / "figures"
FIG.mkdir(exist_ok=True)


def main():
    summary = json.loads((ROOT / "results" / "summary.json").read_text())
    cor = json.loads((ROOT / "results" / "correlated.json").read_text())
    models = load_pilot("expanded")
    sizes = [10, 25, 50, 100, 200, 400]
    dense = sizes
    s_of = lambda n: sum(1 for x in build_catalog(n) if x.role is Role.SENSITIVE_SOURCE)
    s_dense = [s_of(n) for n in dense]

    # bootstrap band for the policy-conditioned fit (same procedure and seed
    # as analyze_effective_m.py, which draws description-only first)
    rng = random.Random(BOOT_SEED)
    _, _, mat_d = _matrix(models, "description_only")
    for _ in range(N_BOOT):
        [mat_d[rng.randrange(len(mat_d))] for _ in mat_d]
    _, _, mat_p = _matrix(models, "policy_conditioned")
    rhos = []
    for _ in range(N_BOOT):
        sample = [mat_p[rng.randrange(len(mat_p))] for _ in mat_p]
        rhos.append(_rho_homogeneous(sample))
    lo = [_pct([catalog_risk(s, P, r) for r in rhos], 0.025) for s in s_dense]
    hi = [_pct([catalog_risk(s, P, r) for r in rhos], 0.975) for s in s_dense]

    fig, ax = plt.subplots(figsize=(6.0, 2.7))
    ax.fill_between(dense, lo, hi, color="#E69F00", alpha=0.18, linewidth=0,
                    label="policy fit, 95% bootstrap")
    curves = [
        ("independent ($g=1$, $M=S$)", 0.0, "#2166ac", "o",
         [summary["strategies"]["low_error"][str(n)]["catalog_vulnerable_rate"] for n in sizes]),
        (rf"pilot, description only ($\hat\rho={cor['rho']['description_only']:.2f}$)",
         cor["rho"]["description_only"],
         "#D55E00", "s",
         [cor["by_condition"]["description_only"][str(n)]["catalog_vulnerable_rate"] for n in sizes]),
        (rf"pilot, policy supplied ($\hat\rho={cor['rho']['policy_conditioned']:.2f}$)",
         cor["rho"]["policy_conditioned"],
         "#E69F00", "^",
         [cor["by_condition"]["policy_conditioned"][str(n)]["catalog_vulnerable_rate"] for n in sizes]),
        ("one shared decision ($g=S$): $p=0.08$", 1.0, "#555555", None, None),
    ]
    for label, rho, col, mk, measured in curves:
        ax.plot(dense, [catalog_risk(s, P, rho) for s in s_dense], "-", color=col,
                label=label)
        if measured is not None:
            ax.plot(sizes, measured, mk, color=col, markersize=5)
    ax.set_xscale("log")
    ax.set_xticks(sizes)
    ax.set_xticklabels(sizes)
    ax.set_ylim(0, 1.03)
    ax.set_title("per-attack blocking is $1-p=0.92$ in every regime", fontsize=8.5)
    ax.set_xlabel("tool catalog size $N$")
    ax.set_ylabel(r"P(catalog has $\geq 1$ tested hole)")
    ax.grid(alpha=0.3)
    ax.legend(frameon=False, fontsize=7.5, loc="center left", bbox_to_anchor=(1.01, 0.5))
    fig.tight_layout()
    fig.savefig(FIG / "effective_m.pdf")
    plt.close(fig)
    print("wrote figures/effective_m.pdf")


if __name__ == "__main__":
    main()
