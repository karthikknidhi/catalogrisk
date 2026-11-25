"""Publication figures from results/summary.json. Type-42 fonts, no Type-3.

    PYTHONPATH=. python analyze_plots.py
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
matplotlib.rcParams["font.size"] = 9  # drawn near final size
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent
FIG = ROOT / "figures"
FIG.mkdir(exist_ok=True)
S = json.load(open(ROOT / "results" / "summary.json"))
SIZES = S["sizes"]
STRATS = ["gold", "low_error", "naive_calibrated"]
LABEL = {
    "gold": "gold ($p=0$)",
    "low_error": "low-error ($p=0.08$)",
    "naive_calibrated": "calibrated-high ($p=0.75$)",
}
COL = {"gold": "#1b7837", "low_error": "#e08214",
       "naive_calibrated": "#b2182b"}
MK = {"gold": "o", "low_error": "s", "naive_calibrated": "^"}


def fig_contrast():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.0, 2.35))
    for st in STRATS:
        br = [S["strategies"][st][str(n)]["attack_block_rate_mean"] for n in SIZES]
        si = [S["strategies"][st][str(n)]["catalog_vulnerable_rate"] for n in SIZES]
        ax1.plot(SIZES, br, marker=MK[st], color=COL[st], label=LABEL[st])
        ax2.plot(SIZES, si, marker=MK[st], color=COL[st], label=LABEL[st])
    ax1.set_xscale("log"); ax2.set_xscale("log")
    ax1.set_xlabel("tool catalog size $N$"); ax2.set_xlabel("tool catalog size $N$")
    ax1.set_ylabel("per-attack block rate")
    ax2.set_ylabel(r"P(catalog has $\geq 1$ tested hole)")
    ax1.set_title("(a) per-attack view")
    ax2.set_title("(b) catalog-level view")
    ax1.set_ylim(-0.03, 1.03); ax2.set_ylim(-0.03, 1.03)
    ax1.set_xticks(SIZES); ax1.set_xticklabels(SIZES)
    ax2.set_xticks(SIZES); ax2.set_xticklabels(SIZES)
    ax1.legend(frameon=False, loc="center left", fontsize=8)
    ax1.grid(alpha=0.3); ax2.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIG / "contrast.pdf"); plt.close(fig)
    print("wrote figures/contrast.pdf")


def fig_tolerable():
    emp = [S["tolerable_rate"][str(n)] for n in SIZES]
    ana = [S["tolerable_rate_analytic"][str(n)] for n in SIZES]
    fig, ax = plt.subplots(figsize=(3.0, 2.35))
    ax.plot(SIZES, ana, "-", color="#2166ac",
            label=r"exact: $1-(1-\epsilon)^{1/M}$")
    ax.plot(SIZES, emp, "o", color="#b2182b", markersize=4,
            label=r"engine, $p$ grid (slope $%.2f$)" % S["empirical_grid_loglog_slope"])
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("tool catalog size $N$")
    ax.set_ylabel(r"tolerable error rate $p_{\max}$")
    ax.set_xticks(SIZES); ax.set_xticklabels(SIZES)
    ax.legend(frameon=False, loc="lower left", fontsize=7.5)
    ax.grid(alpha=0.3, which="both")
    fig.tight_layout()
    fig.savefig(FIG / "tolerable_rate.pdf"); plt.close(fig)
    print("wrote figures/tolerable_rate.pdf")


if __name__ == "__main__":
    fig_contrast()
    fig_tolerable()
