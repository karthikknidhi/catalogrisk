"""
Figure 1: the paper's argument in two panels, drawn at its printed size.

(a) Synthetic catalogs at an 8% source-budget error rate: per-attack blocking
    stays flat while the catalog-vulnerable rate rises with catalog size, in
    ChainCaps (2,000 draws per size) and OpenAPPA (paired subset), under
    independent authoring; the author-effect fit to the pilot and one shared
    decision bound how far correlated authoring bends the curve.
(b) Real MCP catalogs with measured errors: per-attack blocking stays near
    0.89 while the share of authors whose catalog is vulnerable rises with the
    number of restricted tools S, following the author-effect model fitted to
    the same answers rather than independence.

Okabe-Ito colours (colour-blind safe), Type-42 fonts.

    PYTHONPATH=. python analyze_teaser.py
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
matplotlib.rcParams["font.size"] = 8.5
import matplotlib.pyplot as plt  # noqa: E402

from scaling.correlated import catalog_risk  # noqa: E402

ROOT = Path(__file__).resolve().parent
R = ROOT / "results"
FIG = ROOT / "figures"
FIG.mkdir(exist_ok=True)

BLUE, ORANGE, VERM, SKY, GREY, BLACK = "#0072B2", "#E69F00", "#D55E00", "#56B4E9", "#7f7f7f", "#222222"


def main():
    summary = json.loads((R / "summary.json").read_text())
    appa = json.loads((R / "appa.json").read_text())
    cor = json.loads((R / "correlated.json").read_text())
    real = json.loads((R / "real_catalog.json").read_text())
    sizes = summary["sizes"]
    low = summary["strategies"]["low_error"]
    pol = cor["by_condition"]["policy_conditioned"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.0, 2.45))
    lab = dict(fontsize=7, va="center")

    # ---- (a) synthetic: direct labels instead of a legend ----
    blk = [low[str(n)]["attack_block_rate_mean"] for n in sizes]
    ind = [low[str(n)]["catalog_vulnerable_rate"] for n in sizes]
    app = [appa["by_regime"]["low_error"][str(n)]["appa_catalog_vulnerable"] for n in sizes]
    fit = [pol[str(n)]["catalog_vulnerable_rate"] for n in sizes]
    ax1.plot(sizes, blk, "-o", color=BLACK, ms=3.2, lw=1.2)
    ax1.plot(sizes, ind, "-s", color=BLUE, ms=3.2, lw=1.4)
    ax1.plot(sizes, app, "s", mfc="none", mec=SKY, ms=6.5, mew=1.0)
    ax1.plot(sizes, fit, "-^", color=ORANGE, ms=3.2, lw=1.4)
    ax1.plot(sizes, [0.08] * len(sizes), "--", color=GREY, lw=1.1)
    ax1.text(10.5, 0.985, "per-attack blocking", color=BLACK, **lab)
    ax1.text(98, 0.68, "catalog vulnerable,\nindependent errors\n(open: OpenAPPA)", color=BLUE, **lab)
    ax1.text(115, 0.21, "pilot fit\n" + r"($\hat\rho=%.2f$)" % cor["rho"]["policy_conditioned"],
             color=ORANGE, **lab)
    ax1.text(60, 0.035, "one shared decision", color=GREY, **lab)
    ax1.set_xscale("log")
    ax1.set_xticks(sizes)
    ax1.set_xticklabels(sizes)
    ax1.set_ylim(-0.02, 1.06)
    ax1.set_xlabel("tool catalog size $N$")
    ax1.set_ylabel("rate")
    ax1.set_title("(a) synthetic catalogs, 8% error rate", fontsize=8.5)
    ax1.grid(alpha=0.3)

    # ---- (b) real MCP catalogs, measured errors ----
    deps = [("sentry", "Sentry"), ("launchdarkly", "LD"), ("github", "GitHub"),
            ("posthog", "PostHog"), ("github+posthog+launchdarkly+sentry", "all four")]
    s_dense = list(range(1, 101))
    ends = {}
    for cond, col, mk in (("description_only", VERM, "D"), ("policy_conditioned", ORANGE, "^")):
        a = real["conditions"][cond]["all"]
        p, rho = a["network_overperm_rate"], a["rho_homogeneous"]
        S = [a["by_deployment"][d]["S"] for d, _ in deps]
        ax2.plot(S, [a["by_deployment"][d]["vulnerable_share"] for d, _ in deps], mk, color=col, ms=4.3)
        ax2.plot(s_dense, [catalog_risk(s, p, rho) for s in s_dense], "-", color=col, lw=1.2)
        ax2.plot(s_dense, [1 - (1 - p) ** s for s in s_dense], ":", color=col, lw=1.1)
        ends[cond] = catalog_risk(100, p, rho)
    S = [real["conditions"]["description_only"]["all"]["by_deployment"][d]["S"] for d, _ in deps]
    blk = [(real["conditions"]["description_only"]["all"]["by_deployment"][d]["mean_http_block_rate"]
            + real["conditions"]["policy_conditioned"]["all"]["by_deployment"][d]["mean_http_block_rate"]) / 2
           for d, _ in deps]
    ax2.plot(S, blk, "o", color=BLACK, ms=3.2)
    ax2.text(48, 0.80, "per-attack blocking", color=BLACK, **lab)
    ax2.text(13, 0.63, "independence\n(dotted)", color=GREY, **lab)
    ax2.text(60, 0.68, "description only", color=VERM, **lab)
    ax2.text(52, ends["policy_conditioned"] - 0.085, "policy-conditioned", color=ORANGE, **lab)
    ax2.set_xticks(S)
    ax2.set_xticklabels([str(s) for s in S])
    ax2.set_xlim(0, 100)
    ax2.set_ylim(-0.02, 1.06)
    ax2.set_xlabel("restricted tools in the catalog $S$")
    ax2.set_title("(b) real MCP catalogs, measured errors", fontsize=8.5)
    ax2.grid(alpha=0.3)
    fig.tight_layout(w_pad=1.0)
    fig.savefig(FIG / "teaser.pdf")
    plt.close(fig)
    print("wrote figures/teaser.pdf")


if __name__ == "__main__":
    main()
