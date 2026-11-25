"""Exact sensitivity analysis for correlated manifest-authoring errors.

The main sweep draws one authoring error independently for each sensitive
source. This script makes that assumption explicit by grouping sources. All
sources in a group share one authoring decision; groups are independent. For S
sensitive sources, group size g, and marginal group-error probability p:

    P(catalog vulnerable) = 1 - (1-p)^ceil(S/g).

With fixed g, the effective number of decisions still grows with N and the
allowable error rate is O(1/N). With one catalog-wide decision (g=S), catalog
risk equals p and does not grow with N. Raw tool count is therefore not the
universal scaling variable; independent policy decisions are.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from scaling.catalog import Role, build_catalog

SIZES = [10, 25, 50, 100, 200, 400]
P = 0.08
TARGET_RISK = 0.05
GROUP_SIZES = [1, 5, 20, "catalog"]
OUT = Path(__file__).resolve().parent / "results" / "dependence.json"


def vulnerable_probability(n_sensitive: int, group_size: int, p: float) -> float:
    groups = math.ceil(n_sensitive / group_size)
    return 1.0 - (1.0 - p) ** groups


def tolerable_rate(n_sensitive: int, group_size: int, target: float) -> float:
    groups = math.ceil(n_sensitive / group_size)
    return 1.0 - (1.0 - target) ** (1.0 / groups)


def main() -> None:
    rows = []
    for n in SIZES:
        s = sum(1 for spec in build_catalog(n)
                if spec.role is Role.SENSITIVE_SOURCE)
        for requested in GROUP_SIZES:
            g = s if requested == "catalog" else min(int(requested), s)
            groups = math.ceil(s / g)
            rows.append({
                "n_tools": n,
                "n_sensitive": s,
                "group_size": requested,
                "independent_policy_decisions": groups,
                "marginal_error_rate": P,
                "catalog_vulnerable_probability": round(
                    vulnerable_probability(s, g, P), 6),
                "tolerable_rate_at_5pct_risk": round(
                    tolerable_rate(s, g, TARGET_RISK), 6),
            })
    payload = {
        "model": "within-group perfect correlation; between-group independence",
        "fixed_marginal_error_rate": P,
        "target_catalog_risk": TARGET_RISK,
        "rows": rows,
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2) + "\n")
    print("N=200 sensitivity (p=0.08):")
    for row in rows:
        if row["n_tools"] == 200:
            print(row)
    print(f"saved {OUT}")


if __name__ == "__main__":
    main()
