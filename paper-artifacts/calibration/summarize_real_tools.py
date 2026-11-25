"""
Sanity check and summary for the real-tool run. Standard library only.

Reads real_tools.json (written by run_real_tools.py) and writes
real_tools_summary.txt next to it: for every author, records per condition,
request errors, unparsable answers, and on the 93 restricted tools the
network over-permissions (any_network allowed) and any over-permission.

    python3 summarize_real_tools.py
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path

HERE = Path(os.environ.get(
    "PILOT_OUT", Path(__file__).resolve().parent.parent / "results" / "real_tools.json"))
EXPECTED = 114


def main():
    data = json.loads(HERE.read_text())
    recs = data["records"]
    by = defaultdict(list)
    for r in recs:
        by[(f"{r['provider']}:{r['model']}", r["condition"])].append(r)
    lines = [f"records: {len(recs)}   authors: {len({a for a, _ in by})}", "",
             f"{'author':40s} {'cond':6s} {'n':>4s} {'err':>4s} {'unpar':>5s} {'net':>7s} {'over':>7s}"]
    problems = []
    tot = defaultdict(lambda: [0, 0, 0])
    for (author, cond), rows in sorted(by.items()):
        err = sum(1 for r in rows if r.get("error"))
        unp = sum(1 for r in rows if not r.get("error") and not r.get("model_role") and not r.get("channels"))
        sens = [r for r in rows if r["over_permission"] is not None]
        net = sum(1 for r in sens if r.get("network_over_permission"))
        over = sum(1 for r in sens if r["over_permission"])
        lines.append(f"{author:40s} {cond[:6]:6s} {len(rows):4d} {err:4d} {unp:5d} {net:3d}/{len(sens):<3d} {over:3d}/{len(sens):<3d}")
        t = tot[cond]; t[0] += net; t[1] += over; t[2] += len(sens)
        if len(rows) != EXPECTED: problems.append(f"{author} {cond}: {len(rows)} records, expected {EXPECTED}")
        if err: problems.append(f"{author} {cond}: {err} request errors (rerun to retry)")
        if unp > 5: problems.append(f"{author} {cond}: {unp} unparsable answers")
    lines += ["", "TOTALS"]
    for cond, (net, over, n) in tot.items():
        lines.append(f"  {cond}: network over-permission {net}/{n}, any over-permission {over}/{n}")
    temp = data.get("protocol", {}).get("temperature_unsupported", [])
    lines += ["", "temperature_unsupported: " + (", ".join(temp) or "none")]
    lines += ["", "PROBLEMS:" if problems else "NO PROBLEMS FOUND"] + [f"  - {p}" for p in problems]
    out = HERE.parent / "real_tools_summary.txt"
    out.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
