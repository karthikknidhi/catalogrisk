"""
Sanity check and summary for the expanded pilot. Standard library only.

Reads llm_calibration_v2.json (written by run_llm_calibration_v2.py) and writes
pilot2_summary.txt next to it. Reports, for every author (provider:model):
records per condition, request errors, unparsable answers, role accuracy, and
over/under-permission counts on the 19 sensitive sources. If the original
pilot file is present, it also compares the original seven models on the
original 18 tools against the preserved submission outputs.

    python3 summarize_pilot2.py
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path

HERE = Path(os.environ.get(
    "PILOT_OUT",
    Path(__file__).resolve().parent.parent / "results" / "llm_calibration_v2.json"))
ORIGINAL = Path(__file__).resolve().parent.parent / "results" / "llm_calibration.json"
EXPECTED_PER_CONDITION = 28


def main():
    data = json.loads(HERE.read_text())
    recs = data["records"]
    by = defaultdict(list)
    for r in recs:
        by[(r["provider"], r["model"], r["condition"])].append(r)
    authors = sorted({(p, m) for p, m, _ in by})
    lines = [f"records: {len(recs)}   authors: {len(authors)}", ""]
    hdr = (f"{'author':45s} {'cond':6s} {'n':>3s} {'err':>3s} {'unpar':>5s} "
           f"{'role':>5s} {'over':>6s} {'under':>6s} {'net':>4s} {'email':>5s} {'file':>4s}")
    lines.append(hdr)
    problems = []
    totals = defaultdict(lambda: defaultdict(int))
    for p, m in authors:
        for cond in ("description_only", "policy_conditioned"):
            rows = by.get((p, m, cond), [])
            sens = [r for r in rows if r["over_permission"] is not None]
            err = sum(1 for r in rows if r.get("error"))
            unp = sum(1 for r in rows if not r.get("error") and not r.get("model_role")
                      and not r.get("channels"))
            role = sum(r["model_role"] == r["gold_role"] for r in rows)
            over = sum(r["over_permission"] for r in sens)
            under = sum(r["under_permission"] for r in sens)
            net = sum("any_network" in r["extra_channels"] for r in sens)
            em = sum("internal_email" in r["extra_channels"] for r in sens)
            fi = sum("file_tmp" in r["extra_channels"] for r in sens)
            c = cond[:6]
            lines.append(f"{p + ':' + m:45s} {c:6s} {len(rows):3d} {err:3d} {unp:5d} "
                         f"{role:2d}/{len(rows):<2d} {over:2d}/{len(sens):<3d} "
                         f"{under:2d}/{len(sens):<3d} {net:4d} {em:5d} {fi:4d}")
            if len(rows) != EXPECTED_PER_CONDITION:
                problems.append(f"{p}:{m} {cond}: {len(rows)} records, expected {EXPECTED_PER_CONDITION}")
            if err:
                problems.append(f"{p}:{m} {cond}: {err} request errors (rerun to retry)")
            if unp > 3:
                problems.append(f"{p}:{m} {cond}: {unp} unparsable answers")
            t = totals[cond]
            t["decisions"] += len(sens); t["over"] += over; t["under"] += under
            t["net"] += net; t["email"] += em; t["file"] += fi
    lines += ["", "TOTALS"]
    for cond, t in totals.items():
        lines.append(f"  {cond}: over {t['over']}/{t['decisions']}, under {t['under']}/{t['decisions']}, "
                     f"excess channels net={t['net']} email={t['email']} file={t['file']}")

    if ORIGINAL.exists():
        lines += ["", "COMPARISON WITH ORIGINAL PILOT (original 7 models, original 18 tools)"]
        orig = json.loads(ORIGINAL.read_text())
        for m in orig["models"]:
            new = {r["tool"]: r for r in by.get(("ollama", m["model"], m["condition"]), [])}
            if not new:
                lines.append(f"  {m['model']} {m['condition']}: not in new run")
                continue
            same = sum(1 for d in m["details"]
                       if d["tool"] in new and sorted(new[d["tool"]]["channels"]) == sorted(d["channels"])
                       and new[d["tool"]]["model_role"] == d["model_role"])
            lines.append(f"  {m['model']:18s} {m['condition']:18s} identical answers {same}/{len(m['details'])}")

    lines += ["", "PROBLEMS" if problems else "NO PROBLEMS FOUND"] + [f"  - {x}" for x in problems]
    out = HERE.parent / "pilot2_summary.txt"
    out.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
