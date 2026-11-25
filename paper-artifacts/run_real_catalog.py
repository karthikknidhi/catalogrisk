"""
Real catalogs with measured authoring errors, in both engines.

Input: results/real_tools.json (calibration/run_real_tools.py): 15 authors x
114 real MCP tools x 2 prompting conditions. For every author, condition, and
deployment (each non-empty subset of the four services, plus the agent's
generic transforms and external sinks), we build that author's manifests from
its own answers (scaling/real_catalog.py), send every expert-restricted source
to every external sink, and evaluate each path in ChainCaps and in OpenAPPA.
No error is injected: every hole is one an author wrote.

We also compare the observed share of vulnerable deployments with two
predictions from the measured answers alone: independence, 1-(1-p)^S with the
pooled network over-permission rate p, and the beta-binomial author-effect
model with rho moment-matched to the per-author counts.

Produces:
    results/real_catalog.json

Run:
    APPA_BIN=/path/to/appa PYTHONPATH=. python run_real_catalog.py
"""
from __future__ import annotations

import itertools
import json
import os
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

from scaling.correlated import catalog_risk
from scaling.real_catalog import (SERVICES, attack_paths, catalog, evaluate_appa,
                                  evaluate_chaincaps, load_spec, manifests_for, tool_id)

ROOT = Path(__file__).resolve().parent
INP = Path(os.environ.get("REAL_IN", ROOT / "results" / "real_tools.json"))
OUT = Path(os.environ.get("REAL_OUT", ROOT / "results" / "real_catalog.json"))
FRONTIER_PREFIX = "anthropic:"


def rho_hat(counts, s):
    pbar = sum(counts) / (len(counts) * s)
    vb = s * pbar * (1 - pbar)
    if vb == 0:
        return 0.0
    return min(max((st.pvariance(counts) / vb - 1) / (s - 1), 0.0), 0.999)


def main():
    if not os.environ.get("APPA_BIN"):
        sys.exit("set APPA_BIN to the appa binary")
    spec = {tool_id(t): t for t in load_spec()}
    restricted = [k for k, t in spec.items() if t["restricted"]]
    recs = json.loads(INP.read_text())["records"]
    by = defaultdict(dict)
    bad = defaultdict(int)
    for r in recs:
        svc, name = r["tool"].split("/", 1)
        key = f"{svc}__{name.replace('-', '_')}"
        a = (f"{r['provider']}:{r['model']}", r["condition"])
        if r.get("error"):
            bad[a] += 1
        by[a][key] = r
    authors = sorted(a for a in by if len(by[a]) == len(spec) and not bad[a])
    excluded = sorted(set(by) - set(authors))
    deployments = [list(c) for k in range(1, len(SERVICES) + 1)
                   for c in itertools.combinations(SERVICES, k)]
    rows = []
    for (author, cond) in authors:
        ans = {k: r["channels"] for k, r in by[(author, cond)].items()}
        for dep in deployments:
            specs, real = catalog(dep)
            mans = manifests_for(specs, ans)
            paths = attack_paths(specs)
            cc = evaluate_chaincaps(mans, paths)
            ap = evaluate_appa(specs, mans, paths)
            http = [i for i, p in enumerate(paths) if p[2].endswith("http")]
            S = sum(1 for t in real if t["restricted"])
            # The only expected disagreement: a source the author let reach the
            # network carries APPA audience `public`, which every external sink
            # accepts, while its ChainCaps budget grants only SEND_HTTP.
            diff = [i for i in cc if cc[i] != ap[i]]
            unexpected = [i for i in diff if not (ap[i] and not cc[i]
                          and not paths[i][2].endswith("http")
                          and "any_network" in ans[paths[i][0]])]
            assert not unexpected, [paths[i] for i in unexpected]
            rows.append({
                "author": author, "condition": cond, "deployment": "+".join(dep), "S": S,
                "n_tools": len(real), "paths": len(paths), "http_paths": len(http),
                "agree": len(paths) - len(diff),
                "agree_http": sum(cc[i] == ap[i] for i in http),
                "appa_only_nonhttp": len(diff),
                "vulnerable_chaincaps": int(any(cc.values())),
                "vulnerable_appa": int(any(ap.values())),
                "http_block_rate": round(sum(not cc[i] for i in http) / len(http), 4),
                "network_holes": sum(1 for t in real if t["restricted"]
                                     and "any_network" in ans[tool_id(t)]),
            })
        print(author, cond, "done", flush=True)

    out = {"authors": [f"{a}|{c}" for a, c in authors], "excluded": [f"{a}|{c}" for a, c in excluded],
           "n_restricted": len(restricted), "deployments": ["+".join(d) for d in deployments],
           "total_paths": sum(r["paths"] for r in rows), "total_agree": sum(r["agree"] for r in rows),
           "total_http_paths": sum(r["http_paths"] for r in rows),
           "total_http_agree": sum(r["agree_http"] for r in rows),
           "catalog_decisions_agree": sum(r["vulnerable_chaincaps"] == r["vulnerable_appa"] for r in rows),
           "catalog_decisions": len(rows),
           "conditions": {}, "rows": rows}
    for cond in ("description_only", "policy_conditioned"):
        auth = [a for a, c in authors if c == cond]
        groups = {"all": auth, "local": [a for a in auth if not a.startswith(FRONTIER_PREFIX)],
                  "frontier": [a for a in auth if a.startswith(FRONTIER_PREFIX)]}
        res = {}
        for g, members in groups.items():
            if not members:
                continue
            counts = [sum(1 for k in restricted if "any_network" in by[(a, cond)][k]["channels"])
                      for a in members]
            anyover = [sum(1 for k in restricted if by[(a, cond)][k]["over_permission"]) for a in members]
            p = sum(counts) / (len(members) * len(restricted))
            rho = rho_hat(counts, len(restricted))
            per_dep = {}
            for dep in out["deployments"]:
                sub = [r for r in rows if r["condition"] == cond and r["deployment"] == dep
                       and r["author"] in members]
                S = sub[0]["S"]
                per_dep[dep] = {
                    "S": S, "authors": len(sub),
                    "vulnerable_share": round(sum(r["vulnerable_chaincaps"] for r in sub) / len(sub), 4),
                    "vulnerable_share_appa": round(sum(r["vulnerable_appa"] for r in sub) / len(sub), 4),
                    "mean_http_block_rate": round(st.mean(r["http_block_rate"] for r in sub), 4),
                    "predicted_independent": round(1 - (1 - p) ** S, 4),
                    "predicted_beta_binomial": round(catalog_risk(S, p, rho), 4) if 0 < p < 1 else round(float(p > 0), 4),
                }
            res[g] = {"authors": members, "n_authors": len(members),
                      "network_overperm_per_author": dict(zip(members, counts)),
                      "any_overperm_per_author": dict(zip(members, anyover)),
                      "network_overperm_rate": round(p, 4),
                      "any_overperm_rate": round(sum(anyover) / (len(members) * len(restricted)), 4),
                      "rho_homogeneous": round(rho, 4), "by_deployment": per_dep}
        out["conditions"][cond] = res
    OUT.write_text(json.dumps(out, indent=1) + "\n")
    print(f"HTTP-path agreement {out['total_http_agree']}/{out['total_http_paths']}; "
          f"catalog decisions agree {out['catalog_decisions_agree']}/{out['catalog_decisions']}; "
          f"all paths {out['total_agree']}/{out['total_paths']}; saved {OUT.name}")
    for cond, res in out["conditions"].items():
        for g, r in res.items():
            full = r["by_deployment"]["+".join(SERVICES)]
            print(f"{cond:18s} {g:8s} n={r['n_authors']:2d} p_net={r['network_overperm_rate']:.3f} "
                  f"rho={r['rho_homogeneous']:.2f} | all-4 S={full['S']} vuln={full['vulnerable_share']:.2f} "
                  f"block={full['mean_http_block_rate']:.3f} pred_ind={full['predicted_independent']:.2f} "
                  f"pred_bb={full['predicted_beta_binomial']:.2f}")


if __name__ == "__main__":
    main()
