import argparse, json
from . import report, estimate_rho

def main():
    ap = argparse.ArgumentParser(prog="catalogrisk", description="Weakest-link risk for agent tool catalogs (arXiv:2611.31338)")
    ap.add_argument("--p", type=float, required=True, help="per-policy error rate (e.g. 0.08)")
    ap.add_argument("--tools", type=int, required=True, help="number of tools in the catalog")
    ap.add_argument("--sensitive-share", type=float, default=0.30, help="share of tools that read sensitive data (default 0.30)")
    ap.add_argument("--rho", type=float, default=0.0, help="author-effect correlation (0 = independent; paper pilot: 0.29-0.45)")
    ap.add_argument("--author-counts", type=str, help="comma-separated per-author error counts; estimates rho")
    ap.add_argument("--epsilon", type=float, default=0.05, help="target catalog risk for the tolerable rate")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rho = a.rho
    if a.author_counts:
        counts = [int(x) for x in a.author_counts.split(",")]
        s = max(1, round(a.tools * a.sensitive_share))
        rho, d, _ = estimate_rho(counts, s)
    r = report(a.p, a.tools, a.sensitive_share, rho, a.epsilon)
    if a.json:
        print(json.dumps(r, indent=2)); return
    print(f"Catalog of {r['tools']} tools ({r['sensitive_sources']} sensitive sources), per-policy error {a.p:.3f}, rho {rho:.2f}")
    print(f"  per-attack blocking            {r['per_attack_blocking']:.1%}")
    print(f"  catalog vulnerability          {r['catalog_vulnerability']:.1%}  (independent: {r['catalog_vulnerability_if_independent']:.1%})")
    print(f"  effective independent choices  {r['effective_independent_decisions']:.1f}")
    print(f"  tolerable error rate @ eps={a.epsilon}  {r['tolerable_error_rate']:.5f}")

if __name__ == "__main__":
    main()
