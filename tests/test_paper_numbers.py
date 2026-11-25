"""Checks against values reported in arXiv:2611.31338."""
from catalogrisk import catalog_vulnerability, tolerable_error_rate, beta_binomial_risk, effective_m, estimate_rho

def close(a, b, tol): assert abs(a - b) <= tol, (a, b)

def test_exact_group_table():  # Appendix table, N=200, S=60, p=0.08
    close(catalog_vulnerability(0.08, 60), 0.993, 0.001)
    close(catalog_vulnerability(0.08, 12), 0.632, 0.001)
    close(catalog_vulnerability(0.08, 3), 0.221, 0.001)
    close(tolerable_error_rate(0.05, 60), 0.00086, 0.00001)
    close(tolerable_error_rate(0.05, 12), 0.00427, 0.00001)

def test_rho_estimates():  # Appendix: S=19 sources, 15 models
    desc = [14, 3, 10, 13, 19, 17, 11, 11, 13, 0, 8, 15, 19, 12, 17]
    pol = [0, 0, 0, 0, 4, 2, 11, 10, 12, 15, 16, 0, 3, 9, 17]
    r, d, _ = estimate_rho(desc, 19); close(d, 6.23, 0.01); close(r, 0.29, 0.005)
    r, d, _ = estimate_rho(pol, 19); close(d, 9.16, 0.01); close(r, 0.45, 0.005)

def test_independence_limit():
    close(beta_binomial_risk(0.08, 60, 0.0), catalog_vulnerability(0.08, 60), 1e-12)
    close(effective_m(0.08, 60, 1e-9), 60, 0.01)

def test_author_effect_200_tools():  # Section 5: rho fitted to policy-conditioned pilot, N=200
    pol = [0, 0, 0, 0, 4, 2, 11, 10, 12, 15, 16, 0, 3, 9, 17]
    r, _, _ = estimate_rho(pol, 19)
    close(beta_binomial_risk(0.08, 60, r), 0.349, 0.001)
    close(effective_m(0.08, 60, r), 5.15, 0.05)
