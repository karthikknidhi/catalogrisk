"""catalogrisk: weakest-link risk for agent tool catalogs.

Implements the measures from Karunanithi (2026), "Per-Attack Blocking Hides
Catalog Vulnerability: A Weakest-Link Analysis of Tool Manifests",
arXiv:2611.31338. Standard library only.
"""
from math import lgamma, log, exp

__version__ = "0.1.0"
__all__ = ["catalog_vulnerability", "tolerable_error_rate", "beta_binomial_risk",
           "effective_m", "estimate_rho", "report"]


def _check_p(p):
    if not 0.0 <= p < 1.0:
        raise ValueError("p must be in [0, 1)")


def catalog_vulnerability(p, m):
    """Chance that at least one of m independent source policies is wrong: 1-(1-p)^m."""
    _check_p(p)
    return 1.0 - (1.0 - p) ** m


def tolerable_error_rate(epsilon, m):
    """Largest per-policy error rate keeping catalog risk <= epsilon: 1-(1-eps)^(1/m) ~ eps/m."""
    if not 0.0 < epsilon < 1.0 or m <= 0:
        raise ValueError("need 0 < epsilon < 1 and m > 0")
    return 1.0 - (1.0 - epsilon) ** (1.0 / m)


def _lbeta(a, b):
    return lgamma(a) + lgamma(b) - lgamma(a + b)


def beta_binomial_risk(p, s, rho):
    """Catalog risk when one author's errors are correlated (intra-class correlation rho).

    Author propensity pi ~ Beta(a, b), a = p(1/rho-1), b = (1-p)(1/rho-1);
    risk = 1 - B(a, b+s) / B(a, b). rho=0 reduces to independence.
    """
    _check_p(p)
    if not 0.0 <= rho < 1.0:
        raise ValueError("rho must be in [0, 1)")
    if rho == 0.0 or p == 0.0:
        return catalog_vulnerability(p, s)
    k = 1.0 / rho - 1.0
    a, b = p * k, (1.0 - p) * k
    return 1.0 - exp(_lbeta(a, b + s) - _lbeta(a, b))


def effective_m(p, s, rho):
    """Effective number of independent decisions: ln(1-r)/ln(1-p) for r = beta_binomial_risk."""
    r = beta_binomial_risk(p, s, rho)
    return log(1.0 - r) / log(1.0 - p)


def estimate_rho(counts, s):
    """Moment estimator of rho from per-author error counts over s sensitive sources.

    D = Var(K) / [s * pbar * (1-pbar)] (population variance); rho = (D-1)/(s-1), clipped to [0, 1).
    Returns (rho, D, pbar).
    """
    n = len(counts)
    if n < 2 or s < 2:
        raise ValueError("need at least two authors and two sources")
    pbar = sum(counts) / (n * s)
    mean = sum(counts) / n
    var = sum((c - mean) ** 2 for c in counts) / n
    d = var / (s * pbar * (1.0 - pbar))
    rho = min(max((d - 1.0) / (s - 1.0), 0.0), 0.999999)
    return rho, d, pbar


def report(p, tools, sensitive_share=0.30, rho=0.0, epsilon=0.05):
    """Everything an evaluation should state alongside per-attack blocking."""
    s = max(1, round(tools * sensitive_share))
    risk = beta_binomial_risk(p, s, rho)
    m_eff = effective_m(p, s, rho) if p > 0 else float(s)
    return {
        "tools": tools, "sensitive_sources": s, "per_policy_error": p, "rho": rho,
        "per_attack_blocking": 1.0 - p,
        "catalog_vulnerability": risk,
        "catalog_vulnerability_if_independent": catalog_vulnerability(p, s),
        "effective_independent_decisions": m_eff,
        "tolerable_error_rate": tolerable_error_rate(epsilon, m_eff),
        "epsilon": epsilon,
    }
