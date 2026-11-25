"""Machine-check the headline values reported in the manuscript."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def close(actual: float, expected: float, tol: float = 5e-4) -> None:
    assert abs(actual - expected) <= tol, (actual, expected, tol)


def main() -> None:
    summary = json.loads((ROOT / "results" / "summary.json").read_text())
    assert summary["n_seeds"] == 2000

    low = summary["strategies"]["low_error"]
    close(low["10"]["attack_block_rate_mean"], 0.920)
    close(low["200"]["attack_block_rate_mean"], 0.9197)
    close(low["10"]["catalog_vulnerable_rate"], 0.218)
    close(low["50"]["catalog_vulnerable_rate"], 0.710)
    close(low["200"]["catalog_vulnerable_rate"], 0.9935)
    assert low["10"]["catalog_vulnerable_ci95"] == [0.2005, 0.2366]
    assert low["50"]["catalog_vulnerable_ci95"] == [0.6897, 0.7295]
    assert low["200"]["catalog_vulnerable_ci95"] == [0.9889, 0.9962]

    high = summary["strategies"]["naive_calibrated"]
    assert min(r["attack_block_rate_mean"] for r in high.values()) >= 0.247
    assert max(r["attack_block_rate_mean"] for r in high.values()) <= 0.254
    close(summary["empirical_grid_loglog_slope"], -0.989)
    close(summary["analytic_loglog_slope"], -1.005)

    dependence = json.loads((ROOT / "results" / "dependence.json").read_text())
    rows = {str(r["group_size"]): r for r in dependence["rows"]
            if r["n_tools"] == 200}
    close(rows["1"]["catalog_vulnerable_probability"], 0.993282, 1e-6)
    close(rows["5"]["catalog_vulnerable_probability"], 0.632334, 1e-6)
    close(rows["20"]["catalog_vulnerable_probability"], 0.221312, 1e-6)
    close(rows["catalog"]["catalog_vulnerable_probability"], 0.08, 1e-6)

    # ---- submitted pilot (7 models x 18 tools), kept as the record ---------
    pilot = json.loads((ROOT / "results" / "llm_calibration.json").read_text())
    desc = pilot["conditions"]["description_only"]
    policy = pilot["conditions"]["policy_conditioned"]
    assert (desc["overpermission_count"], desc["underpermission_count"]) == (42, 28)
    assert (policy["overpermission_count"], policy["underpermission_count"]) == (27, 11)

    # ---- expanded pilot (Table 4, Section 4.5, Appendix A) -----------------
    import sys
    sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT.parent / "chaincaps-code"))
    from scaling.pilot_data import ORIGINAL_MODELS, load_pilot
    recs = json.loads((ROOT / "results" / "llm_calibration_v2.json").read_text())["records"]
    assert len(recs) == 840 and not any(r.get("error") for r in recs)
    assert len({r["model"] for r in recs}) == 15 and len({r["tool"] for r in recs}) == 28
    frontier = {"claude-fable-5-1", "claude-haiku-5-5", "claude-sonnet-5-5"}
    assert {r["model"] for r in recs if r["provider"] != "ollama"} == frontier
    proto = json.loads((ROOT / "results" / "llm_calibration_v2.json").read_text())["protocol"]
    assert set(proto["temperature_unsupported"]) == frontier
    unparsable = [r for r in recs if not r.get("model_role") and not r.get("channels")]
    assert [(r["model"], r["condition"], r["tool"]) for r in unparsable] == [
        ("claude-fable-5-1", "description_only", "send_http")]
    table4 = {}
    for cond in ("description_only", "policy_conditioned"):
        rows = [r for r in recs if r["condition"] == cond]
        sens = [r for r in rows if r["over_permission"] is not None]
        table4[cond] = (sum(r["model_role"] == r["gold_role"] for r in rows), len(rows),
                        sum(r["over_permission"] for r in sens),
                        sum(r["under_permission"] for r in sens), len(sens),
                        sum("any_network" in r["extra_channels"] for r in sens),
                        sum("internal_email" in r["extra_channels"] for r in sens),
                        sum("file_tmp" in r["extra_channels"] for r in sens))
    assert table4 == {"description_only": (381, 420, 182, 114, 285, 23, 149, 128),
                      "policy_conditioned": (372, 420, 99, 28, 285, 24, 63, 61)}, table4
    fr4 = {}
    for cond in ("description_only", "policy_conditioned"):
        rows = [r for r in recs if r["condition"] == cond and r["model"] in frontier]
        sens = [r for r in rows if r["over_permission"] is not None]
        fr4[cond] = (sum(r["model_role"] == r["gold_role"] for r in rows), len(rows),
                     sum(r["over_permission"] for r in sens),
                     sum(r["under_permission"] for r in sens), len(sens),
                     sum("any_network" in r["extra_channels"] for r in sens),
                     sum("internal_email" in r["extra_channels"] for r in sens),
                     sum("file_tmp" in r["extra_channels"] for r in sens))
    assert fr4 == {"description_only": (82, 84, 27, 13, 57, 0, 24, 18),
                   "policy_conditioned": (82, 84, 0, 3, 57, 0, 0, 0)}, fr4
    net_policy = {}
    for r in recs:
        if r["condition"] == "policy_conditioned" and "any_network" in r["extra_channels"]:
            net_policy[r["model"]] = net_policy.get(r["model"], 0) + 1
    assert net_policy == {"olmo2:7b": 8, "qwen3:8b": 16}
    assert all(not r["channels"] for r in recs if r["model"] == "olmo2:7b"
               and r["condition"] == "description_only" and r["over_permission"] is not None)
    # the original seven models reproduce the submitted answers on the 18 tools
    ex = load_pilot("expanded")
    for m in pilot["models"]:
        new = next(x for x in ex if x["model"] == m["model"] and x["condition"] == m["condition"])
        by = {d["tool"]: d for d in new["details"]}
        for d in m["details"]:
            assert sorted(by[d["tool"]]["channels"]) == sorted(d["channels"]), (m["model"], d["tool"])
            assert by[d["tool"]]["model_role"] == d["model_role"]
    assert sorted({m["model"] for m in pilot["models"]}) == sorted(ORIGINAL_MODELS)

    coverage = json.loads((ROOT / "results" / "sink_coverage.json").read_text())
    assert coverage["p"] == 0.08 and coverage["n_seeds"] == 2000
    assert coverage["pilot_channel_mix"] == {
        "description_only": {"http": 23, "email": 149, "file": 128},
        "policy_conditioned": {"http": 24, "email": 63, "file": 61}}
    do = coverage["mixes"]["description_only"]["by_size"]
    pc = coverage["mixes"]["policy_conditioned"]["by_size"]
    for n, v in (("50", 0.086), ("100", 0.170), ("200", 0.302), ("400", 0.5265)):
        close(do[n]["http_only_vulnerable_rate"], v)
    for n, v in (("50", 0.178), ("100", 0.3235), ("200", 0.5305), ("400", 0.7905)):
        close(pc[n]["http_only_vulnerable_rate"], v)
    # Wilson interval from the exact count (the JSON stores it rounded to 4 dp)
    k, n = round(do["200"]["http_only_vulnerable_rate"] * 2000), 2000
    z = 1.96; ph = k / n; d = 1 + z * z / n; c = (ph + z * z / (2 * n)) / d
    h = z * ((ph * (1 - ph) / n + z * z / (4 * n * n)) ** 0.5) / d
    assert (round(c - h, 3), round(c + h, 3)) == (0.282, 0.322), (c - h, c + h)
    assert pc["200"]["http_only_vulnerable_ci95"] == [0.5086, 0.5523]
    # full coverage reproduces the weakest-link curve for both channel mixes
    for by_size in (do, pc):
        close(by_size["50"]["all_sink_vulnerable_rate"], 0.710)
        close(by_size["100"]["all_sink_vulnerable_rate"], 0.912)
        close(by_size["200"]["all_sink_vulnerable_rate"], 0.9935)
        close(by_size["400"]["all_sink_vulnerable_rate"], 1.000)

    pdep = json.loads((ROOT / "results" / "pilot_dependence.json").read_text())
    dd = pdep["description_only"]
    pp = pdep["policy_conditioned"]
    assert dd["n_models"] == pp["n_models"] == 15 and dd["n_sensitive"] == 19
    assert (dd["overdispersion_ratio"], pp["overdispersion_ratio"]) == (6.23, 9.16)
    close(dd["marginal_overperm_rate"], 0.6386, 1e-4)
    close(pp["marginal_overperm_rate"], 0.3474, 1e-4)
    sp = pdep["submitted"]["policy_conditioned"]
    assert sp["overdispersion_ratio"] == 3.56 and pdep["submitted"]["description_only"][
        "unanimous_overperm_sources"] == 4

    # ---- effective M (Section 4.4, Table 3, Appendix B) ---------------------
    eff = json.loads((ROOT / "results" / "effective_m.json").read_text())
    ed = eff["conditions"]["description_only"]
    ep = eff["conditions"]["policy_conditioned"]
    assert list(ed["per_model_overperm_count"].values()) == [14, 3, 10, 13, 19, 17, 11, 11, 13, 0, 8, 15, 19, 12, 17]
    assert list(ep["per_model_overperm_count"].values()) == [0, 0, 0, 0, 4, 2, 11, 10, 12, 15, 16, 0, 3, 9, 17]
    assert (ed["dispersion_ratio"], ep["dispersion_ratio"]) == (6.23, 9.16)
    assert (round(ed["rho_homogeneous"], 2), round(ep["rho_homogeneous"], 2)) == (0.29, 0.45)
    assert (round(ed["rho_heterogeneity_adjusted"], 2), round(ep["rho_heterogeneity_adjusted"], 2)) == (0.43, 0.54)
    close(ed["curve_rho_homogeneous"]["200"]["effective_decisions"], 8.20, 0.01)
    close(ep["curve_rho_homogeneous"]["200"]["effective_decisions"], 5.15, 0.01)
    close(ep["curve_rho_homogeneous"]["200"]["catalog_vulnerable"], 0.3492, 1e-4)
    close(ed["curve_rho_heterogeneity_adjusted"]["200"]["catalog_vulnerable"], 0.369, 1e-3)
    close(ep["curve_rho_heterogeneity_adjusted"]["200"]["catalog_vulnerable"], 0.290, 1e-3)
    close(ed["curve_rho_heterogeneity_adjusted"]["200"]["effective_decisions"], 5.5, 0.05)
    close(ep["curve_rho_heterogeneity_adjusted"]["200"]["effective_decisions"], 4.1, 0.05)
    assert ed["bootstrap_N200"]["effective_decisions_95"] == [4.56, 24.22]
    assert ep["bootstrap_N200"]["effective_decisions_95"] == [3.36, 9.16]
    close(ed["bootstrap_N200"]["catalog_vulnerable_95"][0], 0.32, 0.005)
    close(ed["bootstrap_N200"]["catalog_vulnerable_95"][1], 0.87, 0.005)
    close(ep["bootstrap_N200"]["catalog_vulnerable_95"][0], 0.24, 0.005)
    close(ep["bootstrap_N200"]["catalog_vulnerable_95"][1], 0.53, 0.005)
    # submitted-pilot fit is reproduced exactly (Table 6 first row)
    sd, sp = eff["submitted_pilot"]["description_only"], eff["submitted_pilot"]["policy_conditioned"]
    close(sd["rho_homogeneous"], 0.0179, 1e-4)
    close(sp["rho_homogeneous"], 0.3194, 1e-4)
    assert sd["bootstrap_N200"]["effective_decisions_95"] == [12.85, 60.0]
    assert sp["bootstrap_N200"]["effective_decisions_95"] == [3.68, 60.0]
    close(sd["curve_rho_homogeneous"]["200"]["effective_decisions"], 40.34, 0.01)
    close(sp["curve_rho_homogeneous"]["200"]["effective_decisions"], 7.5, 0.01)
    # sensitivity table
    sens = eff["sensitivity"]
    table = {"original_7_models_19_sources": ((0.070, 22.7), (0.25, 9.5)),
             "local_models_only": ((0.29, 8.2), (0.37, 6.5)),
             "all_models_original_9_sources": ((0.27, 8.7), (0.45, 5.1)),
             "all_models_10_new_sources": ((0.25, 9.25), (0.43, 5.5))}  # 9.2498 -> 9.2
    for key, ((rd, md), (rp, mp)) in table.items():
        a, b = sens["description_only"][key], sens["policy_conditioned"][key]
        assert round(a["rho_homogeneous"], 3 if rd < 0.1 else 2) == rd, (key, a)
        assert round(b["rho_homogeneous"], 2) == rp, (key, b)
        close(a["effective_decisions_N200"], md, 0.05)
        close(b["effective_decisions_N200"], mp, 0.05)
    fo = sens["description_only"]["frontier_models_only"]
    assert round(fo["rho_homogeneous"], 2) == 0.19
    close(fo["effective_decisions_N200"], 11.9, 0.05)
    assert sum(ep["per_model_overperm_count"][m] for m in frontier) == 0
    for cond, (rlo, rhi, mlo, mhi) in (("description_only", (0.19, 0.32, 7.6, 11.8)),
                                       ("policy_conditioned", (0.41, 0.49, 4.7, 5.8))):
        loo = sens[cond]["leave_one_author_out"].values()
        assert round(min(v["rho_homogeneous"] for v in loo), 2) == rlo
        assert round(max(v["rho_homogeneous"] for v in loo), 2) == rhi
        close(min(v["effective_decisions_N200"] for v in loo), mlo, 0.05)
        close(max(v["effective_decisions_N200"] for v in loo), mhi, 0.05)
    drop_olmo = sens["description_only"]["leave_one_author_out"]["olmo2:7b"]
    close(drop_olmo["effective_decisions_N200"], 11.8, 0.05)
    tol = eff["tolerable_rate_eps05"]
    assert [round(tol["policy_conditioned"]["p_max"][n], 4) for n in ("10", "50", "200", "400")] \
        == [0.0264, 0.0140, 0.0097, 0.0084]
    assert round(tol["policy_conditioned"]["loglog_slope"], 2) == -0.31
    assert round(tol["description_only"]["loglog_slope"], 2) == -0.40

    cor = json.loads((ROOT / "results" / "correlated.json").read_text())
    assert cor["n_seeds"] == 2000 and cor["p"] == 0.08
    cd = cor["by_condition"]["description_only"]
    cp = cor["by_condition"]["policy_conditioned"]
    for n, v in (("50", 0.377), ("100", 0.431), ("200", 0.505), ("400", 0.566)):
        close(cd[n]["catalog_vulnerable_rate"], v)
    for n, v in (("50", 0.2635), ("100", 0.2965), ("200", 0.3495), ("400", 0.3895)):  # half-up in text
        close(cp[n]["catalog_vulnerable_rate"], v)
    lo, hi = cp["200"]["catalog_vulnerable_ci95"]
    assert (round(lo, 3), round(hi, 3)) == (0.329, 0.371)
    close(cp["200"]["catalog_vulnerable_analytic"], 0.3492)
    blocks = [r["attack_block_rate_mean"] for c in (cd, cp) for r in c.values()]
    assert round(min(blocks), 3) == 0.914 and round(max(blocks), 3) == 0.927
    inside = sum(r["catalog_vulnerable_ci95"][0] <= r["catalog_vulnerable_analytic"]
                 <= r["catalog_vulnerable_ci95"][1] for c in (cd, cp) for r in c.values())
    assert inside == 11, inside
    assert not (cd["50"]["catalog_vulnerable_ci95"][0] <= cd["50"]["catalog_vulnerable_analytic"])
    # expected holed sources in a vulnerable 200-tool catalog
    close(60 * 0.08 / cp["200"]["catalog_vulnerable_analytic"], 13.7, 0.05)
    close(60 * 0.08 / 0.9933, 4.8, 0.05)

    cf = json.loads((ROOT / "results" / "coverage_fraction.json").read_text())
    assert cf["n_seeds"] == 2000 and cf["p"] == 0.08
    for h, rows in cf["by_h"].items():
        for n, r in rows.items():
            if float(h) < 1.0:
                assert r["http_only_vulnerable_rate"] < r["all_sink_vulnerable_rate"], (h, n)
    for n, v in (("50", 0.710), ("100", 0.912), ("200", 0.994), ("400", 1.000)):
        assert {round(rows[n]["all_sink_vulnerable_rate"], 3)
                for rows in cf["by_h"].values()} == {v}, n
    # role-mix robustness (Appendix D)
    mix = json.loads((ROOT / "results" / "role_mix.json").read_text())
    cells = [r for rows in mix["by_frac"].values() for r in rows.values()]
    assert len(cells) == 9 and all(r["analytic_inside_ci"] for r in cells)
    assert round(min(r["attack_block_rate_mean"] for r in cells), 3) == 0.918
    assert round(max(r["attack_block_rate_mean"] for r in cells), 3) == 0.921
    m30 = mix["by_frac"]["0.3"]
    close(m30["50"]["catalog_vulnerable_rate"], 0.710)
    close(m30["100"]["catalog_vulnerable_rate"], 0.912)
    close(m30["200"]["catalog_vulnerable_rate"], 0.9935)

    # Section 4.2 and Appendix E: second engine (OpenAPPA)
    appa = json.loads((ROOT / "results" / "appa.json").read_text())
    assert appa["total_paths"] == appa["total_paths_agree"] == 488_400
    assert appa["mixed_label_refused"] is True
    by = appa["by_regime"]
    assert sum(c["catalogs"] for r in by.values() for c in r.values()) == 16_500
    for regime, row in by.items():
        for n, c in row.items():
            assert c["paths_agree"] == c["paths"], (regime, n)
            assert c["appa_catalog_vulnerable"] == c["chaincaps_catalog_vulnerable"], (regime, n)
    assert {r: sum(c["paths"] for c in row.values()) for r, row in by.items()} == {
        "gold": 35_400, "low_error": 151_000, "naive_calibrated": 151_000,
        "correlated_policy_fit": 151_000}
    table_e = {"gold": [0.0] * 6,
               "low_error": [0.209, 0.437, 0.705, 0.910, 0.994, 1.000],
               "naive_calibrated": [0.981, 1.0, 1.0, 1.0, 1.0, 1.0],
               "correlated_policy_fit": [0.136, 0.208, 0.256, 0.284, 0.360, 0.427]}
    for regime, vals in table_e.items():
        got = [by[regime][str(n)]["appa_catalog_vulnerable"] for n in (10, 25, 50, 100, 200, 400)]
        assert [round(v, 3) for v in got] == vals, (regime, got)
    assert by["gold"]["200"]["benign_completion_appa"] == 1.0
    assert by["low_error"]["200"]["appa_catalog_vulnerable_ci95"] == [0.987, 0.9972]
    lo, hi = by["correlated_policy_fit"]["200"]["appa_catalog_vulnerable_ci95"]
    assert (round(lo, 3), round(hi, 3)) == (0.331, 0.39) and lo <= 0.349 <= hi
    assert appa["rho_policy_fit"] == eff["conditions"]["policy_conditioned"]["rho_homogeneous"]

    # Section 4.7 and Appendix F: real catalogs with measured errors
    rt = json.loads((ROOT / "results" / "real_tools.json").read_text())
    assert len(rt["records"]) == 3420 and not any(r.get("error") for r in rt["records"])
    spec = json.loads((ROOT / "data" / "real_tools_spec.json").read_text())["tools"]
    assert len(spec) == 114 and sum(t["restricted"] for t in spec) == 93
    assert {s: sum(1 for t in spec if t["restricted"] and t["service"] == s)
            for s in ("github", "posthog", "launchdarkly", "sentry")} == {
        "github": 26, "posthog": 43, "launchdarkly": 17, "sentry": 7}
    rc = json.loads((ROOT / "results" / "real_catalog.json").read_text())
    assert rc["total_http_agree"] == rc["total_http_paths"] == 22320
    assert rc["catalog_decisions_agree"] == rc["catalog_decisions"] == 450
    assert len(rc["authors"]) == 30 and not rc["excluded"]
    expect = {"description_only": (158, 928, 0.113, 0.887, 0.60, 0.62, 0.33, [3, 0, 0, 0, 0, 11, 4, 5, 5, 0, 42, 1, 32, 0, 55]),
              "policy_conditioned": (175, 297, 0.125, 0.875, 0.40, 0.31, 0.72, [1, 0, 0, 0, 0, 0, 1, 84, 0, 10, 8, 0, 0, 0, 71])}
    for cond, (net, anyo, p, blk, vul, bb, rho, per) in expect.items():
        a = rc["conditions"][cond]["all"]
        assert sum(a["network_overperm_per_author"].values()) == net
        assert sum(a["any_overperm_per_author"].values()) == anyo
        assert list(a["network_overperm_per_author"].values()) == per
        assert round(a["network_overperm_rate"], 3) == p
        assert round(a["rho_homogeneous"], 2) == rho
        full = a["by_deployment"]["github+posthog+launchdarkly+sentry"]
        assert full["S"] == 93 and round(full["vulnerable_share"], 2) == vul
        assert full["vulnerable_share"] == full["vulnerable_share_appa"]
        assert round(full["mean_http_block_rate"], 3) == blk
        assert round(full["predicted_beta_binomial"], 2) == bb and full["predicted_independent"] == 1.0
        deps = a["by_deployment"].values()
        mae_i = sum(abs(d["vulnerable_share"] - d["predicted_independent"]) for d in deps) / len(deps)
        mae_b = sum(abs(d["vulnerable_share"] - d["predicted_beta_binomial"]) for d in deps) / len(deps)
        assert (round(mae_i, 2), round(mae_b, 2)) == {"description_only": (0.45, 0.05),
                                                      "policy_conditioned": (0.62, 0.06)}[cond]
    pc = rc["conditions"]["policy_conditioned"]["all"]["network_overperm_per_author"]
    assert pc["ollama:llama3.2:latest"] + pc["ollama:qwen3:8b"] == 155
    assert sum(v for k, v in pc.items() if k.startswith("anthropic:")) == 1
    fr = rc["conditions"]["policy_conditioned"]["frontier"]["by_deployment"]["github+posthog+launchdarkly+sentry"]
    assert round(fr["vulnerable_share"], 2) == 0.33
    fable = [r for r in rc["rows"] if r["author"] == "anthropic:claude-fable-5-1"
             and r["condition"] == "policy_conditioned" and r["deployment"] == "github+posthog+launchdarkly+sentry"][0]
    assert fable["vulnerable_chaincaps"] == 1 and fable["network_holes"] == 1
    assert round(fable["http_block_rate"] * 93) == 92

    # Section 4.2: Wilson intervals vs the binomial
    import sys
    sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT.parent / "chaincaps-code"))
    from scaling.catalog import Role, build_catalog
    s_of = {n: sum(1 for x in build_catalog(n) if x.role is Role.SENSITIVE_SOURCE)
            for n in summary["sizes"]}
    grid_in = sum(lo <= 1 - (1 - float(p)) ** s_of[int(n)] <= hi
                  for p, row in summary["reliability_ci95"].items()
                  for n, (lo, hi) in row.items())
    assert grid_in == 77, grid_in
    for strat, p in (("low_error", 0.08), ("naive_calibrated", 0.75)):
        for n, r in summary["strategies"][strat].items():
            lo, hi = r["catalog_vulnerable_ci95"]
            assert lo <= 1 - (1 - p) ** s_of[int(n)] <= hi, (strat, n)
    print("ALL REPORTED CLAIMS VERIFIED")


if __name__ == "__main__":
    main()
