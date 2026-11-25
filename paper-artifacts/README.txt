CAMERA-READY SUPPLEMENT
Per-Attack Blocking Hides Catalog Vulnerability:
A Weakest-Link Analysis of Tool Manifests
Karthik Karunanithi. Third Workshop on Agents in the Wild (NeurIPS 2026).

This supplement contains the complete deterministic catalog sweep, dependence
analysis, plotting code, local-model pilot, raw result tables, the pinned
ChainCaps engine used by the paper, and the harness that replays the same tests
in a second engine, OpenAPPA.

LAYOUT AFTER EXTRACTION

  manifest-scaling/
    scaling/                       Catalog, authoring, workflow, and correlated-authoring modules
    tests/smoke.py                 Invariant checks
    calibration/run_llm_calibration.py     Submitted pilot (7 models, 18 tools)
    calibration/run_llm_calibration_v2.py  Expanded pilot (15 models, 28 tools; camera-ready)
    calibration/summarize_pilot2.py        Per-author check of the expanded pilot
    run_scaling.py                 2,000-draw catalog sweep
    run_sink_coverage.py           HTTP-only vs all-sink coverage sweep (pilot mixes)
    run_coverage_fraction.py       Coverage sweep over the HTTP share h (camera-ready)
    run_correlated.py              Engine sweep under the pilot-fitted author effect (camera-ready)
    analyze_dependence.py          Exact shared-decision sensitivity
    analyze_pilot_dependence.py    Pilot error-correlation statistics
    analyze_effective_m.py         Effective number of independent decisions (camera-ready)
    analyze_meff_plot.py           Figure for the effective-M curves (camera-ready)
    run_role_mix.py                Role-mix robustness in the engine (camera-ready)
    run_appa.py                    Paired ChainCaps vs OpenAPPA sweep (camera-ready)
    run_real_catalog.py            Real MCP catalogs with measured errors, both engines (camera-ready)
    calibration/run_real_tools.py  Authoring run on 114 real MCP tools (camera-ready)
    data/real_tools_spec.json      The 114 real tools: descriptions, expert gold, provenance
    data/extract_real_tools.py     How the spec was extracted from the servers and batteries
    analyze_plots.py               Tolerable-rate figure (and the submission's contrast figure)
    analyze_teaser.py              Figure 1: synthetic and real catalogs (camera-ready)
    results/                       Raw CSV and JSON outputs
    figures/                       Generated PDF figures
    requirements.txt
    README.txt
  chaincaps-code/
    chaincaps/                     Pinned third-party enforcement engine
    LICENSE                        Upstream MIT license
    COMMIT                         Upstream commit identifier

ENVIRONMENT

Core experiments:
  Python 3.13.13 (standard library only)

Figures:
  matplotlib 3.11.1

Local-model pilot (optional). Submitted pilot, Ollama 0.33.3:
  gemma2:9b          ff02c3702f32
  llama3.1:8b        46e0c10c039e
  qwen2.5:7b         845dbda0ea48
  mistral:7b         6577803aa9a0
  phi3.5:latest      61819fb370a3
  qwen2.5:3b         357c53fb659c
  llama3.2:latest    a80c4f17acd5
Expanded camera-ready pilot, Ollama 0.33.3: the seven above plus
  gemma3:12b         b92b218582c5
  granite3.3:8b      fd429f23b909
  olmo2:7b           4208d3b406db
  phi4:latest        ac896e5b8b34
  qwen3:8b           500a1f067a9f
and three hosted frontier models through the Anthropic API:
  claude-fable-5-1, claude-haiku-5-5, claude-sonnet-5-5
(these reject temperature 0 and run at their default sampling; listed under
"temperature_unsupported" in the output's protocol block)

The included ChainCaps package is pinned to upstream commit
  dc268006af3ed06583178c273549ab0171aadec9
and retains its upstream MIT license.

Second engine (optional, not included): OpenAPPA 0.38.1, MIT license,
  https://github.com/archestra-ai/OpenAPPA
  commit fc46b128babfeaf0f29e288d326ae3d3db12627e
built with `cargo build --release` (Rust 1.97). Only the `appa` binary is used.

QUICK REPRODUCTION

From the extracted manifest-scaling directory:

  PYTHONPATH=. python3 tests/smoke.py
  PYTHONPATH=. python3 run_scaling.py
  PYTHONPATH=. python3 run_sink_coverage.py
  PYTHONPATH=. python3 analyze_dependence.py
  PYTHONPATH=. python3 analyze_pilot_dependence.py
  PYTHONPATH=. python3 analyze_effective_m.py
  PYTHONPATH=. python3 run_correlated.py
  PYTHONPATH=. python3 run_coverage_fraction.py
  PYTHONPATH=. python3 run_role_mix.py
  PYTHONPATH=. python3 tests/test_reported_claims.py
  python3 analyze_plots.py
  PYTHONPATH=. python3 analyze_meff_plot.py

The first three commands do not use a network, model API, or external dataset.
run_scaling.py regenerates results/strategies.csv, results/reliability.csv, and
results/summary.json. run_sink_coverage.py regenerates results/sink_coverage.json.
analyze_dependence.py regenerates results/dependence.json.
analyze_pilot_dependence.py regenerates results/pilot_dependence.json from the
preserved pilot outputs. analyze_effective_m.py regenerates
results/effective_m.json (moment-matched intra-class correlation on the
expanded pilot, bootstrap over the fifteen models with a fixed seed, the implied
effective number of independent decisions, the same fit on the submitted
seven-model pilot, local-only, frontier-only, subset and leave-one-author-out
estimates, and the tolerable
rate at the fit); run_correlated.py must run after it and regenerates
results/correlated.json. run_sink_coverage.py draws excess channels from the
expanded pilot's counts (scaling/sink_coverage.py). run_coverage_fraction.py regenerates
results/coverage_fraction.json. run_role_mix.py regenerates results/role_mix.json.
analyze_meff_plot.py regenerates figures/effective_m.pdf. tests/test_reported_claims.py checks every
number quoted in the paper against these files. analyze_plots.py regenerates figures/contrast.pdf and
figures/tolerable_rate.pdf.

OPTIONAL SECOND ENGINE (OPENAPPA)

Build OpenAPPA at the commit above, then run:

  APPA_BIN=/path/to/appa PYTHONPATH=. python3 run_appa.py

run_appa.py must run after analyze_effective_m.py. It authors the same
catalogs as the main sweep (same seeds and random draws; 1,000 per size up to
N=200, 300 at N=400, 100 for gold), translates each catalog into an OpenAPPA
policy (scaling/appa_engine.py), writes one trace per test path, evaluates
them with `appa replay`, and evaluates the same paths in ChainCaps. It
regenerates results/appa.json: per-path agreement, both engines'
catalog-vulnerable rates, and a check that OpenAPPA refuses a reader set that
combines `public` with other entries. No tool is executed and no network is
used. The full run takes about 80 minutes on two cores.

REAL CATALOGS WITH MEASURED ERRORS

data/real_tools_spec.json lists 114 real tools from four open-source MCP
servers (GitHub, PostHog, LaunchDarkly, Sentry; commits in the file) with the
first sentence of each server's own description, and the gold label from the
expert-written OpenAPPA battery rules for that server (93 restricted tools).
calibration/run_real_tools.py asks the same 15 authors to write a manifest for
each tool (same prompt template as the pilot; results/real_tools.json, with
results/real_tools_summary.txt from calibration/summarize_real_tools.py).
run_real_catalog.py then builds every author's manifests for each of the 15
service combinations, sends every restricted tool to external HTTP, email, and
file sinks in ChainCaps and OpenAPPA, and writes results/real_catalog.json
(per-author errors, vulnerable share per deployment, independence and
author-effect predictions, engine agreement). It needs APPA_BIN and takes
about 10 minutes:

  APPA_BIN=/path/to/appa PYTHONPATH=. python3 run_real_catalog.py

OPTIONAL LOCAL-MODEL PILOT

Start Ollama, install the models listed above, then run:

  python3 calibration/run_llm_calibration.py       # submitted pilot
  python3 calibration/run_llm_calibration_v2.py    # expanded pilot
  python3 calibration/summarize_pilot2.py

These regenerate results/llm_calibration.json and
results/llm_calibration_v2.json (and results/pilot2_summary.txt). The expanded
run uses the submitted prompts and scoring unchanged, adds ten sensitive
sources, and is resumable. Hosted models are queried when their API key is set
in the environment (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY); the
camera-ready run used the Anthropic API only. Failed requests are retried on
a rerun. The preserved
JSON files contain the outputs for every model, tool, and condition. Although temperature is 0
and the seed is fixed at 7, runtime and hardware differences can affect local
model output; the preserved outputs are the submission record.

MEASURED OBJECT

The main sweep constructs synthetic catalogs with gold manifests known by
construction. It injects HTTP-enabling errors into confidential source budgets,
then tests each confidential source through one representative HTTP path using
the public ChainCaps engine. catalog_vulnerable equals one when at least one
such path is accepted. This is a source-complete conformance property of the
generated catalog, not a probability of real-world compromise.

The low_error and naive_calibrated labels name synthetic regimes. They do not
represent measured human author classes. The calibrated-high regime has p=0.75,
which gives expected per-path blocking 0.25 and is used only as an anchor near
the 27.3% naive attack-block rate reported by ChainCaps. That is an attack-block
rate, not a source-budget error rate; p=0.75 is not an estimate of the latter. The local-model pilot is a separate,
descriptive experiment and does not supply p for the main sweep.

EXPECTED CHECKS

  - Gold manifests block every tested attack and complete every benign path.
  - A planted source-budget error permits HTTP exfiltration.
  - At p=0.08, per-path blocking remains near 0.92 while catalog vulnerability
    increases with the number of independent source-policy decisions.
  - The empirical grid slope is approximately -0.989; the exact finite-size
    expression over the same sizes has slope approximately -1.005.
  - With one shared authoring decision for the whole catalog, the inverse-size
    result disappears.
  - Under the author effect fitted to the policy-conditioned expanded pilot
    (rho=0.45, 15 authors), a 200-tool catalog is vulnerable in about 0.35 of
    draws (effective independent decisions about 5.2, bootstrap 95% 3.4 to
    9.2) while per-attack blocking stays near 0.92.
  - An HTTP-only test under-reports catalog vulnerability for every HTTP share
    of excess channels below one; all-sink coverage is unaffected by the share.
  - OpenAPPA and ChainCaps make the same decision on all 488,400 paired test
    paths (16,500 catalogs, four regimes).
  - On the real catalogs, the models' own manifests leave 9 of 15 four-service
    catalogs vulnerable (6 of 15 with the policy) at about 0.89 per-attack
    blocking; the engines agree on all 22,320 HTTP paths and 450 catalog
    decisions.

PROVENANCE

The archive contains no local absolute paths or repository metadata. The core
sweeps were rerun for the camera-ready on Python 3.13 and reproduce the
submission's summary, strategies, reliability, and dependence files byte for
byte. Files that depend on the pilot (sink_coverage, pilot_dependence,
effective_m, correlated, appa) were regenerated from the expanded pilot; the
submitted pilot's fit is kept inside effective_m.json ("submitted_pilot") and
pilot_dependence.json ("submitted").