# catalogrisk

Reporting per-attack blocking makes a tool catalog look safer than it is.

If each of `M` independently written tool policies is wrong with probability `p`, per-attack blocking stays at `1 - p`. But the chance that the catalog contains at least one open exfiltration path is `1 - (1 - p)^M`, and that number climbs quickly as catalogs grow.

`catalogrisk` computes the numbers an evaluation should report alongside blocking:

- catalog vulnerability
- the effective number of independent decisions when one author's errors are correlated
- the tolerable per-policy error rate for a target catalog risk

It is the companion code to:

> Karthik Karunanithi. **Per-Attack Blocking Hides Catalog Vulnerability: A Weakest-Link Analysis of Tool Manifests.** arXiv:2611.31338, 2026. Poster at the Third Workshop on Agents in the Wild, NeurIPS 2026. https://arxiv.org/abs/2611.31338

## Install

```bash
pip install catalogrisk          # once published to PyPI
pip install git+https://github.com/karthikknidhi/catalogrisk
```

The package uses only the standard library and needs Python 3.9 or later.

## Use

```bash
catalogrisk --p 0.08 --tools 200 --rho 0.45
```

```
Catalog of 200 tools (60 sensitive sources), per-policy error 0.080, rho 0.45
  per-attack blocking            92.0%
  catalog vulnerability          35.2%  (independent: 99.3%)
  effective independent choices  5.2
  tolerable error rate @ eps=0.05  0.00983
```

```python
from catalogrisk import report, estimate_rho

rho, D, pbar = estimate_rho([0, 0, 0, 0, 4, 2, 11, 10, 12, 15, 16, 0, 3, 9, 17], s=19)
print(report(p=0.08, tools=200, rho=rho))
```

You can estimate `rho` from your own authoring data. Give `estimate_rho` the number of over-permissioned sources each author (person or model) produced, out of `s` sensitive sources.

## What to report

An evaluation of manifest-based controls should report four things together:

1. per-attack blocking
2. catalog vulnerability at realistic catalog sizes
3. the sink coverage of the tests
4. the effective number of independent decisions

## Reproducing the paper

`paper-artifacts/` contains the camera-ready supplement:

- the deterministic catalog sweep
- the dependence analysis
- the 15-model authoring pilot
- the 114 real MCP tools with expert-written rules
- raw results
- the figure code

It also includes the pinned ChainCaps engine under its upstream MIT license. See `paper-artifacts/README.txt`.

`tests/test_paper_numbers.py` checks this package against values reported in the paper.

## Cite

```bibtex
@article{karunanithi2026perattack,
  title   = {Per-Attack Blocking Hides Catalog Vulnerability: A Weakest-Link Analysis of Tool Manifests},
  author  = {Karunanithi, Karthik},
  journal = {arXiv preprint arXiv:2611.31338},
  year    = {2026},
  note    = {Poster, Third Workshop on Agents in the Wild (AIWILD), NeurIPS 2026}
}
```

## License

MIT, except `paper-artifacts/chaincaps-code/`, which keeps its upstream license.
