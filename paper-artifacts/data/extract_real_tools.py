"""Real tools: expert labels from OpenAPPA batteries, descriptions from each server's source."""
import json, re, sys, tomllib
from pathlib import Path
EXT = Path(sys.argv[1]); OUT = Path(sys.argv[2])
B = EXT / "OpenAPPA/marketplace/batteries"; S = EXT / "servers"

def battery(b):
    d = tomllib.load(open(B / b / "appa.toml", "rb"))
    tools = {}
    for t in d.get("policy", {}).get("tool", []):
        full = t["name"]; base = full.split("(")[0].split("/")[-1]
        aud = (t.get("delta") or {}).get("audience")
        req = (t.get("requires") or {}).get("audience")
        e = tools.setdefault(base, {"rules": [], "default": None})
        rule = {"argument_rule": "(" in full, "audience": aud, "requires_audience": req is not None}
        e["rules"].append(rule)
        if "(" not in full:
            e["default"] = rule
    return tools

def first_line(s):
    s = " ".join(s.replace("\\n", "\n").split("\n\n")[0].split())
    m = re.match(r"(.+?[.!?])(\s|$)", s)
    s = m.group(1) if m else s
    return s[:240]

def github():
    out = {}
    pat = re.compile(r'Name:\s*"(?P<n>[a-z0-9_]+)",(?P<mid>(?:(?!Name:)[\s\S]){0,600}?)Description:\s*t\("[A-Z0-9_]+",\s*(?:"(?P<d>(?:\\.|[^"\\])*)"|`(?P<b>[^`]*)`|(?P<v>[A-Za-z_][A-Za-z0-9_]*))\)')
    for p in (S / "github_github-mcp-server/pkg").rglob("*.go"):
        if p.name.endswith("_test.go"): continue
        text = p.read_text()
        for m in pat.finditer(text):
            d = m.group("d") or m.group("b")
            if d is None and m.group("v"):
                v = re.search(r'%s\s*:?=\s*(?:"((?:\\.|[^"\\])*)"|`([^`]*)`)' % m.group("v"), text)
                d = (v.group(1) or v.group(2)) if v else None
            if d:
                out.setdefault(m.group("n"), (d.replace('\\"', '"'), str(p.relative_to(EXT))))
    return out

def posthog():
    d = json.load(open(S / "PostHog_mcp/schema/tool-definitions.json"))
    return {k: (v.get("description", ""), "servers/PostHog_mcp/schema/tool-definitions.json") for k, v in d.items()}

def sentry():
    d = json.load(open(S / "getsentry_sentry-mcp/packages/mcp-core/src/toolDefinitions.json"))
    return {t["name"]: (t["description"], "servers/getsentry_sentry-mcp/packages/mcp-core/src/toolDefinitions.json") for t in d}

def launchdarkly():
    out = {}
    pat = re.compile(r'name:\s*"(?P<n>[a-z0-9-]+)",\s*description:\s*(?P<q>[`"])(?P<d>[\s\S]*?)(?P=q)\s*,')
    for p in (S / "launchdarkly_mcp-server/src/mcp-server/tools").glob("*.ts"):
        for m in pat.finditer(p.read_text()):
            out.setdefault(m.group("n"), (m.group("d"), str(p.relative_to(EXT))))
    return out

SOURCES = {"github": github, "posthog": posthog, "sentry": sentry, "launchdarkly": launchdarkly}
rows = []
for svc, fn in SOURCES.items():
    descs = fn(); bat = battery(svc)
    for tool, e in sorted(bat.items()):
        d, where = descs.get(tool, (None, None))
        rule = e["default"] or e["rules"][0]
        restricted_default = rule["audience"] is not None and "public" not in rule["audience"]
        any_restricted = any(r["audience"] is not None and "public" not in r["audience"] for r in e["rules"])
        writes = any(r["requires_audience"] for r in e["rules"])
        reads = any(r["audience"] is not None for r in e["rules"])
        rows.append({"service": svc, "tool": tool, "description": first_line(d) if d else None,
                     "full_description_chars": len(d) if d else 0, "description_source": where,
                     "battery_rules": len(e["rules"]), "has_default_rule": e["default"] is not None,
                     "default_audience": rule["audience"], "restricted": restricted_default or (e["default"] is None and any_restricted),
                     "writes": writes, "reads_labeled": reads})
    n = sum(1 for r in rows if r["service"] == svc); f = sum(1 for r in rows if r["service"] == svc and r["description"])
    print(f"{svc:13s} tools={n:3d} described={f:3d} restricted={sum(1 for r in rows if r['service']==svc and r['restricted'])}")
OUT.write_text(json.dumps(rows, indent=1))
