"""
Load the local-model authoring pilots in one shape.

Two record files exist:

  results/llm_calibration.json     the submitted pilot: 7 models, 18 tools
                                   (9 sensitive sources), grouped by model
  results/llm_calibration_v2.json  the expanded camera-ready pilot: 15 models
                                   (12 local, 3 hosted frontier), the same 18
                                   tools plus 10 sensitive sources
                                   (28 tools, 19 sensitive sources), one record
                                   per request

`load_pilot()` returns a list of {"model", "condition", "details"} entries, the
format of the submitted file, with `details` in the run's tool order. The
expanded run reproduces the submitted pilot's answers for the original seven
models on the original 18 tools exactly (see calibration/summarize_pilot2.py).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
SUBMITTED = ROOT / "results" / "llm_calibration.json"
EXPANDED = ROOT / "results" / "llm_calibration_v2.json"

ORIGINAL_SOURCES = ["read_file", "list_directory", "db_query", "postgres_query",
                    "s3_download", "redis_get", "pdf_extract", "doc_search",
                    "calendar_read"]
ORIGINAL_MODELS = ["gemma2:9b", "llama3.1:8b", "qwen2.5:7b", "mistral:7b",
                   "phi3.5:latest", "qwen2.5:3b", "llama3.2:latest"]


def load_pilot(which: str = "expanded") -> List[Dict]:
    if which == "submitted":
        return json.loads(SUBMITTED.read_text())["models"]
    recs = json.loads(EXPANDED.read_text())["records"]
    order: Dict[str, int] = {}
    for r in recs:
        order.setdefault(r["tool"], len(order))
    grouped: Dict[tuple, List[Dict]] = {}
    for r in recs:
        grouped.setdefault((r["model"], r["condition"]), []).append(r)
    out = []
    for (model, cond), rows in sorted(grouped.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        out.append({"model": model, "condition": cond,
                    "details": sorted(rows, key=lambda r: order[r["tool"]])})
    return out


def restrict(models: List[Dict], model_names=None, sources=None) -> List[Dict]:
    """Subset of authors and/or sensitive sources (non-sensitive tools kept)."""
    out = []
    for m in models:
        if model_names is not None and m["model"] not in model_names:
            continue
        det = [d for d in m["details"]
               if sources is None or d["over_permission"] is None or d["tool"] in sources]
        out.append({**m, "details": det})
    return out
