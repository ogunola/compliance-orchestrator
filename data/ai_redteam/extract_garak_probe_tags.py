#!/usr/bin/env python3
"""
Builds data/ai_redteam/garak_probe_tags.generated.json - a static dump of
every garak probe class's own metadata (goal, tags, and specifically its
owasp:llmXX tags), read directly from garak's source rather than
hand-curated.

Why this exists: garak's own Report.get_evaluations() (garak/report.py)
derives each probe's tags by dynamically importing the probe module and
instantiating the class at report-analysis time. That's fine for garak
itself, but it means our aggregation side would need garak (and its heavy
ML dependencies - torch, transformers) installed just to read a handful of
static string tags off a class. This script does that read ONCE, on a
machine that has garak's probe modules importable, and writes the result
to a plain JSON file so orchestrator/ai_aggregator.py never needs garak
installed at all - same pattern as data/build_crosswalk.py for the
ATT&CK/NIST/CIS data.

Requirements to RUN this script (not to use its output):
    pip install garak
    # if you only want probe metadata (no local-model generation), you can
    # get away with a much lighter set - verified working with just:
    pip install tqdm tiktoken huggingface_hub nltk wn
    # (garak's core package itself still lists torch/transformers as hard
    # requirements in pyproject.toml even though probe *metadata* doesn't
    # need them - a plain `pip install garak` will pull those in too)

Usage:
    python3 data/ai_redteam/extract_garak_probe_tags.py /path/to/garak/checkout

Re-run this whenever you upgrade garak to pick up new/changed probes.
"""

from __future__ import annotations

import importlib
import inspect
import json
import pkgutil
import sys
from pathlib import Path

OUTPUT_FILE = Path(__file__).parent / "garak_probe_tags.generated.json"


def build(garak_checkout: str) -> dict:
    sys.path.insert(0, garak_checkout)
    import garak.probes as probes_pkg
    from garak.probes.base import Probe

    results: dict[str, dict] = {}

    for _, modname, _ in pkgutil.iter_modules(probes_pkg.__path__):
        try:
            mod = importlib.import_module(f"garak.probes.{modname}")
        except Exception as exc:  # noqa: BLE001 - report and keep going
            print(f"  skipping garak.probes.{modname}: {exc}", file=sys.stderr)
            continue

        for name, cls in inspect.getmembers(mod, inspect.isclass):
            if cls.__module__ != f"garak.probes.{modname}":
                continue  # imported from elsewhere (base classes, mixins)
            if not issubclass(cls, Probe) or cls is Probe or inspect.isabstract(cls):
                continue

            tags = sorted(set(getattr(cls, "tags", []) or []))
            owasp_categories = sorted(
                {f"LLM{t.split(':', 1)[1][3:].zfill(2)}" for t in tags if t.startswith("owasp:llm")}
            )

            probe_id = f"{modname}.{name}"
            results[probe_id] = {
                "module": modname,
                "class_name": name,
                "goal": getattr(cls, "goal", "") or "",
                "active_by_default": bool(getattr(cls, "active", True)),
                "tags": tags,
                "owasp_llm_categories": owasp_categories,
            }

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} /path/to/garak/checkout", file=sys.stderr)
        sys.exit(1)

    data = build(sys.argv[1])
    OUTPUT_FILE.write_text(json.dumps(data, indent=2))

    with_owasp = [p for p, d in data.items() if d["owasp_llm_categories"]]
    print(f"Wrote {OUTPUT_FILE}")
    print(f"  {len(data)} probe classes total")
    print(f"  {len(with_owasp)} carry at least one owasp:llmXX tag from garak itself")
