"""
Rolls up garak findings against the OWASP LLM Top 10 (via garak's own
probe tags - see data/ai_redteam/garak_probe_tags.generated.json) and the
curated Zero Trust pillar overlay in data/ai_redteam/owasp_llm_top10_2025.yaml.

Deliberately kept SEPARATE from orchestrator/aggregator.py rather than
merged into it: OWASP's LLM Top 10 has no free structured crosswalk to
NIST 800-53 or CIS Controls, so there's nothing legitimate to join garak
findings onto in the main by_framework rollup (see
data/ai_redteam/SOURCES.md for the reasoning). This module produces its own
parallel view instead of fabricating one.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from .schema import Finding

logger = logging.getLogger(__name__)

DEFAULT_PROBE_TAGS_PATH = Path(__file__).resolve().parent.parent / "data" / "ai_redteam" / "garak_probe_tags.generated.json"
DEFAULT_CATEGORIES_PATH = Path(__file__).resolve().parent.parent / "data" / "ai_redteam" / "owasp_llm_top10_2025.yaml"


def load_owasp_mapping(
    probe_tags_path: Path = DEFAULT_PROBE_TAGS_PATH,
    categories_path: Path = DEFAULT_CATEGORIES_PATH,
) -> dict[str, Any]:
    probe_tags: dict[str, Any] = {}
    if probe_tags_path.exists():
        probe_tags = json.loads(probe_tags_path.read_text())
    else:
        logger.warning(
            "%s not found - run `python3 data/ai_redteam/extract_garak_probe_tags.py "
            "/path/to/garak/checkout` first. Falling back to no probe->OWASP mapping.",
            probe_tags_path,
        )

    with open(categories_path, "r") as fh:
        category_data = yaml.safe_load(fh)

    return {
        "probe_tags": probe_tags,
        "categories": category_data.get("categories", {}),
    }


def aggregate_ai(findings: list[Finding], mapping: dict[str, Any]) -> dict[str, Any]:
    """
    Returns a dict with:
      - totals: overall pass/fail/error/unknown/not_applicable counts (garak findings only)
      - by_probe: counts per garak probe id
      - by_owasp_category: {"LLM01": {"pass":.., "fail":.., "probes": [...]}, ...}
      - by_zt_pillar: same shape as the main aggregator's, for whatever pillars OWASP categories map to
      - unmapped_probes: probe ids seen in findings but absent from garak_probe_tags.generated.json
      - uncovered_categories: OWASP categories with zero findings routed to them (e.g. LLM03, always)
    """
    probe_tags = mapping["probe_tags"]
    categories = mapping["categories"]

    totals = defaultdict(int)
    by_probe: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_owasp_category: dict[str, dict[str, Any]] = {
        cat_id: {"pass": 0, "fail": 0, "error": 0, "unknown": 0, "not_applicable": 0, "probes": set()}
        for cat_id in categories
    }
    by_zt_pillar: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"pass": 0, "fail": 0, "error": 0, "unknown": 0, "not_applicable": 0, "categories": set()}
    )
    unmapped_probes: set[str] = set()

    for f in findings:
        if f.source_tool != "garak":
            continue

        totals[f.status] += 1
        probe = f.secondary_tag or "unknown"
        by_probe[probe][f.status] += 1

        probe_info = probe_tags.get(probe)
        if probe_info is None:
            unmapped_probes.add(probe)
            continue

        for cat_id in probe_info.get("owasp_llm_categories", []):
            if cat_id not in by_owasp_category:
                by_owasp_category[cat_id] = {
                    "pass": 0, "fail": 0, "error": 0, "unknown": 0, "not_applicable": 0, "probes": set()
                }
            by_owasp_category[cat_id][f.status] += 1
            by_owasp_category[cat_id]["probes"].add(probe)

            pillar = categories.get(cat_id, {}).get("zt_pillar")
            if pillar:
                by_zt_pillar[pillar][f.status] += 1
                by_zt_pillar[pillar]["categories"].add(cat_id)

    uncovered_categories = [
        cat_id
        for cat_id in categories
        if sum(by_owasp_category.get(cat_id, {}).get(s, 0) for s in ("pass", "fail", "error", "unknown", "not_applicable")) == 0
    ]

    for cat_data in by_owasp_category.values():
        cat_data["probes"] = sorted(cat_data["probes"])
    for pillar_data in by_zt_pillar.values():
        pillar_data["categories"] = sorted(pillar_data["categories"])

    return {
        "totals": dict(totals),
        "by_probe": {k: dict(v) for k, v in by_probe.items()},
        "by_owasp_category": by_owasp_category,
        "by_zt_pillar": dict(by_zt_pillar),
        "unmapped_probes": sorted(unmapped_probes),
        "uncovered_categories": sorted(uncovered_categories),
    }
