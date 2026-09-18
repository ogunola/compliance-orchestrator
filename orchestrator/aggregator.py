"""
Rolls a flat list of Finding records up against the ATT&CK -> NIST 800-53 ->
CIS Controls crosswalk (data/attack_crosswalk.generated.json, built by
data/build_crosswalk.py from the real MITRE/CTID source datasets) plus the
hand-curated Zero Trust pillar / ISO 27001 overlay
(data/control_mappings.yaml), into per-framework and per-Zero-Trust-pillar
coverage views.
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

DEFAULT_CROSSWALK_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_crosswalk.generated.json"


def load_mappings(overlay_path: Path, crosswalk_path: Path = DEFAULT_CROSSWALK_PATH) -> dict[str, Any]:
    """
    Merges the auto-generated ATT&CK->NIST->CIS crosswalk with the curated
    Zero Trust pillar / ISO 27001 overlay into one by_technique lookup.
    """
    with open(overlay_path, "r") as fh:
        overlay_data = yaml.safe_load(fh)
    overlay_by_technique = {row["attack_technique"]: row for row in overlay_data.get("overlay", [])}

    by_technique: dict[str, dict[str, Any]] = {}

    if crosswalk_path.exists():
        crosswalk_data = json.loads(crosswalk_path.read_text())
        for row in crosswalk_data.get("techniques", []):
            technique = row["attack_technique"]
            by_technique[technique] = {
                "attack_technique": technique,
                "attack_name": row.get("attack_name"),
                "nist_800_53": row.get("nist_800_53", []),
                "cis_controls": row.get("cis_controls", []),
                "iso_27001_annex_a": [],
                "zt_pillar": None,
            }
    else:
        logger.warning(
            "%s not found - run `python3 data/build_crosswalk.py` first. "
            "Falling back to the curated overlay's own techniques only "
            "(no NIST/CIS coverage).",
            crosswalk_path,
        )

    # Layer the curated overlay (zt_pillar, iso_27001_annex_a) on top. A
    # technique present only in the overlay (not in the generated crosswalk)
    # still gets an entry, just with empty nist/cis lists.
    for technique, overlay_row in overlay_by_technique.items():
        entry = by_technique.setdefault(
            technique,
            {
                "attack_technique": technique,
                "attack_name": None,
                "nist_800_53": [],
                "cis_controls": [],
                "iso_27001_annex_a": [],
                "zt_pillar": None,
            },
        )
        entry["iso_27001_annex_a"] = overlay_row.get("iso_27001_annex_a", [])
        entry["zt_pillar"] = overlay_row.get("zt_pillar")

    return {
        "by_technique": by_technique,
        "zero_trust_pillars": overlay_data.get("zero_trust_pillars", {}),
        "pillar_tool_coverage": overlay_data.get("pillar_tool_coverage", {}),
    }


def _lookup_technique_row(technique: str, by_technique: dict[str, Any]) -> tuple[dict[str, Any] | None, bool]:
    """
    Exact match first; if a sub-technique (T1078.001) isn't mapped, fall
    back to its base technique (T1078) - the crosswalk maps some techniques
    only at the base level. Returns (row, was_fallback).
    """
    if technique in by_technique:
        return by_technique[technique], False
    base = technique.split(".")[0]
    if base != technique and base in by_technique:
        return by_technique[base], True
    return None, False


def aggregate(findings: list[Finding], mappings: dict[str, Any]) -> dict[str, Any]:
    """
    Returns a dict with:
      - totals: overall pass/fail/error/unknown counts
      - by_tool: counts per source_tool
      - by_attack_technique: counts per T#### with mapped frameworks attached
      - by_framework: {"nist_800_53": {control_id: {...}}, "cis_controls": {...}, "iso_27001_annex_a": {...}}
      - by_zt_pillar: {pillar: {pass, fail, ..., tools_reporting: set}}
      - unmapped_techniques: ATT&CK techniques seen in findings but absent from the crosswalk+overlay
      - fallback_techniques: sub-techniques resolved via their base technique
    """
    by_technique_map = mappings["by_technique"]

    totals = defaultdict(int)
    by_tool: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_attack_technique: dict[str, dict[str, Any]] = {}
    by_framework: dict[str, dict[str, dict[str, int]]] = {
        "nist_800_53": defaultdict(lambda: defaultdict(int)),
        "cis_controls": defaultdict(lambda: defaultdict(int)),
        "iso_27001_annex_a": defaultdict(lambda: defaultdict(int)),
    }
    by_zt_pillar: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"pass": 0, "fail": 0, "error": 0, "unknown": 0, "not_applicable": 0, "tools_reporting": set()}
    )
    unmapped_techniques: set[str] = set()
    fallback_techniques: set[str] = set()

    for f in findings:
        totals[f.status] += 1
        by_tool[f.source_tool][f.status] += 1

        if not f.attack_technique:
            continue

        technique = f.attack_technique
        row, was_fallback = _lookup_technique_row(technique, by_technique_map)
        if was_fallback:
            fallback_techniques.add(technique)

        tech_entry = by_attack_technique.setdefault(
            technique,
            {"pass": 0, "fail": 0, "error": 0, "unknown": 0, "not_applicable": 0, "mapped": row is not None},
        )
        tech_entry[f.status] += 1

        if row is None:
            unmapped_techniques.add(technique)
            continue

        for control_id in row.get("nist_800_53", []):
            by_framework["nist_800_53"][control_id][f.status] += 1
        for control_id in row.get("cis_controls", []):
            by_framework["cis_controls"][control_id][f.status] += 1
        for control_id in row.get("iso_27001_annex_a", []):
            by_framework["iso_27001_annex_a"][control_id][f.status] += 1

        pillar = row.get("zt_pillar")
        if pillar:
            by_zt_pillar[pillar][f.status] += 1
            by_zt_pillar[pillar]["tools_reporting"].add(f.source_tool)

    # PingCastle findings without an attack_technique still count toward the
    # identity pillar (see pingcastle_parser docstring) - add them explicitly.
    for f in findings:
        if f.source_tool == "pingcastle" and not f.attack_technique:
            by_zt_pillar["identity"][f.status] += 1
            by_zt_pillar["identity"]["tools_reporting"].add("pingcastle")

    # Flag pillars with zero evidence at all, using the declared tool coverage
    # map, so the report can call out real gaps (e.g. automation_orchestration,
    # governance) instead of silently showing "0 findings" with no context.
    pillar_gaps = []
    all_pillars = mappings.get("zero_trust_pillars", {})
    for pillar_key in all_pillars:
        if pillar_key not in by_zt_pillar or sum(
            by_zt_pillar[pillar_key][s] for s in ("pass", "fail", "error", "unknown", "not_applicable")
        ) == 0:
            pillar_gaps.append(pillar_key)

    # Convert sets to sorted lists for JSON/YAML serialization downstream.
    for pillar_data in by_zt_pillar.values():
        pillar_data["tools_reporting"] = sorted(pillar_data["tools_reporting"])

    return {
        "totals": dict(totals),
        "by_tool": {k: dict(v) for k, v in by_tool.items()},
        "by_attack_technique": by_attack_technique,
        "by_framework": {k: {ck: dict(cv) for ck, cv in v.items()} for k, v in by_framework.items()},
        "by_zt_pillar": dict(by_zt_pillar),
        "pillar_gaps": pillar_gaps,
        "unmapped_techniques": sorted(unmapped_techniques),
        "fallback_techniques": sorted(fallback_techniques),
    }
