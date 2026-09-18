#!/usr/bin/env python3
"""
Builds data/attack_crosswalk.generated.json - the full ATT&CK -> NIST 800-53
-> CIS Controls v8.1 crosswalk - by joining the two vendored source datasets
in data/sources/ on their shared NIST 800-53 control id.

Run this whenever you refresh the source files (new ATT&CK version, new CIS
Controls version): see data/sources/SOURCES.md for where to get updates.

    python3 data/build_crosswalk.py

This does NOT touch data/control_mappings.yaml, which stays a separate,
hand-curated overlay for Zero Trust pillar tags and ISO 27001 Annex A
references - things neither source dataset covers. orchestrator/aggregator.py
loads the generated file as the base and layers control_mappings.yaml on top.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

SOURCES_DIR = Path(__file__).parent / "sources"
ATTACK_NIST_FILE = SOURCES_DIR / "nist_800_53-rev5_attack-16.1-enterprise.json"
CIS_NIST_FILE = SOURCES_DIR / "cis-cci-mapping-v8.1.json"
OUTPUT_FILE = Path(__file__).parent / "attack_crosswalk.generated.json"

_CONTROL_RE = re.compile(r"^([A-Z]{2})-\s*\(?(\d+)\)?")


def normalize_control(raw: str) -> str | None:
    """'AC-6 (5)' -> 'AC-06', 'CM-8.3' -> 'CM-08', 'CM-03' -> 'CM-03'."""
    match = _CONTROL_RE.match(raw.strip())
    if not match:
        return None
    family, number = match.groups()
    return f"{family}-{int(number):02d}"


def display_control(normalized: str) -> str:
    """'AC-06' -> 'AC-6' for human-readable output."""
    family, number = normalized.split("-")
    return f"{family}-{int(number)}"


def build() -> dict:
    attack_data = json.loads(ATTACK_NIST_FILE.read_text())
    cis_data = json.loads(CIS_NIST_FILE.read_text())

    # --- CIS safeguard -> normalized NIST base control(s) ---
    nist_to_cis: dict[str, set[str]] = {}
    unnormalizable_cis = []
    for entry in cis_data["mappings"]:
        normalized = normalize_control(entry["nist_control"])
        if normalized is None:
            unnormalizable_cis.append(entry)
            continue
        nist_to_cis.setdefault(normalized, set()).add(entry["cis_id"])

    # --- ATT&CK technique -> NIST base controls (direct, from CTID) ---
    technique_rows: dict[str, dict] = {}
    for obj in attack_data["mapping_objects"]:
        technique_id = obj["attack_object_id"]
        row = technique_rows.setdefault(
            technique_id,
            {
                "attack_technique": technique_id,
                "attack_name": obj.get("attack_object_name"),
                "status": obj["status"],  # "complete" or "non_mappable"
                "nist_800_53": [],
                "cis_controls": [],
            },
        )
        if obj["status"] != "complete" or not obj.get("capability_id"):
            continue
        normalized = normalize_control(obj["capability_id"])
        if normalized is None:
            continue
        display = display_control(normalized)
        if display not in row["nist_800_53"]:
            row["nist_800_53"].append(display)

        # derive CIS Controls transitively via the shared NIST control
        for cis_id in sorted(nist_to_cis.get(normalized, [])):
            if cis_id not in row["cis_controls"]:
                row["cis_controls"].append(cis_id)

    rows = sorted(technique_rows.values(), key=lambda r: r["attack_technique"])

    complete_rows = [r for r in rows if r["status"] == "complete"]
    with_cis = [r for r in complete_rows if r["cis_controls"]]

    return {
        "_metadata": {
            "generated_by": "data/build_crosswalk.py",
            "attack_version": attack_data["metadata"]["attack_version"],
            "nist_framework_version": attack_data["metadata"]["mapping_framework_version"],
            "cis_controls_version": cis_data.get("cis_controls_version", "8.1"),
            "technique_count": len(rows),
            "technique_count_with_nist_mapping": len(complete_rows),
            "technique_count_with_derived_cis_mapping": len(with_cis),
            "unnormalizable_cis_entries": len(unnormalizable_cis),
            "note": (
                "cis_controls is a DERIVED (two-hop) mapping: ATT&CK-mitigated-by-"
                "NIST-control, NIST-control-implemented-by-CIS-safeguard. See "
                "data/sources/SOURCES.md before treating it as audit-grade."
            ),
        },
        "techniques": rows,
    }


if __name__ == "__main__":
    result = build()
    OUTPUT_FILE.write_text(json.dumps(result, indent=2))
    meta = result["_metadata"]
    print(f"Wrote {OUTPUT_FILE}")
    print(f"  ATT&CK v{meta['attack_version']} / NIST 800-53 {meta['nist_framework_version']} / CIS Controls {meta['cis_controls_version']}")
    print(f"  {meta['technique_count']} techniques total")
    print(f"  {meta['technique_count_with_nist_mapping']} with a direct NIST 800-53 mapping")
    print(f"  {meta['technique_count_with_derived_cis_mapping']} of those also got a derived CIS Controls mapping")
