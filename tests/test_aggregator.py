"""Smoke tests for the aggregation logic - no external tools or network calls.

Uses the REAL generated crosswalk (data/attack_crosswalk.generated.json,
built from the vendored MITRE/CTID datasets - see data/build_crosswalk.py)
merged with the curated overlay (data/control_mappings.yaml), exactly as
the CLI does.
"""

from pathlib import Path

import yaml

from orchestrator.aggregator import DEFAULT_CROSSWALK_PATH, aggregate, load_mappings
from orchestrator.schema import Finding

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OVERLAY_PATH = PROJECT_ROOT / "data" / "control_mappings.yaml"


def test_overlay_file_is_valid_yaml():
    data = yaml.safe_load(OVERLAY_PATH.read_text())
    assert "overlay" in data
    assert "zero_trust_pillars" in data
    assert len(data["overlay"]) > 0


def test_generated_crosswalk_exists_and_is_substantial():
    assert DEFAULT_CROSSWALK_PATH.exists(), (
        "data/attack_crosswalk.generated.json is missing - run "
        "`python3 data/build_crosswalk.py` first."
    )
    mappings = load_mappings(OVERLAY_PATH)
    # Real MITRE/CTID data as of ATT&CK v16.1: 470 mapped techniques.
    # Assert a floor rather than an exact count so this doesn't break the
    # moment someone regenerates against a newer ATT&CK/NIST version.
    mapped = [t for t in mappings["by_technique"].values() if t["nist_800_53"]]
    assert len(mapped) > 400


def test_load_mappings_indexes_by_technique_and_applies_overlay():
    mappings = load_mappings(OVERLAY_PATH)
    row = mappings["by_technique"]["T1078"]
    assert row["zt_pillar"] == "identity"          # from the curated overlay
    assert "AC-2" in row["nist_800_53"]             # from the generated crosswalk
    assert len(row["cis_controls"]) > 0             # derived CIS mapping present


def test_aggregate_rolls_up_known_technique():
    mappings = load_mappings(OVERLAY_PATH)
    findings = [
        Finding(
            source_tool="caldera",
            target="host1",
            check_id="ability-1",
            title="Valid Accounts test",
            status="fail",
            attack_technique="T1078",
        ),
        Finding(
            source_tool="prowler",
            target="acct-1",
            check_id="check-1",
            title="MFA enabled",
            status="pass",
        ),
    ]

    result = aggregate(findings, mappings)

    assert result["totals"] == {"fail": 1, "pass": 1}
    assert result["by_zt_pillar"]["identity"]["fail"] == 1
    assert "AC-2" in result["by_framework"]["nist_800_53"]
    assert result["by_framework"]["nist_800_53"]["AC-2"]["fail"] == 1
    assert result["unmapped_techniques"] == []


def test_aggregate_falls_back_to_base_technique_for_unmapped_subtechnique():
    """T1078.001 IS in the real crosswalk, but pick a synthetic sub-technique
    of a mapped base technique that the crosswalk does NOT carry at the
    sub-technique level, to exercise the fallback path deterministically."""
    mappings = load_mappings(OVERLAY_PATH)
    assert "T1078.999" not in mappings["by_technique"]  # confirm it's really absent
    assert "T1078" in mappings["by_technique"]

    findings = [
        Finding(
            source_tool="atomic",
            target="host1",
            check_id="T1078.999",
            title="Synthetic sub-technique test",
            status="fail",
            attack_technique="T1078.999",
        )
    ]
    result = aggregate(findings, mappings)
    assert "T1078.999" in result["fallback_techniques"]
    assert "AC-2" in result["by_framework"]["nist_800_53"]  # inherited from base T1078


def test_aggregate_flags_unmapped_technique():
    mappings = load_mappings(OVERLAY_PATH)
    findings = [
        Finding(
            source_tool="atomic",
            target="host1",
            check_id="T9999",
            title="Made-up technique",
            status="fail",
            attack_technique="T9999",
        )
    ]

    result = aggregate(findings, mappings)
    assert "T9999" in result["unmapped_techniques"]


def test_aggregate_flags_pillar_with_no_evidence():
    mappings = load_mappings(OVERLAY_PATH)
    result = aggregate([], mappings)
    assert "automation_orchestration" in result["pillar_gaps"]
    assert "governance" in result["pillar_gaps"]
