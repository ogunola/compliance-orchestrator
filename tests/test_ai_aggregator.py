"""Smoke tests for the AI red-team (garak/OWASP) aggregation pipeline."""

from pathlib import Path

from orchestrator.ai_aggregator import DEFAULT_CATEGORIES_PATH, DEFAULT_PROBE_TAGS_PATH, aggregate_ai, load_owasp_mapping
from orchestrator.schema import Finding

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_probe_tags_file_exists_and_is_substantial():
    assert DEFAULT_PROBE_TAGS_PATH.exists(), (
        "data/ai_redteam/garak_probe_tags.generated.json is missing - run "
        "extract_garak_probe_tags.py first."
    )
    mapping = load_owasp_mapping()
    assert len(mapping["probe_tags"]) > 100  # real data: 194 at build time


def test_categories_cover_all_ten_owasp_llm_categories():
    mapping = load_owasp_mapping()
    assert len(mapping["categories"]) == 10
    assert "LLM01" in mapping["categories"]
    assert mapping["categories"]["LLM01"]["zt_pillar"] == "applications_workloads"


def test_aggregate_ai_rolls_up_known_probe():
    mapping = load_owasp_mapping()
    # dan.Dan_11_0 is a real probe in the vendored data, tagged owasp:llm01.
    findings = [
        Finding(
            source_tool="garak",
            target="my-model",
            check_id="dan.Dan_11_0::dan.DAN",
            title="garak dan.Dan_11_0 / dan.DAN",
            status="fail",
            secondary_tag="dan.Dan_11_0",
        ),
        Finding(source_tool="prowler", target="acct-1", check_id="x", title="x", status="pass"),
    ]

    result = aggregate_ai(findings, mapping)

    assert result["totals"] == {"fail": 1}  # the prowler finding is excluded - not source_tool "garak"
    assert result["by_owasp_category"]["LLM01"]["fail"] == 1
    assert "dan.Dan_11_0" in result["by_owasp_category"]["LLM01"]["probes"]
    assert result["by_zt_pillar"]["applications_workloads"]["fail"] == 1
    assert result["unmapped_probes"] == []


def test_aggregate_ai_flags_unmapped_probe():
    mapping = load_owasp_mapping()
    findings = [
        Finding(
            source_tool="garak",
            target="my-model",
            check_id="madeup.NotARealProbe::always.Pass",
            title="x",
            status="fail",
            secondary_tag="madeup.NotARealProbe",
        )
    ]
    result = aggregate_ai(findings, mapping)
    assert "madeup.NotARealProbe" in result["unmapped_probes"]


def test_llm03_supply_chain_is_always_uncovered_with_no_findings():
    """No garak probe carries an owasp:llm03 tag (see SOURCES.md) - this
    should show up as uncovered even with zero findings passed in, since
    that's a structural gap, not a run-specific one."""
    mapping = load_owasp_mapping()
    result = aggregate_ai([], mapping)
    assert "LLM03" in result["uncovered_categories"]
