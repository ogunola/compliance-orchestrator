"""
Tests for the Vanta connector. No live credentials or network calls -
build_resources() is pure and tested directly; VantaClient's HTTP calls are
mocked (per the user's own call: build against the public API docs, test
with mocked responses, plug in real credentials later).
"""

from __future__ import annotations

import json
import logging
import time
from unittest.mock import MagicMock, patch

import pytest

from orchestrator.connectors.vanta import VantaClient, build_ai_resources, build_resources, merge_resources

SAMPLE_AGGREGATE = {
    "totals": {"pass": 3, "fail": 2},
    "by_tool": {"prowler": {"pass": 2, "fail": 1}, "caldera": {"pass": 1, "fail": 1}},
    "by_framework": {
        "nist_800_53": {"AC-2": {"pass": 1, "fail": 1}},
        "cis_controls": {"5.1": {"pass": 1, "fail": 0}},
        "iso_27001_annex_a": {},
    },
    "by_zt_pillar": {
        "identity": {"pass": 1, "fail": 1, "error": 0, "unknown": 0, "not_applicable": 0, "tools_reporting": ["caldera", "pingcastle"]},
    },
    "pillar_gaps": ["governance"],
    "unmapped_techniques": [],
}

SAMPLE_AI_AGGREGATE = {
    "totals": {"pass": 4, "fail": 1},
    "by_owasp_category": {
        "LLM01": {"pass": 3, "fail": 1, "error": 0, "unknown": 0, "not_applicable": 0, "probes": ["dan.Dan_11_0"]},
        "LLM03": {"pass": 0, "fail": 0, "error": 0, "unknown": 0, "not_applicable": 0, "probes": []},
    },
    "by_zt_pillar": {
        "identity": {"pass": 1, "fail": 0, "error": 0, "unknown": 0, "not_applicable": 0, "tools_reporting": ["garak"]},
    },
    "uncovered_categories": ["LLM03"],
    "unmapped_probes": [],
}


def test_build_resources_covers_every_framework_and_pillar():
    resources = build_resources(SAMPLE_AGGREGATE)
    unique_ids = {r["uniqueId"] for r in resources}

    assert "nist_800_53:AC-2" in unique_ids
    assert "cis_controls:5.1" in unique_ids
    assert "zt_pillar:identity" in unique_ids
    assert "run:summary" in unique_ids


def test_build_resources_computes_pass_rate_correctly():
    resources = build_resources(SAMPLE_AGGREGATE)
    ac2 = next(r for r in resources if r["uniqueId"] == "nist_800_53:AC-2")
    assert ac2["customProperties"]["pass_count"] == 1
    assert ac2["customProperties"]["fail_count"] == 1
    assert ac2["customProperties"]["total_count"] == 2
    assert ac2["customProperties"]["pass_rate"] == 0.5


def test_build_resources_handles_zero_total_without_dividing_by_zero():
    empty = {"totals": {}, "by_tool": {}, "by_framework": {"nist_800_53": {"AC-1": {}}}, "by_zt_pillar": {}}
    resources = build_resources(empty)
    ac1 = next(r for r in resources if r["uniqueId"] == "nist_800_53:AC-1")
    assert ac1["customProperties"]["pass_rate"] == 0.0


def test_client_rejects_missing_credentials():
    with pytest.raises(ValueError):
        VantaClient(client_id="", client_secret="secret", resource_id="res1")


@patch("orchestrator.connectors.vanta.requests.put")
@patch("orchestrator.connectors.vanta.requests.post")
def test_push_requests_a_token_then_puts_resources(mock_post, mock_put):
    mock_post.return_value = MagicMock(
        status_code=200,
        json=lambda: {"access_token": "tok_abc", "expires_in": 3600, "token_type": "Bearer"},
        raise_for_status=lambda: None,
    )
    mock_put.return_value = MagicMock(
        status_code=200,
        json=lambda: {"results": {"accepted": 2, "rejected": 0}},
        raise_for_status=lambda: None,
    )

    client = VantaClient(client_id="id1", client_secret="secret1", resource_id="res1")
    resources = build_resources(SAMPLE_AGGREGATE)
    result = client.push(resources)

    assert result["results"]["accepted"] == 2
    mock_post.assert_called_once()
    assert mock_post.call_args.kwargs["json"]["grant_type"] == "client_credentials"

    mock_put.assert_called_once()
    put_kwargs = mock_put.call_args.kwargs
    assert put_kwargs["headers"]["Authorization"] == "Bearer tok_abc"
    assert put_kwargs["json"]["resourceId"] == "res1"
    assert put_kwargs["json"]["resources"] == resources


@patch("orchestrator.connectors.vanta.requests.put")
@patch("orchestrator.connectors.vanta.requests.post")
def test_token_is_reused_across_pushes_until_near_expiry(mock_post, mock_put):
    mock_post.return_value = MagicMock(
        status_code=200,
        json=lambda: {"access_token": "tok_abc", "expires_in": 3600, "token_type": "Bearer"},
        raise_for_status=lambda: None,
    )
    mock_put.return_value = MagicMock(
        status_code=200,
        json=lambda: {"results": {"accepted": 1, "rejected": 0}},
        raise_for_status=lambda: None,
    )

    client = VantaClient(client_id="id1", client_secret="secret1", resource_id="res1")
    client.push(build_resources(SAMPLE_AGGREGATE))
    client.push(build_resources(SAMPLE_AGGREGATE))

    # Only one token request across two pushes - Vanta revokes the previous
    # token on every new request, so re-fetching per call would break a
    # process that pushes more than once.
    assert mock_post.call_count == 1
    assert mock_put.call_count == 2


@patch("orchestrator.connectors.vanta.requests.put")
@patch("orchestrator.connectors.vanta.requests.post")
def test_token_is_refreshed_once_expired(mock_post, mock_put):
    mock_post.return_value = MagicMock(
        status_code=200,
        json=lambda: {"access_token": "tok_abc", "expires_in": 1, "token_type": "Bearer"},  # expires almost immediately
        raise_for_status=lambda: None,
    )
    mock_put.return_value = MagicMock(
        status_code=200,
        json=lambda: {"results": {"accepted": 1, "rejected": 0}},
        raise_for_status=lambda: None,
    )

    client = VantaClient(client_id="id1", client_secret="secret1", resource_id="res1")
    client.push(build_resources(SAMPLE_AGGREGATE))
    time.sleep(1.1)
    client.push(build_resources(SAMPLE_AGGREGATE))

    assert mock_post.call_count == 2


def test_build_ai_resources_covers_owasp_categories_and_run_summary():
    resources = build_ai_resources(SAMPLE_AI_AGGREGATE)
    unique_ids = {r["uniqueId"] for r in resources}

    assert "owasp_llm_top10:LLM01" in unique_ids
    assert "owasp_llm_top10:LLM03" in unique_ids
    assert "ai_run:summary" in unique_ids
    # build_ai_resources deliberately does not build zt_pillar resources -
    # that's merge_resources()'s job, so main and AI pillar evidence don't
    # compete under the same uniqueId.
    assert not any(uid.startswith("zt_pillar:") for uid in unique_ids)


def test_build_ai_resources_computes_pass_rate_and_probe_list():
    resources = build_ai_resources(SAMPLE_AI_AGGREGATE)
    llm01 = next(r for r in resources if r["uniqueId"] == "owasp_llm_top10:LLM01")
    assert llm01["customProperties"]["framework"] == "OWASP LLM Top 10 (2025)"
    assert llm01["customProperties"]["pass_count"] == 3
    assert llm01["customProperties"]["fail_count"] == 1
    assert llm01["customProperties"]["total_count"] == 4
    assert llm01["customProperties"]["pass_rate"] == 0.75
    assert llm01["customProperties"]["source_tools"] == "dan.Dan_11_0"


def test_build_ai_resources_handles_zero_total_without_dividing_by_zero():
    empty = {"totals": {}, "by_owasp_category": {"LLM03": {}}}
    resources = build_ai_resources(empty)
    llm03 = next(r for r in resources if r["uniqueId"] == "owasp_llm_top10:LLM03")
    assert llm03["customProperties"]["pass_rate"] == 0.0


def test_merge_resources_keeps_all_distinct_uniqueIds():
    main_resources = build_resources(SAMPLE_AGGREGATE)
    ai_resources = build_ai_resources(SAMPLE_AI_AGGREGATE)

    merged = merge_resources(main_resources, ai_resources)
    unique_ids = {r["uniqueId"] for r in merged}

    # every distinct id from both builds survives the merge
    assert unique_ids == {r["uniqueId"] for r in main_resources} | {r["uniqueId"] for r in ai_resources}
    assert len(merged) == len(main_resources) + len(ai_resources)


def test_merge_resources_sums_overlapping_zt_pillar_counts_instead_of_overwriting():
    # Both pipelines report "identity" pillar evidence independently -
    # main via caldera/pingcastle, AI via garak. merge_resources() must sum
    # them rather than letting one clobber the other.
    main_pillar = {
        "displayName": "Zero Trust - identity",
        "uniqueId": "zt_pillar:identity",
        "customProperties": {
            "framework": "Zero Trust Maturity (CISA ZTMM)",
            "control_id": "identity",
            "pass_count": 1,
            "fail_count": 1,
            "error_count": 0,
            "total_count": 2,
            "pass_rate": 0.5,
            "last_aggregated_at": "2026-01-01T00:00:00+00:00",
            "source_tools": "caldera,pingcastle",
        },
    }
    ai_pillar = {
        "displayName": "Zero Trust - identity",
        "uniqueId": "zt_pillar:identity",
        "customProperties": {
            "framework": "Zero Trust Maturity (CISA ZTMM)",
            "control_id": "identity",
            "pass_count": 3,
            "fail_count": 0,
            "error_count": 0,
            "total_count": 3,
            "pass_rate": 1.0,
            "last_aggregated_at": "2026-02-01T00:00:00+00:00",
            "source_tools": "garak",
        },
    }

    merged = merge_resources([main_pillar], [ai_pillar])

    assert len(merged) == 1
    props = merged[0]["customProperties"]
    assert props["pass_count"] == 4  # 1 + 3
    assert props["fail_count"] == 1
    assert props["total_count"] == 5
    assert props["pass_rate"] == 0.8  # 4/5
    assert props["source_tools"] == "caldera,garak,pingcastle"  # unioned, sorted
    assert props["last_aggregated_at"] == "2026-02-01T00:00:00+00:00"  # max() of the two


def test_merge_resources_does_not_mutate_its_inputs():
    main_resources = build_resources(SAMPLE_AGGREGATE)
    ai_resources = build_ai_resources(SAMPLE_AI_AGGREGATE)
    main_before = json.loads(json.dumps(main_resources))

    merge_resources(main_resources, ai_resources)

    assert main_resources == main_before


def test_merge_resources_logs_and_keeps_first_on_unexpected_non_pillar_collision(caplog):
    dup_a = {"uniqueId": "run:summary", "customProperties": {"pass_count": 1}}
    dup_b = {"uniqueId": "run:summary", "customProperties": {"pass_count": 99}}

    with caplog.at_level(logging.WARNING, logger="orchestrator.connectors.vanta"):
        merged = merge_resources([dup_a], [dup_b])

    assert len(merged) == 1
    assert merged[0]["customProperties"]["pass_count"] == 1  # first one wins
    assert "duplicate resource uniqueid" in caplog.text.lower()
