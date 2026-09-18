"""
Tests for the Vanta connector. No live credentials or network calls -
build_resources() is pure and tested directly; VantaClient's HTTP calls are
mocked (per the user's own call: build against the public API docs, test
with mocked responses, plug in real credentials later).
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from orchestrator.connectors.vanta import VantaClient, build_resources

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
