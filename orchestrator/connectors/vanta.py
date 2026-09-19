"""
Vanta GRC hand-off connector.

Vanta's public API (developer.vanta.com) has no endpoint for pushing
arbitrary "test results" directly - custom compliance logic in Vanta is
built on top of *Custom Resources*: you predefine a resource type/schema
once in the Vanta UI (Settings -> Developer Console -> your private
integration -> Resources tab), then push instances of that resource via the
API, and author a Custom Test in Vanta's UI whose pass/fail logic reads
your resources' properties. This module does the second part - it turns
this project's aggregate() output into Custom Resource instances and PUTs
them.

One-time manual setup required in the Vanta UI before this will work (see
README.md "GRC hand-off (Vanta)" section):
  1. Create a Private Integration in Settings -> Developer Console.
  2. Generate a client secret; note the client_id + client_secret.
  3. Under that integration's Resources tab, create a Custom Resource named
     e.g. "compliance_control_coverage" using the JSON Type Definition
     schema documented in README.md. Note the generated Resource ID.
  4. Author a Custom Test against that resource type (e.g. "fail_count ==
     0") and map it to the relevant control in Vanta's framework library.

Authentication: OAuth2 client_credentials grant against
POST https://api.vanta.com/oauth/token, scope
"connectors.self:write-resource", bearer token good for 3600s. Vanta only
allows ONE active token per integration - requesting a new one revokes the
previous one - so this client fetches a token lazily and reuses it for the
process lifetime rather than re-requesting per call.

Push semantics: PUT https://api.vanta.com/v1/resources/custom_resource
replaces the FULL state of that resource type on every call - any
previously-pushed uniqueId not included in the current payload is treated
as no longer existing. build_resources() is therefore expected to always
receive the complete current aggregate(), not a delta, and this client
always sends everything in one call rather than batching (undocumented
whether the API enforces a size cap; at the scale this project produces -
low hundreds of controls - a single call is expected to be well within any
reasonable limit).
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)

TOKEN_URL = "https://api.vanta.com/oauth/token"
API_BASE = "https://api.vanta.com/v1"
PUSH_RESOURCE_PATH = "/resources/custom_resource"
TOKEN_SCOPE = "connectors.self:write-resource connectors.self:read-resource"
TOKEN_REFRESH_MARGIN_SEC = 60  # refresh a bit before the token actually expires

_FRAMEWORK_LABELS = {
    "nist_800_53": "NIST 800-53 Rev5",
    "cis_controls": "CIS Controls v8.1",
    "iso_27001_annex_a": "ISO 27001:2022 Annex A",
}


def build_resources(aggregate: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Pure function: aggregate() output -> Vanta custom resource instances.
    No network calls - kept separate from VantaClient so it's trivially
    unit-testable, and so you can inspect exactly what would be pushed
    (e.g. `python main.py push-vanta --dry-run`) without credentials.
    """
    now = datetime.now(timezone.utc).isoformat()
    resources: list[dict[str, Any]] = []

    for framework_key, controls in aggregate.get("by_framework", {}).items():
        label = _FRAMEWORK_LABELS.get(framework_key, framework_key)
        for control_id, counts in controls.items():
            pass_n = counts.get("pass", 0)
            fail_n = counts.get("fail", 0)
            error_n = counts.get("error", 0)
            unknown_n = counts.get("unknown", 0)
            total = pass_n + fail_n + error_n + unknown_n
            resources.append(
                {
                    "displayName": f"{label} {control_id}",
                    "uniqueId": f"{framework_key}:{control_id}",
                    "customProperties": {
                        "framework": label,
                        "control_id": control_id,
                        "pass_count": pass_n,
                        "fail_count": fail_n,
                        "error_count": error_n,
                        "total_count": total,
                        "pass_rate": round(pass_n / total, 4) if total else 0.0,
                        "last_aggregated_at": now,
                    },
                }
            )

    for pillar, counts in aggregate.get("by_zt_pillar", {}).items():
        pass_n = counts.get("pass", 0)
        fail_n = counts.get("fail", 0)
        error_n = counts.get("error", 0)
        unknown_n = counts.get("unknown", 0)
        total = pass_n + fail_n + error_n + unknown_n
        resources.append(
            {
                "displayName": f"Zero Trust - {pillar}",
                "uniqueId": f"zt_pillar:{pillar}",
                "customProperties": {
                    "framework": "Zero Trust Maturity (CISA ZTMM)",
                    "control_id": pillar,
                    "pass_count": pass_n,
                    "fail_count": fail_n,
                    "error_count": error_n,
                    "total_count": total,
                    "pass_rate": round(pass_n / total, 4) if total else 0.0,
                    "last_aggregated_at": now,
                    "source_tools": ",".join(counts.get("tools_reporting", [])),
                },
            }
        )

    totals = aggregate.get("totals", {})
    resources.append(
        {
            "displayName": "Compliance orchestrator - latest run summary",
            "uniqueId": "run:summary",
            "customProperties": {
                "framework": "orchestrator",
                "control_id": "run_summary",
                "pass_count": totals.get("pass", 0),
                "fail_count": totals.get("fail", 0),
                "error_count": totals.get("error", 0),
                "total_count": sum(totals.values()),
                "pass_rate": round(totals.get("pass", 0) / sum(totals.values()), 4) if sum(totals.values()) else 0.0,
                "last_aggregated_at": now,
                "source_tools": ",".join(sorted(aggregate.get("by_tool", {}).keys())),
            },
        }
    )

    return resources


_OWASP_FRAMEWORK_LABEL = "OWASP LLM Top 10 (2025)"


def build_ai_resources(ai_aggregate: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Same idea as build_resources(), for orchestrator/ai_aggregator.py's
    output (the garak/OWASP pipeline). Uses the SAME Custom Resource schema
    as build_resources() - framework/control_id/pass_count/etc. are generic
    enough to cover both, so no second schema needs to be defined in Vanta's
    UI. A Custom Test filters on `framework == "OWASP LLM Top 10 (2025)"` to
    build LLM-specific tests distinct from the infra/config ones.

    zt_pillar resources are intentionally NOT built here - see
    merge_resources(), which combines this pipeline's pillar evidence with
    build_resources()'s before either gets pushed, so Zero Trust pillar
    coverage in Vanta reflects both infra and AI findings together rather
    than two competing resources with the same uniqueId.
    """
    now = datetime.now(timezone.utc).isoformat()
    resources: list[dict[str, Any]] = []

    for cat_id, counts in ai_aggregate.get("by_owasp_category", {}).items():
        pass_n = counts.get("pass", 0)
        fail_n = counts.get("fail", 0)
        error_n = counts.get("error", 0)
        unknown_n = counts.get("unknown", 0)
        not_applicable_n = counts.get("not_applicable", 0)
        total = pass_n + fail_n + error_n + unknown_n + not_applicable_n
        resources.append(
            {
                "displayName": f"{_OWASP_FRAMEWORK_LABEL} {cat_id}",
                "uniqueId": f"owasp_llm_top10:{cat_id}",
                "customProperties": {
                    "framework": _OWASP_FRAMEWORK_LABEL,
                    "control_id": cat_id,
                    "pass_count": pass_n,
                    "fail_count": fail_n,
                    "error_count": error_n,
                    "total_count": total,
                    "pass_rate": round(pass_n / total, 4) if total else 0.0,
                    "last_aggregated_at": now,
                    "source_tools": ",".join(counts.get("probes", [])),
                },
            }
        )

    totals = ai_aggregate.get("totals", {})
    total_all = sum(totals.values())
    resources.append(
        {
            "displayName": "AI red-team (garak) - latest run summary",
            "uniqueId": "ai_run:summary",
            "customProperties": {
                "framework": "orchestrator",
                "control_id": "ai_run_summary",
                "pass_count": totals.get("pass", 0),
                "fail_count": totals.get("fail", 0),
                "error_count": totals.get("error", 0),
                "total_count": total_all,
                "pass_rate": round(totals.get("pass", 0) / total_all, 4) if total_all else 0.0,
                "last_aggregated_at": now,
                "source_tools": "garak",
            },
        }
    )

    return resources


def merge_resources(main_resources: list[dict[str, Any]], ai_resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Combines build_resources() and build_ai_resources() output into one
    list safe to push in a single PUT (remember: PUT replaces the *entire*
    resource set, so pushing them separately under the same resourceId
    would make each call erase the other's data - see VantaClient.push()).

    Every uniqueId is distinct EXCEPT zt_pillar:<pillar>, which both
    pipelines can produce independently (infra tools and garak can both
    surface, say, Identity-pillar evidence). Those get merged by summing
    counts and unioning source_tools, rather than one silently overwriting
    the other - Zero Trust pillar coverage in Vanta should reflect all
    evidence, not just whichever pipeline's resource happened to be built
    last in the list.
    """
    by_id: dict[str, dict[str, Any]] = {}

    for resource in main_resources + ai_resources:
        uid = resource["uniqueId"]
        if uid not in by_id:
            by_id[uid] = json.loads(json.dumps(resource))  # deep copy
            continue

        existing = by_id[uid]
        if not uid.startswith("zt_pillar:"):
            # Non-pillar collision shouldn't happen given the namespacing
            # above; if it does, keep the first and log rather than silently
            # dropping data.
            logger.warning("Unexpected duplicate resource uniqueId %r during merge - keeping the first", uid)
            continue

        existing_props = existing["customProperties"]
        new_props = resource["customProperties"]
        existing_props["pass_count"] += new_props.get("pass_count", 0)
        existing_props["fail_count"] += new_props.get("fail_count", 0)
        existing_props["error_count"] += new_props.get("error_count", 0)
        existing_props["total_count"] += new_props.get("total_count", 0)
        existing_props["pass_rate"] = (
            round(existing_props["pass_count"] / existing_props["total_count"], 4)
            if existing_props["total_count"]
            else 0.0
        )
        existing_tools = set(t for t in existing_props.get("source_tools", "").split(",") if t)
        new_tools = set(t for t in new_props.get("source_tools", "").split(",") if t)
        existing_props["source_tools"] = ",".join(sorted(existing_tools | new_tools))
        existing_props["last_aggregated_at"] = max(existing_props["last_aggregated_at"], new_props["last_aggregated_at"])

    return list(by_id.values())


@dataclass
class _CachedToken:
    access_token: str
    expires_at: float  # time.monotonic() timestamp


class VantaClient:
    """Thin OAuth + PUT client. See module docstring for the API contract."""

    def __init__(self, client_id: str, client_secret: str, resource_id: str, timeout: int = 30):
        if not client_id or not client_secret or not resource_id:
            raise ValueError("client_id, client_secret, and resource_id are all required")
        self._client_id = client_id
        self._client_secret = client_secret
        self._resource_id = resource_id
        self._timeout = timeout
        self._token: _CachedToken | None = None

    def _get_access_token(self) -> str:
        if self._token and time.monotonic() < self._token.expires_at - TOKEN_REFRESH_MARGIN_SEC:
            return self._token.access_token

        logger.info("Requesting new Vanta access token (previous token, if any, is now revoked)")
        response = requests.post(
            TOKEN_URL,
            json={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": TOKEN_SCOPE,
                "grant_type": "client_credentials",
            },
            timeout=self._timeout,
        )
        response.raise_for_status()
        payload = response.json()
        self._token = _CachedToken(
            access_token=payload["access_token"],
            expires_at=time.monotonic() + payload.get("expires_in", 3600),
        )
        return self._token.access_token

    def push(self, resources: list[dict[str, Any]]) -> dict[str, Any]:
        """
        PUTs the full resource set. Remember: this REPLACES everything
        currently stored under self._resource_id in Vanta - always pass the
        complete list from build_resources(aggregate), not a partial update.
        """
        token = self._get_access_token()
        response = requests.put(
            f"{API_BASE}{PUSH_RESOURCE_PATH}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"resourceId": self._resource_id, "resources": resources},
            timeout=self._timeout,
        )
        response.raise_for_status()
        result = response.json()
        accepted = result.get("results", {}).get("accepted", "?")
        rejected = result.get("results", {}).get("rejected", "?")
        logger.info("Vanta push: %s accepted, %s rejected (%d resources sent)", accepted, rejected, len(resources))
        if rejected and rejected != "?" and rejected != 0:
            logger.warning("Vanta rejected %s resources - check field types against the Custom Resource schema", rejected)
        return result
