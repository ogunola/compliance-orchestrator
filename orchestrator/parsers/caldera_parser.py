"""
Parses the Caldera operation report(s) saved by
ansible/roles/caldera_operation into Finding records.

Expected input: results/caldera/operation-<id>.json, the JSON body returned
by Caldera's POST /api/v2/operations/{id}/report endpoint. That payload's
exact shape has shifted across Caldera versions; this parser reads the
fields that have been stable across the 4.x/5.x line (`steps` keyed by
paw/agent, each containing a list of executed abilities with an
`attack_technique` id and a `status` code) and falls back gracefully if a
field is missing.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..schema import Finding

logger = logging.getLogger(__name__)

# Caldera link status codes (as of the 4.x/5.x report format):
#   0 = success, 1 = failure, 2 = timeout/collect, -3/-4 = discarded/untrusted
_STATUS_MAP = {
    0: "pass",
    1: "fail",
    2: "error",
    -3: "not_applicable",
    -4: "not_applicable",
}


def parse_caldera_dir(results_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    caldera_dir = results_dir / "caldera"
    if not caldera_dir.is_dir():
        logger.info("No caldera results directory at %s - skipping", caldera_dir)
        return findings

    for report_file in sorted(caldera_dir.glob("operation-*.json")):
        try:
            payload = json.loads(report_file.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read %s: %s", report_file, exc)
            continue

        steps = payload.get("steps", {})
        if not steps:
            logger.warning(
                "%s has no 'steps' key - Caldera report format may have "
                "changed; check the payload manually.",
                report_file,
            )
            continue

        for paw, agent_steps in steps.items():
            target = _agent_label(payload, paw)
            for step in agent_steps.get("steps", []) if isinstance(agent_steps, dict) else []:
                technique = step.get("attack_technique") or step.get("technique_id")
                link_status = step.get("status", step.get("link_status"))
                status = _STATUS_MAP.get(link_status, "unknown")

                findings.append(
                    Finding(
                        source_tool="caldera",
                        target=target,
                        check_id=step.get("ability_id", technique or "unknown"),
                        title=step.get("name", f"Ability {step.get('ability_id', '')}"),
                        status=status,
                        attack_technique=technique,
                        raw=step,
                    )
                )

    logger.info("Parsed %d Caldera findings", len(findings))
    return findings


def _agent_label(payload: dict, paw: str) -> str:
    for host in payload.get("hosts", []):
        if host.get("paw") == paw:
            return host.get("host", paw)
    return paw
