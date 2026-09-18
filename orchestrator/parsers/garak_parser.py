"""
Parses garak's native `.report.jsonl` files (results/garak/<target>/) into
Finding records.

Schema verified directly against garak's own test fixture
(tests/_assets/report/report_test.report.jsonl in the garak repo) rather
than assumed - an "eval" row looks like:

    {
      "entry_type": "eval",
      "probe": "test.Test",         # "<probe_module>.<ProbeClassName>"
      "detector": "always.Pass",    # "<detector_module>.<DetectorClassName>"
      "passed": 8,
      "nones": 0,
      "total_evaluated": 8,
      "fails": 0,
      "total_processed": 8
    }

One eval row = one (probe, detector) pair, evaluated across however many
prompts that probe sent - not one row per prompt. This parser collapses
each row to a single Finding (pass if fails==0 and total_evaluated>0, fail
if fails>0, not_applicable if nothing was evaluated), keeping the raw
counts in Finding.raw for anyone who wants the underlying rate rather than
a binary rollup.

The probe's OWASP LLM Top 10 category is NOT resolved here - it's looked
up later by orchestrator/ai_aggregator.py from
data/ai_redteam/garak_probe_tags.generated.json, the same
parse-now/map-later split used for ATT&CK techniques in aggregator.py.
This parser only sets Finding.secondary_tag to the raw probe id
(e.g. "dan.Dan_11_0") so that lookup has something to join on.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..schema import Finding

logger = logging.getLogger(__name__)


def parse_garak_dir(results_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    garak_root = results_dir / "garak"
    if not garak_root.is_dir():
        logger.info("No garak results directory at %s - skipping", garak_root)
        return findings

    for report_file in sorted(garak_root.rglob("*.report.jsonl")):
        target = _infer_target(report_file, garak_root)
        findings.extend(_parse_report_file(report_file, target))

    logger.info("Parsed %d garak findings", len(findings))
    return findings


def _infer_target(report_file: Path, garak_root: Path) -> str:
    """results/garak/<target>/garak.<run_id>.report.jsonl -> <target>."""
    try:
        relative = report_file.relative_to(garak_root)
        if len(relative.parts) > 1:
            return relative.parts[0]
    except ValueError:
        pass
    return report_file.stem


def _parse_report_file(report_file: Path, target: str) -> list[Finding]:
    findings: list[Finding] = []
    target_name = target

    try:
        lines = report_file.read_text().splitlines()
    except OSError as exc:
        logger.warning("Could not read %s: %s", report_file, exc)
        return findings

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if record.get("entry_type") == "start_run setup":
            target_name = record.get("plugins.target_name", target) or target
            continue

        if record.get("entry_type") != "eval":
            continue

        probe = record.get("probe", "unknown")
        detector = record.get("detector", "unknown")
        total_evaluated = record.get("total_evaluated", 0)
        fails = record.get("fails", 0)

        if total_evaluated == 0:
            status = "not_applicable"
        elif fails > 0:
            status = "fail"
        else:
            status = "pass"

        findings.append(
            Finding(
                source_tool="garak",
                target=target_name,
                check_id=f"{probe}::{detector}",
                title=f"garak {probe} / {detector}",
                status=status,
                secondary_tag=probe,
                raw={
                    "detector": detector,
                    "passed": record.get("passed", 0),
                    "fails": fails,
                    "total_evaluated": total_evaluated,
                    "nones": record.get("nones", 0),
                },
            )
        )

    return findings
