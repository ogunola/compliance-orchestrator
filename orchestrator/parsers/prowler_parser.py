"""
Parses Prowler's output (results/prowler/<provider>/) into Finding records.

Prowler's own output formats have changed across major versions (v3 vs v4+).
This parser targets the JSON-OCSF format (`--output-formats json-ocsf`,
files ending in *.ocsf.json) since that's the schema Prowler is
standardizing on, and falls back to plain *.json if no ocsf file is found.
Compliance-framework tagging (which CIS/NIST requirement a check maps to)
lives in each finding's metadata under compliance-framework-specific keys
that have also moved around between versions - check a sample output file
for your installed version and adjust `_extract_compliance_refs` if needed.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..schema import Finding

logger = logging.getLogger(__name__)

_STATUS_MAP = {
    "PASS": "pass",
    "FAIL": "fail",
    "MANUAL": "not_applicable",
    "ERROR": "error",
}


def parse_prowler_dir(results_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    prowler_root = results_dir / "prowler"
    if not prowler_root.is_dir():
        logger.info("No prowler results directory at %s - skipping", prowler_root)
        return findings

    for provider_dir in sorted(p for p in prowler_root.iterdir() if p.is_dir()):
        output_files = sorted(provider_dir.glob("*.ocsf.json")) or sorted(provider_dir.glob("*.json"))
        if not output_files:
            logger.warning("No JSON output found under %s", provider_dir)
            continue

        for output_file in output_files:
            try:
                records = json.loads(output_file.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not read %s: %s", output_file, exc)
                continue

            if isinstance(records, dict):
                records = records.get("findings", [records])

            for record in records:
                findings.append(_finding_from_record(record, provider_dir.name))

    logger.info("Parsed %d Prowler findings", len(findings))
    return findings


def _finding_from_record(record: dict, provider: str) -> Finding:
    status_raw = record.get("status_code") or record.get("Status") or record.get("status") or ""
    status = _STATUS_MAP.get(str(status_raw).upper(), "unknown")

    check_id = (
        record.get("finding_info", {}).get("uid")
        or record.get("CheckID")
        or record.get("check_id")
        or "unknown"
    )
    title = (
        record.get("finding_info", {}).get("title")
        or record.get("CheckTitle")
        or record.get("check_title")
        or check_id
    )
    severity = record.get("severity") or record.get("Severity")
    resource = (
        record.get("resources", [{}])[0].get("uid")
        if record.get("resources")
        else record.get("ResourceId") or provider
    )

    return Finding(
        source_tool="prowler",
        target=str(resource),
        check_id=str(check_id),
        title=str(title),
        status=status,
        severity=str(severity) if severity else None,
        raw=record,
    )
