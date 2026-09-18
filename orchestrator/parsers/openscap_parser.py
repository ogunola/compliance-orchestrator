"""
Parses OpenSCAP XCCDF results.xml files (results/openscap/<host>/results.xml)
into Finding records.

Uses the standard XCCDF namespace for <rule-result> elements. CIS-control
cross-referencing for each oscap rule id is NOT done here directly - rule
ids from the SCAP Security Guide (e.g.
xccdf_org.ssgproject.content_rule_...) don't carry a stable CIS control
number in the XML consistently across benchmark versions, so this parser
surfaces the raw rule id/title/result, and data/control_mappings.yaml (or an
extension of it) is where you associate specific rule ids to CIS controls
for the SSG content version you're actually running.
"""

from __future__ import annotations

import logging
from pathlib import Path

from lxml import etree

from ..schema import Finding

logger = logging.getLogger(__name__)

_NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

_STATUS_MAP = {
    "pass": "pass",
    "fail": "fail",
    "error": "error",
    "notapplicable": "not_applicable",
    "notchecked": "unknown",
    "notselected": "not_applicable",
    "informational": "unknown",
    "fixed": "pass",
}


def parse_openscap_dir(results_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    openscap_root = results_dir / "openscap"
    if not openscap_root.is_dir():
        logger.info("No openscap results directory at %s - skipping", openscap_root)
        return findings

    for host_dir in sorted(p for p in openscap_root.iterdir() if p.is_dir()):
        results_xml = host_dir / "results.xml"
        if not results_xml.exists():
            logger.warning("No results.xml under %s", host_dir)
            continue

        try:
            tree = etree.parse(str(results_xml))
        except etree.XMLSyntaxError as exc:
            logger.warning("Could not parse %s: %s", results_xml, exc)
            continue

        for rule_result in tree.findall(".//xccdf:rule-result", namespaces=_NS):
            rule_id = rule_result.get("idref", "unknown")
            severity = rule_result.get("severity")
            result_el = rule_result.find("xccdf:result", namespaces=_NS)
            result_text = (result_el.text or "").strip().lower() if result_el is not None else ""
            status = _STATUS_MAP.get(result_text, "unknown")

            findings.append(
                Finding(
                    source_tool="openscap",
                    target=host_dir.name,
                    check_id=rule_id,
                    title=rule_id.rsplit("_rule_", 1)[-1].replace("_", " "),
                    status=status,
                    severity=severity,
                    raw={"raw_result": result_text},
                )
            )

    logger.info("Parsed %d OpenSCAP findings", len(findings))
    return findings
