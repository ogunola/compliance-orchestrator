"""
Parses PingCastle's Active Directory health-check XML report
(results/pingcastle/<domain>.xml) into Finding records.

PingCastle's report XML structure (RiskRules under categories like
StaleObjects, PrivilegedAccounts, Trusts, Anomalies) has been broadly
consistent across recent releases, but always spot check against the
installed version's schema (open the XML and look for <RiskRules> /
<HealthcheckRiskRule> elements) since PingCastle doesn't publish a formal
versioned schema. All findings from this tool are tagged to the Zero Trust
"identity" pillar - that mapping is intentional and lives here rather than
in control_mappings.yaml, since every PingCastle rule is inherently an
identity/AD finding.
"""

from __future__ import annotations

import logging
from pathlib import Path

from lxml import etree

from ..schema import Finding

logger = logging.getLogger(__name__)


def parse_pingcastle_dir(results_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    pingcastle_root = results_dir / "pingcastle"
    if not pingcastle_root.is_dir():
        logger.info("No pingcastle results directory at %s - skipping", pingcastle_root)
        return findings

    for report_xml in sorted(pingcastle_root.glob("*.xml")):
        try:
            tree = etree.parse(str(report_xml))
        except etree.XMLSyntaxError as exc:
            logger.warning("Could not parse %s: %s", report_xml, exc)
            continue

        domain = report_xml.stem
        risk_rules = tree.findall(".//RiskRule") or tree.findall(".//HealthcheckRiskRule")

        if not risk_rules:
            logger.warning(
                "%s parsed but no RiskRule/HealthcheckRiskRule elements found - "
                "check the report structure for this PingCastle version.",
                report_xml,
            )
            continue

        for rule in risk_rules:
            risk_id = _text(rule, "RiskId") or _text(rule, "Id") or "unknown"
            points = _text(rule, "Points")
            category = _text(rule, "Category")
            attack_ref = _text(rule, "MitreAttackTechnique") or _text(rule, "Model")

            # PingCastle reports risk *presence*, not a pass/fail check - treat
            # any risk rule that triggered (present in the report with points > 0)
            # as a "fail" so it rolls up consistently with the other tools.
            status = "fail" if (points and points != "0") else "pass"

            findings.append(
                Finding(
                    source_tool="pingcastle",
                    target=domain,
                    check_id=risk_id,
                    title=_text(rule, "Rationale") or _text(rule, "Description") or risk_id,
                    status=status,
                    severity=category,
                    attack_technique=attack_ref if attack_ref and attack_ref.startswith("T") else None,
                    raw={"points": points, "category": category},
                )
            )

    logger.info("Parsed %d PingCastle findings", len(findings))
    return findings


def _text(el, tag: str) -> str | None:
    child = el.find(tag)
    return child.text.strip() if child is not None and child.text else None
