"""
Parses the per-technique log files fetched by ansible/roles/atomic_redteam
into Finding records.

Expected input: results/atomic/<hostname>/<TECHNIQUE_ID>.log - raw stdout
captured from either Invoke-AtomicRedTeam (Windows) or atomic-operator
(Linux/macOS). Neither tool has a stable machine-readable exit summary in
its console output across all versions, so this parser does a best-effort
keyword scan and flags anything ambiguous as status=unknown rather than
guessing pass/fail - you should spot-check `raw.log_excerpt` for those.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..schema import Finding

logger = logging.getLogger(__name__)

_FAIL_PATTERNS = re.compile(r"(error|exception|failed|not found|access is denied)", re.IGNORECASE)
_PASS_PATTERNS = re.compile(r"(executing test|completed|success)", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)")


def parse_atomic_dir(results_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    atomic_dir = results_dir / "atomic"
    if not atomic_dir.is_dir():
        logger.info("No atomic results directory at %s - skipping", atomic_dir)
        return findings

    for host_dir in sorted(p for p in atomic_dir.iterdir() if p.is_dir()):
        for log_file in sorted(host_dir.glob("*.log")):
            technique_match = _TECHNIQUE_RE.match(log_file.stem)
            technique = technique_match.group(1) if technique_match else log_file.stem

            try:
                text = log_file.read_text(errors="replace")
            except OSError as exc:
                logger.warning("Could not read %s: %s", log_file, exc)
                continue

            status = _classify(text)

            findings.append(
                Finding(
                    source_tool="atomic",
                    target=host_dir.name,
                    check_id=log_file.stem,
                    title=f"Atomic Red Team {technique}",
                    status=status,
                    attack_technique=technique,
                    raw={"log_excerpt": text[-2000:]},  # tail is usually most informative
                )
            )

    logger.info("Parsed %d Atomic Red Team findings", len(findings))
    return findings


def _classify(log_text: str) -> str:
    has_fail = bool(_FAIL_PATTERNS.search(log_text))
    has_pass = bool(_PASS_PATTERNS.search(log_text))
    if has_fail and not has_pass:
        return "fail"
    if has_pass and not has_fail:
        return "pass"
    if not log_text.strip():
        return "error"
    return "unknown"
