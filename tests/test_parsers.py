"""Parser smoke tests using small synthetic fixtures - written to disk in a
tmp_path, not real tool output, so these check the parsing logic itself
rather than any particular tool's exact current output format."""

import json
from pathlib import Path

from orchestrator.parsers import parse_atomic_dir, parse_openscap_dir, parse_prowler_dir


def test_parse_atomic_dir_classifies_pass_and_fail(tmp_path: Path):
    host_dir = tmp_path / "atomic" / "lab-win-01"
    host_dir.mkdir(parents=True)
    (host_dir / "T1078.log").write_text("Executing test: T1078 ... Completed successfully")
    (host_dir / "T1059.log").write_text("Error: access is denied")

    findings = parse_atomic_dir(tmp_path)
    statuses = {f.check_id: f.status for f in findings}

    assert statuses["T1078"] == "pass"
    assert statuses["T1059"] == "fail"


def test_parse_prowler_dir_reads_json(tmp_path: Path):
    provider_dir = tmp_path / "prowler" / "aws"
    provider_dir.mkdir(parents=True)
    records = [
        {"status_code": "PASS", "finding_info": {"uid": "check-1", "title": "MFA enabled"}, "resources": [{"uid": "acct-1"}]},
        {"status_code": "FAIL", "finding_info": {"uid": "check-2", "title": "Public S3 bucket"}, "resources": [{"uid": "acct-1"}]},
    ]
    (provider_dir / "out.ocsf.json").write_text(json.dumps(records))

    findings = parse_prowler_dir(tmp_path)
    statuses = {f.check_id: f.status for f in findings}

    assert statuses["check-1"] == "pass"
    assert statuses["check-2"] == "fail"


def test_parse_openscap_dir_reads_xccdf_results(tmp_path: Path):
    host_dir = tmp_path / "openscap" / "lab-linux-01"
    host_dir.mkdir(parents=True)
    xml = """<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <TestResult>
    <rule-result idref="xccdf_org.ssgproject.content_rule_no_empty_passwords" severity="high">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_selinux_enabled" severity="medium">
      <result>pass</result>
    </rule-result>
  </TestResult>
</Benchmark>"""
    (host_dir / "results.xml").write_text(xml)

    findings = parse_openscap_dir(tmp_path)
    statuses = {f.check_id: f.status for f in findings}

    assert statuses["xccdf_org.ssgproject.content_rule_no_empty_passwords"] == "fail"
    assert statuses["xccdf_org.ssgproject.content_rule_selinux_enabled"] == "pass"
